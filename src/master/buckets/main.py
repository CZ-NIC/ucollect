from twisted.internet.task import LoopingCall
from twisted.internet import reactor
import time
import struct
import socket
import logging

import plugin
import buckets.group
import buckets.criterion
import buckets.client

logger = logging.getLogger(name='buckets')

class BucketsPlugin(plugin.Plugin):
	"""
	Counterpart of the "buckets" plugin in the client. It does
	analysis by hashing data into buckets by several statistics.
	"""
	def __init__(self, plugins):
		plugin.Plugin.__init__(self, plugins)
		self.__bucket_count = 13
		self.__hash_count = 5
		self.__criteria = [buckets.criterion.AddressAndPort(), buckets.criterion.Port(), buckets.criterion.Address()]
		self.__history_size = 2
		self.__config_version = 1
		self.__max_key_count = 1000
		self.__granularity = 2000 # A timeslot of 2 seconds, for testing
		self.__max_timeslots = 30 # Twice as much as needed, just to make sure
		# Just an arbitrary number
		self.__seed = 872945724987
		self.__downloader = LoopingCall(self.__init_download)
		# FIXME: Adjust the time to something reasonable after the testing.
		self.__downloader.start(15, False)
		# We are just gathering data between these two time stamps
		self.__lower_time = 0
		self.__upper_time = 0
		self.__gather_history_max = 3
		self.__process_delay = 1
		self.__treshold = 1.8
		self.__groups = {}
		for crit in self.__criteria:
			self.__groups[crit.code()] = buckets.group.Group(hash_count=self.__hash_count, bucket_count=self.__bucket_count, window_backlog=self.__gather_history_max, treshold=self.__treshold)
		self.__clients = {}

	def client_connected(self, client):
		name = client.cid()
		self.__clients[name] = buckets.client.Client(name, ['/', '/singleton/'+name], lambda message: self.send(message, name))
		# TODO: Groups

	def client_disconnected(self, client):
		# TODO: Groups
		del self.__clients[client.cid()]

	def __gather_start(self, now):
		"""
		Start gathering of data
		"""
		# Move to the next window to gather
		self.__lower_time = self.__upper_time
		self.__upper_time = now
		# Provide empty data
		reactor.callLater(self.__process_delay, self.__process)

	def __process(self):
		"""
		Process the gathered data.
		"""
		if not self.__lower_time:
			# We are not yet fully initialized and filled up (for example, the lower_time is wrong, so
			# we couldn't request the keys)
			logger.info('Starting up, waiting for at least one more generation')
		generation = self.__lower_time
		cindex = 0
		for crit in self.__criteria:
			logger.info('Processing criterion %s', crit.code())
			anomalies = self.__groups[crit.code()].anomalies()
			# We computed the anomalies of all clients. Get the keys for the anomalies from each of them.
			logger.debug('Anomalous indices: %s', anomalies)
			examine = []
			do_send = generation
			for an in anomalies:
				if not an:
					# If there's no anomaly in at least one bucket, we would get nothing back anyway
					do_send = False
					break
				examine.append(len(an))
				examine.extend(an)
			# The lower_time is the timestamp/ID of this batch. Or, with the clients that are connected
			# for the time of the batch at least.
			# We could try asking for the older ones too (we have them in local history).
			if do_send:
				logger.debug('Asking for keys %s on criterion %s at %s', examine, crit.code(), generation)
				def ask_client(criterion, client):
					# Separate function, so the variables are copied to the parameters.
					# Otherwise, the value in both criterions were for the second one,
					# as the function remembered the variable here, which got changed.
					def callback(message, success):
						if success:
							print("Keys for %s on %s:" % (criterion.code(), client.name()))
							for k in criterion.decode_multiple(message):
								print(k)
						else:
							logger.warn("Client %s doesn't have keys for generation %s on criterion %s", client.name(), generation)
					client.get_keys(cindex, generation, examine, callback)
				# Send it to all the clients.
				for client in self.__clients.values():
					ask_client(crit, client)
			else:
				logger.debug('No anomaly asked on criterion %s at %s', crit.code, generation)
			cindex += 1

	def name(self):
		return "Buckets"

	def message_from_client(self, message, client):
		kind = message[0]
		if kind == 'C':
			logger.debug('Config %s for client %s at %s', self.__config_version, client, int(time.time()))
			# It asks for config. Send some.
			self.send('C' + self.__config(), client)
		elif kind == 'G':
			# Generation data.
			# Parse it. Something less error-prone when confused config?
			count = (len(message) - 17) / 4
			deserialized = struct.unpack('!QLL' + str(count) + 'L', message[1:])
			(timestamp, version, timeslots) = deserialized[:3]
			logger.debug('Recevied generation from %s (timestamp = %s)', client, timestamp)
			if timeslots == 0:
				logger.warn('Timeslot overflow on client %s and timestamp %s', client, timestamp)
				return
			deserialized = deserialized[3:]
			for crit in self.__criteria:
				if deserialized[0]:
					logger.warn('Overflow on client %s and criterion %c at %s', client, crit.code(), timestamp)
				deserialized = deserialized[1:] # The overflow flag
				local = deserialized[:self.__bucket_count * self.__hash_count * timeslots]
				deserialized = deserialized[self.__bucket_count * self.__hash_count * timeslots:]
				total = sum(local)
				tslot = 0
				lnum = 0
				to_merge = []
				tslot_data = []
				while local:
					line = local[:self.__bucket_count]
					tslot_data.append(line)
					local = local[self.__bucket_count:]
					lnum += 1
					if lnum % self.__hash_count == 0:
						tslot += 1
						to_merge.append(tslot_data)
						tslot_data = []
				self.__merge(timestamp, self.__groups[crit.code()], to_merge)
		elif kind == 'K':
			# Got keys from the plugin
			(req_id,) = struct.unpack('!L', message[1:5])
			logger.info('Received keys from %s', client)
			buckets.client.manager.response(req_id, message[5:])
		elif kind == 'M':
			(req_id,) = struct.unpack('!L', message[1:5])
			buckets.client.manager.missing(req_id, message[5:])
		else:
			logger.error('Unknown data from plugin %s: %s', client, repr(message))

	def __config(self):
		header = struct.pack('!2Q8L' + str(len(self.__criteria)) + 'c', self.__seed, int(time.time()), self.__bucket_count, self.__hash_count, len(self.__criteria), self.__history_size , self.__config_version, self.__max_key_count, self.__max_timeslots, self.__granularity, *map(lambda c: c.code(), self.__criteria))
		return header

	def __init_download(self):
		"""
		Ask the clients to provide some data.
		"""
		now = int(time.time())
		logger.info('Asking for generation, starting new one at %s', now)
		self.__gather_start(now)
		data = struct.pack('!Q', now)
		self.broadcast('G' + data)
		buckets.client.manager.trim()

	def __merge(self, timestamp, cgroups, data):
		"""
		Merge data to the current set in the given criterion groups.
		"""
		if timestamp < self.__lower_time:
			logger.warn('Too old data (from %s, expected at least %s)', timestamp, self.__lower_time)
			return
		if self.__upper_time <= timestamp:
			logger.warn('Too new data (from %s, expected at most %s)', timestamp, self.__upper_time)
			return
		cgroups.merge(data)
