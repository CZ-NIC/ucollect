from twisted.internet.task import LoopingCall
from twisted.internet import reactor
import time
import struct
import socket
import logging

import plugin
import stats

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
		self.__criteria = ['B', 'P']
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
		self.__gather_history = []
		self.__gather_history_max = 3
		self.__process_delay = 1
		self.__treshold = 1.8

	def __gather_start(self, now):
		"""
		Start gathering of data
		"""
		# Move to the next window to gather
		self.__lower_time = self.__upper_time
		self.__upper_time = now
		# Provide empty data
		self.__gather_counts = {}
		for crit in self.__criteria:
			self.__gather_counts[crit] = map(lambda hnum: map(lambda bnum: [], range(0, self.__bucket_count)), range(0, self.__hash_count))
		reactor.callLater(self.__process_delay, self.__process)

	def __process(self):
		"""
		Process the gathered data.
		"""
		self.__gather_history.append(self.__gather_counts)
		cindex = 0
		if not self.__lower_time:
			# We are not yet fully initialized and filled up (for example, the lower_time is wrong, so
			# we couldn't request the keys)
			logger.info('Starting up, waiting for at least one more generation')
		for crit in self.__criteria:
			logger.info('Processing criterion %s', crit)
			# Extract the relevant batches
			history = map(lambda batch: batch[crit], self.__gather_history)
			# Concatenate the batches together.
			batch = map(lambda hnum:
				map(lambda bnum:
					reduce(lambda a, b: a + b, map(lambda hist: hist[hnum][bnum], history)),
				range(0, self.__bucket_count)),
			range(0, self.__hash_count))
			anomalies = map(lambda bucket: stats.anomalies(bucket, self.__treshold), batch)
			# We computed the anomalies of all clients. Get the keys for the anomalies from each of them.
			logger.debug('Anomalous indices: %s', anomalies)
			examine = [cindex, cindex] # TODO: We'll need some tracking of IDs once we aggregate the answers of keys together.
			do_send = True
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
				logger.debug('Asking for keys %s on criterion %s at %s', examine[2:], crit, self.__lower_time)
				message = struct.pack('!Q' + str(len(examine)) + 'L', self.__lower_time, *examine)
				# Send it to all the clients.
				self.broadcast('K' + message)
			else:
				logger.debug('No anomaly found on criterion %s at %s', crit, self.__lower_time)
			cindex += 1
		# Clean old history.
		if len(self.__gather_history) > self.__gather_history_max:
			self.__gather_history = self.__gather_history[1:]

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
			criterion = 0
			for crit in self.__criteria:
				if deserialized[0]:
					logger.warn('Overflow on client %s and criterion %c at %s', client, crit, timestamp)
				deserialized = deserialized[1:] # The overflow flag
				local = deserialized[:self.__bucket_count * self.__hash_count * timeslots]
				deserialized = deserialized[self.__bucket_count * self.__hash_count * timeslots:]
				total = sum(local)
				criterion += 1
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
				self.__merge(timestamp, crit, to_merge)
		elif kind == 'K':
			# Got keys from the plugin
			(req_id,) = struct.unpack('!L', message[1:5])
			message = message[5:]
			logger.info('Received keys from %s', client)
			print("Keys for ID " + str(req_id) + " on " + client)
			while message:
				addr = ''
				(port,) = struct.unpack('!H', message[:2])
				message = message[2:]
				if req_id == 0:
					addr = "<unknown>:"
					if message[0] == '\x04': # IPv4
						addr = socket.inet_ntop(socket.AF_INET, message[1:5]) + ":"
					elif message[0] == '\x06': # IPv6
						addr = socket.inet_ntop(socket.AF_INET6, message[1:17]) + ":"
					message = message[17:]
				print(addr + str(port))
		else:
			logger.error('Unknown data from plugin %s: %s', client, repr(message))

	def __config(self):
		header = struct.pack('!2Q8L' + str(len(self.__criteria)) + 'c', self.__seed, int(time.time()), self.__bucket_count, self.__hash_count, len(self.__criteria), self.__history_size , self.__config_version, self.__max_key_count, self.__max_timeslots, self.__granularity, *self.__criteria)
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

	def __merge(self, timestamp, criterion, data):
		"""
		Merge data to the current set.
		"""
		if timestamp < self.__lower_time:
			logger.warn('Too old data (from %s, expected at least %s)', timestamp, self.__lower_time)
			return
		if self.__upper_time <= timestamp:
			logger.warn('Too new data (from %s, expected at most %s)', timestamp, self.__upper_time)
			return
		gathered = self.__gather_counts[criterion]
		# We have the data as [timeslot = [hash = [value in bucket]]] and want
		# [hash = [bucket = [value in timeslot]]]. Transpose that.
		new = map(lambda hnum:
			map(lambda bnum:
				map(lambda tslot: tslot[hnum][bnum], data),
			range(0, self.__bucket_count)),
		range(0, self.__hash_count))
		assert(len(gathered) == len(new) and len(gathered) == self.__hash_count)
		for (ghash, nhash) in zip(gathered, new):
			assert(len(ghash) == len(nhash) and len(ghash) == self.__bucket_count)
			for (gbucket, nbucket) in zip(ghash, nhash):
				# Extend them so they are of the same length. As new clients start
				# later, we extend with zeroes on the left side.
				mlen = max(len(gbucket), len(nbucket))
				gbucket[:0] = [0] * (mlen - len(gbucket))
				nbucket[:0] = [0] * (mlen - len(nbucket))
				assert(len(gbucket) == len(nbucket) and len(gbucket) == mlen)
				for i in range(0, len(gbucket)):
					gbucket[i] += nbucket[i]
