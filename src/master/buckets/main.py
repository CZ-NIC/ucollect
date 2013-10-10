#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2013 CZ.NIC
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

from twisted.internet.task import LoopingCall
from twisted.internet import reactor, threads
import time
import struct
import socket
import logging
import importlib
import re

import database
import activity
import plugin
import buckets.group
import buckets.client
import buckets.rng

logger = logging.getLogger(name='buckets')

def store_keys(groups):
	logger.info("Storing buckets")
	with database.transaction() as t:
		t.execute('SELECT NOW()')
		(now,) = t.fetchone()
		def aggregate(l1, l2):
			l1.extend(l2)
			return l1
		def cdata(crit):
			def gdata(gname):
				group = groups[crit][gname]
				(keys, count, strengths) = group.keys_extract()
				return map(lambda key: (crit, now, key, len(keys[key]), count, strengths[key], gname), keys.keys())
			return reduce(aggregate, map(gdata, groups[crit].keys()))
		data = reduce(aggregate, map(cdata, groups.keys()))
		t.executemany('INSERT INTO anomalies(from_group, type, timestamp, value, relevance_count, relevance_of, strength) SELECT groups.id, %s, %s, %s, %s, %s, %s FROM groups WHERE groups.name = %s', data)

def process_group(criterion, group):
	logger.info('Processing criterion %s', criterion.code())
	anomalies = group.anomalies()
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
		examine.extend(map(lambda (index, anomality): index, an))
	if do_send:
		return (examine, map(dict, anomalies))
	else:
		return (None, None)

class BucketsPlugin(plugin.Plugin):
	"""
	Counterpart of the "buckets" plugin in the client. It does
	analysis by hashing data into buckets by several statistics.
	"""
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__bucket_count = int(config['bucket_count'])
		self.__hash_count = int(config['hash_count'])
		def getCriterion(name):
			(modulename, classname) = name.rsplit('.', 1)
			module = importlib.import_module(modulename)
			result = getattr(module, classname)()
			logger.info('Loaded criterion %s from %s', result.code(), name)
			return result
		self.__criteria = map(getCriterion, re.split('\s+', config['criteria']))
		self.__history_size = int(config['history_size'])
		self.__config_version = int(config['config_version'])
		self.__max_key_count = int(config['max_key_count'])
		self.__granularity = int(float(config['granularity']) * 1000)
		self.__max_timeslots = int(float(config['max_timeslots']))
		# Just an arbitrary number
		self.__seed = 872945724987
		self.__downloader = LoopingCall(self.__init_download)
		self.__downloader.start(int(config['interval']), False)
		# We are just gathering data between these two time stamps
		self.__lower_time = 0
		self.__upper_time = 0
		self.__gather_history_max = int(config['gather_history_max'])
		self.__process_delay = int(config['aggregate_delay'])
		self.__treshold = float(config['anomaly_threshold'])
		self.__groups = {}
		for crit in self.__criteria:
			self.__groups[crit.code()] = {}
		self.__clients = {}
		self.__gathering = False
		self.__aggregating_keys = False
		self.__have_keys = False
		self.__hasher = buckets.rng.Hash(self.__seed, self.__hash_count, 256 * max(map(lambda c: c.item_len(), self.__criteria)))
		# Do we have keys to commit?
		self.__background_processing = False

	def client_connected(self, client):
		name = client.cid()
		with database.transaction() as t:
			t.execute('SELECT groups.name FROM groups JOIN group_members ON groups.id = group_members.in_group JOIN clients ON group_members.client = clients.id WHERE clients.name = %s', (name,))
			groups = map(lambda g: g[0], t.fetchall())
		self.__clients[name] = buckets.client.Client(name, groups, lambda message: self.send(message, name))
		# Add the client to all the groups in each criterion
		for g in self.__clients[name].groups():
			for crit in self.__criteria:
				# Does the group exist, or create an empty one?
				if g not in self.__groups[crit.code()]:
					logger.debug("Creating group %s in criterion %s", g, crit.code());
					self.__groups[crit.code()][g] = buckets.group.Group(hash_count=self.__hash_count, bucket_count=self.__bucket_count, window_backlog=self.__gather_history_max, treshold=self.__treshold, hasher=self.__hasher)
				self.__groups[crit.code()][g].add(name)

	def client_disconnected(self, client):
		name = client.cid()
		if not name in self.__clients:
			# Generally, this should not happen. It could if the database manipulation
			# in above routine fails, but that should be rare. Anyway, we have seen this.
			logger.warn("Client %s not found, can't disconnect it", name)
			return
		cobj = self.__clients[name]
		# Remove the client from all the groups
		for g in cobj.groups():
			for crit in self.__criteria:
				self.__groups[crit.code()][g].remove(name)
				if not self.__groups[crit.code()][g].members():
					# Remove an empty group
					del self.__groups[crit.code()][g]
		self.__clients[name].deactivate()
		del self.__clients[name]

	def __gather_start(self, now):
		"""
		Start gathering of data
		"""
		# Move to the next window to gather
		self.__lower_time = self.__upper_time
		self.__upper_time = now
		self.__gathering = True
		# Provide empty data
		reactor.callLater(self.__process_delay, self.__process)

	def __process_keys(self):
		"""
		Extract the keys aggregated in groups and send them to storage.
		"""
		self.__aggregating_keys = False
		if not self.__have_keys:
			return
		def done(ignore_param):
			self.__background_processing = False
		deferred = threads.deferToThread(store_keys, self.__groups)
		deferred.addCallback(done)

	def __process(self):
		"""
		Process the gathered data.
		"""
		self.__gathering = False
		if self.__background_processing:
			logger.error("Previous data not committed yet, skipping one generation")
			return
		self.__background_processing = True
		generation = self.__lower_time
		cindex = 0
		# Start aggregating the keys
		self.__aggregating_keys = True
		self.__have_keys = False
		reactor.callLater(self.__process_delay, self.__process_keys)
		for crit in self.__criteria:
			for g in self.__groups[crit.code()]:
				group = self.__groups[crit.code()][g]
				def one_group(criterion, group, group_name, cindex):
					# Get a new scope, so we preserve copies of variables in parameters.
					# Otherwise, next iteratioun would overwrite the variables and all
					# the functions would use the same ones.
					(examine, strengths) = process_group(criterion, group)

					if examine:
						logger.debug('Asking for keys %s on criterion %s and group %s at %s', examine, criterion.code(), group_name, generation)
						def ask_client(client):
							# The same trick with scope.
							def callback(message, success):
								if success:
									if self.__aggregating_keys:
										group.keys_aggregate(client.name(), criterion.decode_multiple(message), strengths, criterion.decode_raw_multiple(message))
									else:
										logger.debug("Late reply for keys ignored")
								else:
									logger.warn("Client %s doesn't have keys for generation %s on criterion %s", client.name(), generation, criterion.code())
							client.get_keys(cindex, generation, examine, callback)
						# Send it to all the clients.
						for client in group.members():
							ask_client(criterion, self.__clients[client], group, strengths)
					else:
						logger.debug('No anomaly asked on criterion %s and group %s at %s', criterion.code(), group_name, generation)

				one_group(crit, group, g, cindex)

			cindex += 1

	def name(self):
		return "Buckets"

	def message_from_client(self, message, client):
		kind = message[0]
		if kind == 'C':
			logger.debug('Config %s for client %s at %s', self.__config_version, client, int(time.time()))
			# It asks for config. Send some.
			self.send('C' + self.__config(), client)
			# And that makes it active.
			self.__clients[client].activate()
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
				self.__merge(timestamp, map(lambda g: self.__groups[crit.code()][g], self.__clients[client].groups()), to_merge)
			activity.log_activity(client, "buckets")
		elif kind == 'K':
			# Got keys from the plugin
			(req_id,) = struct.unpack('!L', message[1:5])
			logger.info('Received keys from %s', client)
			buckets.client.manager.response(req_id, message[5:])
			self.__have_keys = True
		elif kind == 'M':
			(req_id,) = struct.unpack('!L', message[1:5])
			buckets.client.manager.missing(req_id)
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
		if not self.__gathering:
			logger.warn('Not gathering now')
			return
		for g in cgroups:
			g.merge(data)
