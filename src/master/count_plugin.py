#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2013,2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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
from twisted.internet import reactor
import struct
import plugin
import time
import logging
import database
import activity

logger = logging.getLogger(name='count')

def store_counts(data, stats, now):
	logger.info('Storing count snapshot')
	with database.transaction() as t:
		t.execute('SELECT name, id FROM count_types ORDER BY ord')
		name_data = t.fetchall()
		name_order = map(lambda x: x[0], name_data)
		names = dict(name_data)
		# It seems MySQL complains with insert ... select in some cases.
		# So we do some insert-select-insert magic here. That is probably
		# slower, but no idea how to help that. And it should work.
		t.execute('SELECT name, id FROM clients WHERE name IN (' + (','.join(['%s'] * len(data))) + ')', data.keys())
		clients = dict(t.fetchall())
		# Create a snapshot for each client
		t.executemany('INSERT INTO count_snapshots (timestamp, client) VALUES(%s, %s)', map(lambda client: (now, client), clients.values()))
		t.execute('SELECT client, id FROM count_snapshots WHERE timestamp = %s', (now,))
		snapshots = dict(t.fetchall())
		# Push all the data in
		def truncate(data, limit):
			if data > 2**limit-1:
				logger.warn("Number %s overflow, truncating to %s", data, 2**limit-1)
				return 2**limit-1
			else:
				return data
		def clientdata(client):
			snapshot = snapshots[clients[client]]
			l = min(len(data[client]) / 2, len(name_order))
			return map(lambda name, index: (snapshot, names[name], truncate(data[client][index * 2], 63), truncate(data[client][index * 2 + 1], 63)), name_order[:l], range(0, l))
		def clientcaptures(client):
			snapshot = snapshots[clients[client]]
			return map(lambda i: (snapshot, i, truncate(stats[client][3 * i], 31), truncate(stats[client][3 * i + 1], 31), truncate(stats[client][3 * i + 2], 31)), range(0, len(stats[client]) / 3))
		def join_clients(c1, c2):
			c1.extend(c2)
			return c1
		t.executemany('INSERT INTO counts(snapshot, type, count, size) VALUES(%s, %s, %s, %s)', reduce(join_clients, map(clientdata, data.keys())))
		t.executemany('INSERT INTO capture_stats(snapshot, interface, captured, dropped, dropped_driver) VALUES(%s, %s, %s, %s, %s)', reduce(join_clients, map(clientcaptures, stats.keys())))

class CountPlugin(plugin.Plugin):
	"""
	The plugin providing basic statisticts, like speed, number of
	dropped packets, etc.
	"""
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__interval = int(config['interval'])
		self.__aggregate_delay = int(config['aggregate_delay'])
		self.__downloader = LoopingCall(self.__init_download)
		self.__downloader.start(self.__interval, False)
		self.__data = {}
		self.__stats = {}
		self.__last = int(time.time())
		self.__current = int(time.time())

	def __init_download(self):
		"""
		Ask all the clients to send their statistics.
		"""
		# Send a request with current timestamp
		t = int(time.time())
		self.__last = self.__current
		self.__current = t
		self.broadcast(struct.pack('!Q', t))
		# Wait a short time, so they can send us some data and process it after that.
		self.__data = {}
		self.__stats = {}
		reactor.callLater(self.__aggregate_delay, self.__process)

	def __process(self):
		if not self.__data:
			return # No data to store.
		# As manipulation with DB might be time consuming (as it may be blocking, etc),
		# move it to a separate thread, so we don't block the communication. This is
		# safe -- we pass all the needed data to it as parameters and get rid of our
		# copy, passing the ownership to the task.
		reactor.callInThread(store_counts, self.__data, self.__stats, database.now())
		self.__data = {}
		self.__stats = {}

	def name(self):
		return 'Count'

	def message_from_client(self, message, client):
		count = len(message) / 4 - 2 # 2 for the timestamp
		dtype = 'L'
		data = struct.unpack('!Q' + str(count) + 'L', message)
		if data[0] < self.__last:
			logger.info("Data snapshot on %s too old, ignoring (%s vs. %s)", client, data[0], self.__last)
			return
		if_count = data[1]
		self.__stats[client] = data[2:2 + 3 * if_count]
		d = data[2 + 3 * if_count:]
		if len(d) > 32:
			# TODO: Remove this hack. It is temporary for the time when we have both clients
			# sending 32bit sizes and 64bit sizes. If it's too long, it is 64bit - reencode
			# the data and decode as 64bit ints.
			packed = struct.pack("!" + str(len(d)) + 'L', *d)
			d = struct.unpack('!' + str(len(d) / 2) + 'Q', packed)
		self.__data[client] = d
		logger.debug("Data: %s", data)
		if len(self.__data[client]) % 2:
			logger.error("Odd count of data elements (%s) from %s", len(self.__data[client]), client)
		activity.log_activity(client, "counts")

	def client_connected(self, client):
		"""
		A client connected. Ask for the current counts. It will get ignored (because it'll have time of
		0 probably, or something old anyway), but it resets the client, so we'll get the counts for the
		current snapshot.
		"""
		self.send(struct.pack('!Q', int(time.time())), client.cid())
