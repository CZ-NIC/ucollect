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
from twisted.internet import reactor
import struct
import plugin
import time
import logging
import database

logger = logging.getLogger(name='count')

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
		logger.info('Storing count snapshot')
		with database.transaction() as t:
			t.execute('SELECT name, id FROM count_types ORDER BY ord')
			name_data = t.fetchall()
			name_order = map(lambda x: x[0], name_data)
			names = dict(name_data)
			# Store the timestamp here, so all the clients have the same value.
			t.execute('SELECT NOW()')
			(now,) = t.fetchone()
			# FIXME
			# It seems MySQL complains with insert ... select in some cases.
			# So we do some insert-select-insert magic here. That is probably
			# slower, but no idea how to help that.
			t.execute('SELECT name, id FROM clients WHERE name IN (' + (','.join(['%s'] * len(self.__data))) + ')', self.__data.keys())
			clients = dict(t.fetchall())
			# Create a snapshot for each client
			t.executemany('INSERT INTO count_snapshots (timestamp, client) VALUES(%s, %s)', map(lambda client: (now, client), clients.values()))
			t.execute('SELECT client, id FROM count_snapshots WHERE timestamp = %s', (now,))
			snapshots = dict(t.fetchall())
			# Push all the data in
			def clientdata(client):
				snapshot = snapshots[clients[client]]
				l = min(len(self.__data[client]) / 2, len(name_order))
				return map(lambda name, index: (snapshot, names[name], self.__data[client][index * 2], self.__data[client][index * 2 + 1]), name_order[:l], range(0, l))
			def clientcaptures(client):
				snapshot = snapshots[clients[client]]
				return map(lambda i: (snapshot, i, self.__stats[client][3 * i], self.__stats[client][3 * i + 1], self.__stats[client][3 * i + 2]), range(0, len(self.__stats[client]) / 3))
			def join_clients(c1, c2):
				c1.extend(c2)
				return c1
			t.executemany('INSERT INTO counts(snapshot, type, count, size) VALUES(%s, %s, %s, %s)', reduce(join_clients, map(clientdata, self.__data.keys())))
			t.executemany('INSERT INTO capture_stats(snapshot, interface, captured, dropped, dropped_driver) VALUES(%s, %s, %s, %s, %s)', reduce(join_clients, map(clientcaptures, self.__stats.keys())))

	def name(self):
		return 'Count'

	def message_from_client(self, message, client):
		count = len(message) / 4 - 2 # 2 for the timestamp
		data = struct.unpack('!Q' + str(count) + 'L', message)
		if (data[0] < self.__last):
			logger.info("Data snapshot on %s too old, ignoring (%s vs. %s)", client, data[0], self.__last)
			return
		if_count = data[1]
		self.__stats[client] = data[2:2 + 3 * if_count]
		self.__data[client] = data[2 + 3 * if_count:]
		logger.debug("Data: %s", data)
		if len(self.__data[client]) % 2:
			logger.error("Odd count of data elements (%s) from %s", len(self.__data[client]), client)
		database.log_activity(client, "counts")
