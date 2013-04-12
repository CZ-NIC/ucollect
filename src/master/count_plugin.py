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
	def __init__(self, plugins):
		plugin.Plugin.__init__(self, plugins)
		self.__downloader = LoopingCall(self.__init_download)
		self.__downloader.start(10, False)
		self.__data = {}
		self.__stats = {}
		self.__last = int(time.time())
		self.__current = int(time.time())
		with database.transaction() as t:
			t.execute('SELECT name, id FROM count_types')
			self.__names = dict(t.fetchall())
		self.__name_order = ("All", "IPv4", "IPv6", "In", "Out", "TCP", "UDP", "ICMP", 'Low port', "SYN", "FIN", "SYN+ACK", "ACK", "PUSH")

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
		reactor.callLater(5, self.__process)

	def __process(self):
		if not self.__data:
			return # No data to store.
		logger.info('Storing count snapshot')
		with database.transaction() as t:
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
				return map(lambda name, index: (snapshot, self.__names[name], self.__data[client][index * 2], self.__data[client][index * 2 + 1]), self.__name_order, range(0, len(self.__name_order)))
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
		database.log_activity(client, "counts")
