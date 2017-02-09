#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2014,2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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

from twisted.internet import reactor
import struct
import plugin
import time
import logging
import database
import activity
import timers

logger = logging.getLogger(name='bandwidth')

# Count of items that are send for one window
PROTO_ITEMS_PER_WINDOW = 3
PROTO_ITEMS_PER_BUCKET = 5

BUCKETS_CNT = 40
BUCKET_MAP = {
	250: 0,
	500: 1,
	750: 2,
	1000: 3,
	2000: 4,
	3000: 5,
	4000: 6,
	5000: 7,
	6000: 8,
	7000: 9,
	8000: 10,
	9000: 11,
	10000: 12,
	11000: 13,
	12000: 14,
	13000: 15,
	14000: 16,
	15000: 17,
	16000: 18,
	17000: 19,
	18000: 20,
	19000: 21,
	20000: 22,
	30000: 23,
	40000: 24,
	50000: 25,
	60000: 26,
	70000: 27,
	80000: 28,
	90000: 29,
	100000: 30,
	200000: 31,
	300000: 32,
	400000: 33,
	500000: 34,
	600000: 35,
	700000: 36,
	800000: 37,
	900000: 38,
	1000000: 39
}

class Window:
	"""
	Class desigened to store data of one clients window.
	"""
	def __init__(self, window_length, in_max, out_max):
		self.length = window_length
		self.in_max = in_max
		self.out_max = out_max

class Bucket:
	def __init__(self, bucket, in_time, in_bytes, out_time, out_bytes):
		self.bucket = bucket
		self.in_time = in_time
		self.in_bytes = in_bytes
		self.out_time = out_time
		self.out_bytes = out_bytes

class ClientData:
	"""
	Class that stores all windows of client
	"""
	def __init__(self, version):
		self.version = version
		self.cnt = 0
		self.windows = {}
		self.buckets = {}
		self.timestamp_dbg = None

	def add_window(self, window_length, in_max, out_max):
		self.cnt += 1
		self.windows[window_length] = Window(window_length, in_max, out_max)

	def add_bucket(self, bucket, in_time, in_bytes, out_time, out_bytes):
		self.cnt += 1
		self.buckets[bucket] = Bucket(bucket, in_time, in_bytes, out_time, out_bytes)

def store_bandwidth(data, now):
	logger.info('Storing bandwidth snapshot')

	with database.transaction() as t:
		for client, cldata in data.items():
			for window in cldata.windows.itervalues():
				t.execute("""INSERT INTO bandwidth (client, timestamp, win_len, in_max, out_max)
				SELECT clients.id AS client, %s, %s, %s, %s
				FROM clients
				WHERE name = %s
				""", (now, window.length, window.in_max, window.out_max, client))

		for client, cldata in data.items():
			if not cldata.buckets:
				continue

			try:
				in_time = [0] * BUCKETS_CNT
				in_bytes = [0] * BUCKETS_CNT
				out_time = [0] * BUCKETS_CNT
				out_bytes = [0] * BUCKETS_CNT

				for bucket in cldata.buckets.itervalues():
					pos = BUCKET_MAP[bucket.bucket]
					in_time[pos] = bucket.in_time
					in_bytes[pos] = bucket.in_bytes
					out_time[pos] = bucket.out_time
					out_bytes[pos] = bucket.out_bytes

				t.execute("""SELECT client, timestamp, in_time, in_bytes, out_time, out_bytes
				FROM bandwidth_stats
				JOIN clients ON bandwidth_stats.client = clients.id
				WHERE name = %s AND timestamp = date_trunc('hour', %s)
				""", (client, now))
				result = t.fetchone()
				if result == None:
					in_time = [0] * BUCKETS_CNT
					in_bytes = [0] * BUCKETS_CNT
					out_time = [0] * BUCKETS_CNT
					out_bytes = [0] * BUCKETS_CNT

					for bucket in cldata.buckets.itervalues():
						pos = BUCKET_MAP[bucket.bucket]
						in_time[pos] = bucket.in_time
						in_bytes[pos] = bucket.in_bytes
						out_time[pos] = bucket.out_time
						out_bytes[pos] = bucket.out_bytes

					t.execute("""INSERT INTO bandwidth_stats (client, timestamp, in_time, in_bytes, out_time, out_bytes)
					SELECT clients.id AS client, date_trunc('hour', %s) as timestamp, %s, %s, %s, %s
					FROM clients
					WHERE name = %s
					""", (now, in_time, in_bytes, out_time, out_bytes, client))
				else:
					client_id = result[0]
					timestamp = result[1]
					in_time = result[2]
					in_bytes = result[3]
					out_time = result[4]
					out_bytes = result[5]

					for bucket in cldata.buckets.itervalues():
						pos = BUCKET_MAP[bucket.bucket]
						in_time[pos] += bucket.in_time
						in_bytes[pos] += bucket.in_bytes
						out_time[pos] += bucket.out_time
						out_bytes[pos] += bucket.out_bytes

					t.execute("""UPDATE bandwidth_stats
					SET in_time = %s, in_bytes = %s, out_time = %s, out_bytes = %s
					WHERE client = %s AND timestamp = %s
					""", (in_time, in_bytes, out_time, out_bytes, client_id, timestamp))

			except KeyError:
				# Some clients send invalid data (bucket with index 0). While we need to solve that, we at least don't want to kill data for all the clients in such a case.
				logger.exception("Broken data from client %s", client)


class BandwidthPlugin(plugin.Plugin):
	"""
	Plugin Bandwidth provides statistics about client's internet connection speed
	and allows to make statistics about it.
	"""
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__interval = int(config['interval'])
		self.__aggregate_delay = int(config['aggregate_delay'])
		self.__downloader = timers.timer(self.__init_download, self.__interval, False)
		self.__data = {}
		self.__last = self.__current = int(time.time())

	def __init_download(self):
		"""
		Ask all the clients to send their statistics.
		"""
		# Send a request with current timestamp
		t = int(time.time())
		self.__last = self.__current
		self.__current = t
		self.broadcast(struct.pack('!Q', t))
		self.__data = {}
		reactor.callLater(self.__aggregate_delay, self.__process)

	def __process(self):
		if not self.__data:
			return # No data to store.
		# As manipulation with DM might be time consuming (as it may be blocking, etc),
		# move it to a separate thread, so we don't block the communication. This is
		# safe -- we pass all the needed data to it as parameters and get rid of our
		# copy, passing the ownership to the task.
		reactor.callInThread(store_bandwidth, self.__data, database.now())
		self.__data = {}

	def name(self):
		return 'Bandwidth'

	def message_from_client(self, message, client):
		"""
		This method parses message from client.
		"""
		# Parse message from client
		# Message contains 64bit numbers - 3 numbers for every window
		int_count = len(message) / 8
		data = struct.unpack("!" + str(int_count) + "Q", message);

		logger.debug("Bandwidth data from client %s: %s", client, data)

		# Add client's record
		if not client in self.__data:
			self.__data[client] = ClientData(self.version(client));

		# Extract timestamp from message and skip it
		timestamp = data[0]
		if timestamp < self.__last:
			logger.info("Data of bandwidth snapshot on %s too old, ignoring (%s vs. %s)", client, timestamp, self.__last)
			return
		self.__data[client].timestamp_dbg = timestamp

		win_cnt = data[1]
		buckets_cnt_pos = 2 + PROTO_ITEMS_PER_WINDOW * win_cnt
		data_windows = data[2:buckets_cnt_pos]
		buckets_cnt = data[buckets_cnt_pos]
		data_buckets = data[(buckets_cnt_pos+1):]

		# Get data from message
		for i in range(0, win_cnt):
			self.__data[client].add_window(
				data_windows[i*PROTO_ITEMS_PER_WINDOW],
				data_windows[i*PROTO_ITEMS_PER_WINDOW+1],
				data_windows[i*PROTO_ITEMS_PER_WINDOW+2]
			)

		for i in range(0, buckets_cnt):
			self.__data[client].add_bucket(
				data_buckets[i*PROTO_ITEMS_PER_BUCKET],
				data_buckets[i*PROTO_ITEMS_PER_BUCKET+1],
				data_buckets[i*PROTO_ITEMS_PER_BUCKET+2],
				data_buckets[i*PROTO_ITEMS_PER_BUCKET+3],
				data_buckets[i*PROTO_ITEMS_PER_BUCKET+4]
			)

		# Log client's activity
		activity.log_activity(client, "bandwidth")

	def client_connected(self, client):
		"""
		A client connected. Ask for the current stats. It will get ignored (because it'll have time of
		0 probably, or something old anyway), but it resets the client, so we'll get the counts for the
		current snapshot.
		"""
		self.send(struct.pack('!Q', int(time.time())), client.cid())
