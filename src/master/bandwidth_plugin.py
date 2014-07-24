#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2014 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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

logger = logging.getLogger(name='bandwidth')

# Count of items that are send for one window
PROTO_ITEMS_PER_WINDOW = 3

class Window:
	"""
	Class desigened to store data of one clients window.
	"""
	def __init__(self, window_length, in_max, out_max):
		self.length = window_length
		self.in_max = in_max
		self.out_max = out_max

class ClientData:
	"""
	Class that stores all windows of client
	"""
	def __init__(self):
		self.cnt = 0
		self.windows = {}

	def add_window(self, window_length, in_max, out_max):
		self.cnt += 1
		self.windows[window_length] = Window(window_length, in_max, out_max)

def store_bandwidth(data):
	logger.info('Storing bandwidth snapshot')

	with database.transaction() as t:
		t.execute("SELECT CURRENT_TIMESTAMP AT TIME ZONE 'UTC'");
		(now,) = t.fetchone()

		for client, cldata in data.items():
			for window in cldata.windows.itervalues():
				t.execute("INSERT INTO bandwidth (client, timestamp, win_len, in_max, out_max) SELECT clients.id AS client, %s, %s, %s, %s FROM clients WHERE name = %s;", (now, window.length, window.in_max, window.out_max, client))

class BandwidthPlugin(plugin.Plugin):
	"""
	Plugin Bandwidth provides statistics about client's internet connection speed
	and allows to make statistics about it.
	"""
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__interval = int(config['interval'])
		self.__aggregate_delay = int(config['aggregate_delay'])
		self.__downloader = LoopingCall(self.__init_download)
		self.__downloader.start(self.__interval, False)
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
		reactor.callInThread(store_bandwidth, self.__data)
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
			self.__data[client] = ClientData();

		# Extract timestamp from message and skip it
		timestamp = data[0]
		int_count -= 1
		data = data[1:]

		if timestamp < self.__last:
			logger.info("Data of bandwidth snapshot on %s too old, ignoring (%s vs. %s)", client, timestamp, self.__last)
			return

		# Get data from message
		windows = int_count / PROTO_ITEMS_PER_WINDOW
		for i in range(0, windows):
			self.__data[client].add_window(data[i*PROTO_ITEMS_PER_WINDOW], data[i*PROTO_ITEMS_PER_WINDOW+1], data[i*PROTO_ITEMS_PER_WINDOW+2])

		# Log client's activity
		activity.log_activity(client, "bandwidth")


	def client_connected(self, client):
		"""
		A client connected. Ask for the current stats. It will get ignored (because it'll have time of
		0 probably, or something old anyway), but it resets the client, so we'll get the counts for the
		current snapshot.
		"""
		self.send(struct.pack('!Q', int(time.time())), client.cid())