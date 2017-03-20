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
import database
import plugin
import activity
import logging
import struct
import socket
import rate_limit

logger = logging.getLogger(name='refused')

def store_connections(max_records, message, client, now):
	(basetime,) = struct.unpack('!Q', message[:8])
	message = message[8:]
	values = []
	count = 0
	while message:
		(time, reason, family, loc_port, rem_port) = struct.unpack('!QcBHH', message[:14])
		addr_len = 4 if family == 4 else 16
		address = message[14:14 + addr_len]
		address = socket.inet_ntop(socket.AF_INET if family == 4 else socket.AF_INET6, address)
		message = message[14 + addr_len:]
		if basetime - time > 86400000:
			logger.error("Refused time difference is out of range for client %s: %s", client, basetime - time)
			continue
		values.append((now, basetime - time, address, loc_port, rem_port, reason, client))
		count += 1
	if count > max_records:
		logger.warn("Unexpectedly high number of refused connections in the message from client %s - %s connection, max expected %s. Ignoring.", client, count, max_records)
		return
	with database.transaction() as t:
		t.executemany("INSERT INTO refused (client, timestamp, address, local_port, remote_port, reason) SELECT clients.id, %s - %s * INTERVAL '1 millisecond', %s, %s, %s, %s FROM clients WHERE clients.name = %s", values)
	logger.debug("Stored %s refused connections for client %s", count, client)

class RefusedPlugin(plugin.Plugin):
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__config = config
		self.__rate_limiter = rate_limit.RateLimiter(100, 1000, 60) #maximum 100 (in average) records per 60 seconds (peak 1000)

	def name(self):
		return 'Refused'

	def message_from_client(self, message, client):
		if message == 'C':
			logger.debug("Sending config %s to client %s", self.__config['version'], client)
			config = struct.pack('!IIIIQQ', *map(lambda name: int(self.__config[name]), ['version', 'finished_limit', 'send_limit', 'undecided_limit', 'timeout', 'max_age']))
			self.send('C' + config, client)
		elif message[0] == 'D':
			activity.log_activity(client, 'refused')
			if not self.__rate_limiter.check_rate(client, 1):
				logger.warn("Storing refused connections for client %s blocked by rate limiter.", client)
				return
			# the limit for the number of records in a message is 2*send_limit because the client may buffer up to two times the number if he disconnects/reconnects
			reactor.callInThread(store_connections, 2 * int(self.__config['send_limit']), message[1:], client, database.now())
		else:
			logger.error("Unknown message from client %s: %s", client, message)
