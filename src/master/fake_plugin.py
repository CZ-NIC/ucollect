#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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
import logging
import struct
import plugin
import activity
import socket
import protocol
import database
import psycopg2

logger = logging.getLogger(name='fake')

types = ['connect', 'disconnect', 'lost', 'extra', 'timeout', 'login']
families = [{
	'len': 4,
	'opt': socket.AF_INET
}, {
	'len': 16,
	'opt': socket.AF_INET6
}]

def store_logs(message, client, now, version):
	values = []
	count = 0
	while message:
		if version <= 1:
			(age, type_idx, family_idx, info_count, code) = struct.unpack('!IBBBc', message[:8])
			rem_port = None
			message = message[8:]
		else:
			(age, type_idx, family_idx, info_count, code, rem_port) = struct.unpack('!IBBBcH', message[:10])
			message = message[10:]
		(name, passwd, reason) = (None, None, None)
		tp = types[type_idx]
		family = families[family_idx]
		rem_address = socket.inet_ntop(family['opt'], message[:family['len']])
		message = message[family['len']:]
		if version <= 1:
			loc_address = None
		else:
			loc_address = socket.inet_ntop(family['opt'], message[:family['len']])
			message = message[family['len']:]
		for i in range(0, info_count):
			(kind_i,) = struct.unpack('!B', message[0])
			(content, message) = protocol.extract_string(message[1:])
			# Twisted gives us the message as a string. The name and password
			# columns are bytea in postgres. This needs to be resolved by
			# a conversion wrapper (because python seems to use escaping, not
			# bound params)
			if kind_i == 0:
				name = psycopg2.Binary(content)
			elif kind_i == 1:
				passwd = psycopg2.Binary(content)
			elif kind_i == 2:
				reason = content
		values.append((now, age, tp, rem_address, loc_address, rem_port, name, passwd, reason, client, code))
		count += 1
	with database.transaction() as t:
		t.executemany("INSERT INTO fake_logs (client, timestamp, event, remote, local, remote_port, server, name, password, reason) SELECT clients.id, %s - %s * INTERVAL '1 millisecond', %s, %s, %s, %s, fake_server_names.type, %s, %s, %s FROM clients CROSS JOIN fake_server_names WHERE clients.name = %s AND fake_server_names.code = %s", values)
	logger.debug("Stored %s fake server log events for client %s", count, client)

class FakePlugin(plugin.Plugin):
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__config = config

	def name(self):
		return 'Fake'

	def message_from_client(self, message, client):
		if message[0] == 'L':
			activity.log_activity(client, 'fake')
			reactor.callInThread(store_logs, message[1:], client, database.now(), self.version(client))
		elif message[0] == 'C':
			config = struct.pack('!IIIII', *map(lambda name: int(self.__config[name]), ['version', 'max_age', 'max_size', 'max_attempts', 'throttle_holdback']))
			self.send('C' + config, client)
		else:
			logger.error("Unknown message from client %s: %s", client, message)
