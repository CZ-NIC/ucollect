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
import zmq
import msgpack

# FIXME: This actually needs to be global for the whole process and this
# probably isn't the best place.
context = zmq.Context()
# The authentication stuff would go somewhere here
zsocket = context.socket(zmq.PUSH)
zsocket.connect('tcp://localhost:9988')

logger = logging.getLogger(name='fake')

types = ['connect', 'disconnect', 'lost', 'extra', 'timeout', 'login']
families = [{
	'len': 4,
	'opt': socket.AF_INET
}, {
	'len': 16,
	'opt': socket.AF_INET6
}]
extras = ['name', 'password', 'reason', 'method', 'uri', 'host']
servers = {
	'T': ('telnet', 23),
	'H': ('http', 80),
	't': ('telnet_alt', 2323),
	'P': ('squid_http_proxy', 3128),
	'p': ('polipo_http_proxy', 8123)
}

def msg_handle(client, message, now):
	# We parse the messages and send them. Alternatively, we could dump the
	# whole binary blob into the socket and let it be done by someone else.
	# But then the server logic and the protocol parsing/serialization
	# would be split in the middle (we would still need to provide the
	# config), which doesn't feel right.
	while message:
		(age, type_idx, family_idx, info_count, code, rem_port) = struct.unpack('!IBBBcH', message[:10])
		message = message[10:]
		family = families[family_idx]
		rem_address = socket.inet_ntop(family['opt'], message[:family['len']])
		message = message[family['len']:]
		loc_address = socket.inet_ntop(family['opt'], message[:family['len']])
		message = message[family['len']:]
		(server, loc_port) = servers[code]
		record = {
			'client': client,
			# TODO: Proper solution is to actually comput now - age
			# here, but now is in database specific format
			# (ISO-something). We would do it properly on real
			# implementation, but let's just send it on in this
			# hack.
			'now': str(now),
			'age': age,
			'type': types[type_idx],
			'remote': (rem_address, rem_port),
			'local': (loc_address, loc_port),
			'server': server
		}
		for i in range(0, info_count):
			(kind_i,) = struct.unpack('!B', message[0])
			(content, message) = protocol.extract_string(message[1:])
			record[extras[kind_i]] = content
		# Send the message with a frame stating what is inside
		logger.debug("Sending.....")
		zsocket.send_string('data/fake-logs', zmq.SNDMORE)
		zsocket.send(msgpack.packb(record))

class FakePlugin(plugin.Plugin):
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__config = config

	def name(self):
		return 'Fake'

	def message_from_client(self, message, client):
		if message[0] == 'L':
			activity.log_activity(client, 'fake')
			msg_handle(client, message[1:], database.now())
		elif message[0] == 'C':
			config = struct.pack('!IIIII', *map(lambda name: int(self.__config[name]), ['version', 'max_age', 'max_size', 'max_attempts', 'throttle_holdback']))
			self.send('C' + config, client)
		else:
			logger.error("Unknown message from client %s: %s", client, message)
