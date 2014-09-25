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
import plugin
import database
import logging
import socket
import struct
import random

logger = logging.getLogger(name='spoof')

class Token:
	def __init__(self, client, time):
		self.__value = random.randint(0, 2**64 - 1)
		self.__client = client
		self.__time = time
		self.__expect_spoofed = True
		self.__expect_ordinary = True

	def value(self):
		return self.__value

class SpoofPlugin(plugin.Plugin):
	"""
	Plugin asking clients to send spoofed packets and checking if they arrive.
	This is to test if ISPs properly block packets with bad source address.
	"""
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__tokens = {}
		self.__answer_timeout = int(config['answer_timeout'])
		self.__dest_addr = config['dest_addr']
		self.__src_addr = config['src_addr']
		self.__port = int(config['port'])
		self.__check_timer = LoopingCall(self.__check)
		# TODO: Change the time to something larger
		self.__check_timer.start(10, True)

	def message_from_client(self, message, client):
		logger.error("Message from spoof plugin, but none expected: %s, on client %s", message, client)

	def name(self):
		return "Spoof"

	def __check(self):
		"""
		Check the DB to see if we should ask for another round of spoofed packets.
		"""
		with database.transaction() as t:
			# TODO: Check if we really need to run now
			t.execute("SELECT CURRENT_TIMESTAMP AT TIME ZONE 'UTC'");
			(now,) = t.fetchone()
		logger.info('Asking clients to send spoofed packets')
		batch = set()
		prefix = '4' + \
			socket.inet_pton(socket.AF_INET, socket.gethostbyname(self.__src_addr)) + \
			socket.inet_pton(socket.AF_INET, socket.gethostbyname(self.__dest_addr)) + \
			struct.pack("!H", self.__port)
		for client in self.plugins().get_clients():
			token = Token(client, now)
			self.__tokens[token.value()] = token
			batch.add(token.value())
			self.send(prefix + struct.pack('!Q', token.value()), client)
		# Drop the tokens after some time if they get no answer
		# (Dropping the already handled ones doesn't matter)
		def cleanup():
			for tok in batch:
				try:
					del self.__tokens[tok]
				except KeyError:
					pass # Not there. But we don't care.
		reactor.callLater(self.__answer_timeout, cleanup)
