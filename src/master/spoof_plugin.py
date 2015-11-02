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
import twisted.internet.protocol
import plugin
import database
import activity
import logging
import socket
import struct
import random
import timers

logger = logging.getLogger(name='spoof')

class Token:
	def __init__(self, client, time):
		self.__value = random.randint(0, 2**64 - 1)
		self.__client = client
		self.__time = time
		self.expect_spoofed = True
		self.expect_ordinary = True

	def value(self):
		return self.__value

	def client(self):
		return self.__client

	def time(self):
		return self.__time

def store_packet(token, spoofed, matches, ip, now):
	logger.debug("Storing packet with spoof %s from client %s", spoofed, token.client())
	with database.transaction() as t:
		t.execute("INSERT INTO spoof (client, batch, spoofed, addr_matches, received, ip) SELECT id, %s, %s, %s, %s, %s FROM clients WHERE name = %s", (token.time(), spoofed, matches, now, ip, token.client()))

class UDPReceiver(twisted.internet.protocol.DatagramProtocol):
	def __init__(self, spoof):
		self.__spoof = spoof

	def datagramReceived(self, dgram, addr):
		logger.trace("Packet from %s", addr)
		if len(dgram) < 13:
			logger.warn("Spoof packet too short (probably a stray one), only %s bytes", len(dgram))
			return
		(magic, token, spoofed) = struct.unpack('!LQ?', dgram[:13])
		if magic != 0x17ACEE43:
			logger.warn("Wrong magic number in spoof packet (probably a stray one)")
			return
		tok = self.__spoof.get_token(token)
		if not tok:
			logger.warn("Token %s not known", token)
			return
		if spoofed:
			tok.expect_spoofed = False
		else:
			tok.expect_ordinary = False
		if not tok.expect_spoofed and not tok.expect_ordinary:
			self.__spoof.drop_token(token)
		reactor.callInThread(store_packet, tok, spoofed, (not spoofed) or (addr[0] == self.__spoof.src_addr()), addr[0], database.now())
		activity.log_activity(tok.client(), 'spoof')

class SpoofPlugin(plugin.Plugin):
	"""
	Plugin asking clients to send spoofed packets and checking if they arrive.
	This is to test if ISPs properly block packets with bad source address.
	"""
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__tokens = {}
		self.__reload_config()
		self.__receiver = UDPReceiver(self)
		reactor.listenUDP(self.__port, self.__receiver)
		self.__check_timer = timers.timer(self.__check, 300, False)
		self.__sent = None
		self.__batch = None
		self.__prefix = None
		self.__now = None

	def __reload_config(self):
		with database.transaction() as t:
			t.execute("SELECT name, value FROM config WHERE plugin = 'spoof'")
			config = dict(t.fetchall())
		self.__answer_timeout = int(config['answer_timeout'])
		self.__dest_addr = config['dest_addr']
		self.__src_addr = config['src_addr']
		self.__port = int(config['port'])
		self.__interval = config['interval']

	def message_from_client(self, message, client):
		logger.error("Message from spoof plugin, but none expected: %s, on client %s", message, client)

	def name(self):
		return "Spoof"

	def get_token(self, token):
		"""
		Look up a token with the given value.
		"""
		return self.__tokens.get(token)

	def drop_token(self, token):
		"""
		Remove a token from the list of known ones.
		"""
		logger.debug("Token %s handled, removing", token)
		del self.__tokens[token]

	def __do_send(self):
		logger.debug("Sending burst of requests")
		clients = set(self.plugins().get_clients()) - self.__sent
		count = 0
		while count < 5 and clients:
			count += 1
			client = clients.pop()
			token = Token(client, self.__now)
			self.__tokens[token.value()] = token
			self.__batch.add(token.value())
			self.send(self.__prefix + struct.pack('!Q', token.value()), client)
			self.__sent.add(client)
		if clients:
			reactor.callLater(1, self.__do_send)
		else:
			logger.debug("That was the last")
			# Drop the tokens after some time if they get no answer
			# (Dropping the already handled ones doesn't matter)
			batch = self.__batch
			def cleanup():
				for tok in batch:
					try:
						del self.__tokens[tok]
					except KeyError:
						pass # Not there. But we don't care.
			reactor.callLater(self.__answer_timeout, cleanup)
			self.__batch = None
			self.__sent = None
			self.__prefix = None

	def __check(self):
		"""
		Check the DB to see if we should ask for another round of spoofed packets.
		"""
		if self.__sent:
			return # Still sending bursts
		self.__reload_config()
		with database.transaction() as t:
			t.execute("SELECT CURRENT_TIMESTAMP AT TIME ZONE 'UTC', COALESCE(MAX(batch) + INTERVAL %s < CURRENT_TIMESTAMP AT TIME ZONE 'UTC', TRUE) FROM spoof", (self.__interval,));
			(self.__now, run) = t.fetchone()
		if not run:
			logger.debug("Too early to ask for spoofed packets")
			return
		logger.info('Asking clients to send spoofed packets')
		self.__batch = set()
		self.__prefix = '4' + \
			socket.inet_pton(socket.AF_INET, socket.gethostbyname(self.__src_addr)) + \
			socket.inet_pton(socket.AF_INET, socket.gethostbyname(self.__dest_addr)) + \
			struct.pack("!H", self.__port)
		self.__sent = set()
		self.__do_send()

	def src_addr(self):
		return self.__src_addr
