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

from twisted.internet import reactor
from twisted.protocols.basic import LineReceiver
from twisted.internet.protocol import ClientFactory
import logging

logger = logging.getLogger(name='auth')

receiver = None
connecting = False

class AuthReceiver(LineReceiver):
	def __init__(self, queue):
		self.__queue = queue
		self.__pending = []
		self.__received = 0
		global receiver
		receiver = self

	def connectionMade(self):
		logger.info("Connected to authenticator")
		global connecting
		connecting = False
		self.delimiter = "\n"
		self.__sendAll()

	def submit(self, callback, line):
		self.__queue.append((line, callback))
		self.__sendAll()

	def connectionLost(self, reason):
		logger.info("Lost connection to authenticator")
		global receiver
		receiver = None
		for cback in self.__pending:
			cback(False)
		for line, cback in self.__queue:
			cback(False)

	def __sendAll(self):
		if self.__queue:
			for line, cback in self.__queue:
				self.sendLine(line)
				self.__pending.append(cback)
			self.__queue = []
			lastReceived = self.__received
			def checkReceived():
				if lastReceived == self.__received:
					self.transport.abortConnection()
			reactor.callLater(60, checkReceived)

	def lineReceived(self, line):
		self.__received += 1
		cback = self.__pending.pop(0)
		if line == 'YES':
			cback(True)
		else:
			cback(False)

class Factory(ClientFactory):
	def __noconn(self):
		global connecting
		connecting = False

	def __init__(self):
		self.__noconn()
		self.__queue = []

	def clientConnectionFailed(self, connector, reason):
		self.__noconn()

	def clientConnectionLost(self, connector, reason):
		self.__noconn()

	def buildProtocol(self, addr):
		q = self.__queue
		self.__queue = []
		return AuthReceiver(q)

	def submit(self, cback, cid, challenge, response):
		global connecting
		global receiver
		line = 'HALF ' + cid + ' ' + challenge + ' ' + response
		if receiver:
			receiver.submit(cback, line)
		else:
			if not connecting:
				connecting = True
				reactor.connectTCP('localhost', 8888, self)
			self.__queue.append((line, cback))

factory = Factory()

def auth(callback, cid, challenge, response):
	factory.submit(callback, cid, challenge, response)
