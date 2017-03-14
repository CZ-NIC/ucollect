#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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
from socket import SOL_SOCKET, socketpair
from twisted.python.sendmsg import SCM_RIGHTS, send1msg, recv1msg
from twisted.internet import reactor
import twisted.internet.protocol
import twisted.protocols.basic
import logging
import traceback
import socket
import sys
from protocol import extract_string, format_string
from struct import unpack, pack

logger = logging.getLogger(name='workerConn')

class MasterConn(twisted.protocols.basic.Int32StringReceiver):
	# connection from master to worker.
	# this is just a skeleton (required by twisted) for now, but more will be added - timers and etc.
	MAX_LENGTH = 10240 # Ten kilobytes should be enough
	def __init__(self, addr, worker):
		self.__worker = worker

	def connectionMade(self):
		self.__worker.connected(self)
		logger.debug("Connection to worker")

	def connectionLost(self, reason):
		logger.fatal("Lost connection to worker")
		
	def stringReceived(self, string):
		logger.trace("MASTER Received from WORKER: %s", repr(string))

class MasterConnFactory(twisted.internet.protocol.Factory):
	def __init__(self, worker):
		self.__worker = worker

	def buildProtocol(self, addr):
		return MasterConn(addr, self.__worker)
	
class Worker():
	# represents worker, contains variables (pipes, sockets) for one worker
	# wraps ugly low-level things like socket passing
	# this might be changed as more functions will be added to master
	def __init__(self, pipe, sock):
		self.__pipe = pipe
		self.__sock = sock
		self.__queue = []
		self.__conn = None
		self.__sock.listen(MasterConnFactory(self))

	def connected(self, conn):
		"""
		Callback, called from MasterConn::connectionMade when worker connects.

		Sets to reference to established connection and eventually sends waiting messages.
		"""
		self.__conn = conn
		for m in self.__queue:
			self.__conn.sendString(m)
		self.__queue = []

	def submit(self, string):
		"""
		Send message to worker. If the worker is not (yet) connected, buffers it (to be send when the connection will be ready).
		"""
		if not self.__conn:
			self.__queue.append(string)
			logger.warn("Tried writing to worker when it's not connected.")
		else:
			self.__conn.sendString(string)

	def passClientHandle(self, cid, messages, fd):
		"""
		Pass (already established) connection with client to worker. Also client CID and buffered messages are send.
		"""
		sent = send1msg(self.__pipe.fileno(), "\x00", 0, [(SOL_SOCKET, SCM_RIGHTS, pack("i", fd.fileno()))])
		# Replay the bufferend messages, pack them (to be sent to worker)
		buffer = ""
		for message in messages:
			buffer += format_string(message)
		worker_conn = self.submit("l"+format_string(cid)+format_string(str(len(messages)))+buffer)
