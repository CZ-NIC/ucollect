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

from twisted.internet.task import LoopingCall
from socket import SOL_SOCKET, socketpair
from twisted.python.sendmsg import SCM_RIGHTS, send1msg, recv1msg
from twisted.internet import reactor
import twisted.internet.protocol
import twisted.protocols.basic
import logging
import traceback
import socket
from protocol import extract_string, format_string
import client
from struct import unpack, pack


logger = logging.getLogger(name='timers')

def timer(callback, time, startnow=False):
	def protected():
		try:
			callback()
		except Exception as e:
			logger.error("Exception in timer call: %s", traceback.format_exc())
	result = LoopingCall(protected)
	result.start(time, startnow)
	return result

class CoordinatorWorkerConn(twisted.protocols.basic.Int32StringReceiver):
	MAX_LENGTH = 1024 ** 3 # A gigabyte should be enough
	def __init__(self, plugins, fastpings):
		self.__plugins=plugins
		self.__fastpings = fastpings

	def connectionMade(self):
		logger.debug("Connected to master")
		return

	def connectionLost(self, reason):
		logger.fatal("Lost connection to master")
		reactor.stop()
		return

	def stringReceived(self, string):
		logger.trace("WORKER Received from MASTER: %s", repr(string))
		(msg, params) = (string[0], string[1:])
		if msg == 'l':
			# Passing client from master
			
			data, flags, ancillary = recv1msg(3, 1024)
			s = unpack("i", ancillary[0][2])[0]
			logging.debug('received socket: %s', s)
			(cid, params) = extract_string(params)
			(replay_msgs,params)=extract_string(params)
			replay_msgs=int(replay_msgs)
			clientObj=client.ClientFactory(self.__plugins, self.__fastpings, None, True, cid)
			reactor.adoptStreamConnection(s, socket.AF_INET, clientObj)
			for i in range(replay_msgs):
				(msg,params)=extract_string(params)
				clientObj.stringReceived(msg)
			logger.debug(" WORKER Got client (fd %s) from master: CID %s msgs %s", s, cid, replay_msgs)
			return
		else:
			logger.warn("Unknown message from coordinator: %s", msg)

class CoordinatorWorkerFactory(twisted.internet.protocol.Factory):
	def __init__(self, plugins, fastpings):
		self.__plugins=plugins
		self.__fastpings = fastpings
    
	def buildProtocol(self, addr):
		return CoordinatorWorkerConn(self.__plugins, self.__fastpings)

class CoordinatorMasterConn(twisted.protocols.basic.Int32StringReceiver):
	MAX_LENGTH = 1024 ** 3 # A gigabyte should be enough
	def __init__(self, addr):
		return

	def connectionMade(self):
		logger.debug("Connection to worker")
			
	def submit(self, string):
		self.sendString(string)

	def connectionLost(self, reason):
		logger.fatal("Lost connection to worker")

class CoordinatorMasterFactory(twisted.internet.protocol.Factory):
	def __init__(self):
		self.conn = None

	def buildProtocol(self, addr):
		self.conn = CoordinatorMasterConn(addr)
		return self.conn
	
	
class Worker():
	def __init__(self, pipe, sock):
		self.__pipe = pipe
		self.__sock = sock
		self.__queue = []
		self.__conn = None
		self.__listen_factory=CoordinatorMasterFactory()
		self.__sock.listen(self.__listen_factory)
		
	def submit(self, string):
		if not self.__conn:
			if self.__listen_factory.conn:
				self.__conn = self.__listen_factory.conn
				return self.__conn.submit(string)
			self.__queue.append(string)
			logger.warn("Tried writing to worker while it's not connected.")
		else:
			self.__conn.submit(string)
		
	def passClientHandle(self, cid, messages, fd):
		sent = send1msg(self.__pipe.fileno(), "\x00", 0, [(SOL_SOCKET, SCM_RIGHTS, pack("i", fd.fileno()))])
		#reduction.send_handle(self.__pipes[0], fd.fileno(), self.__ch.pid)
		#reactor.removeReader(fd)
		#reactor.removeWriter(fd)
		#self.transport.stopReading()
		#self.transport.stopWriting()
		# Replay the bufferend messages, pack them (to be sent to worker)
		buffer=""
		for message in messages:
			buffer += format_string(message)
		worker_conn = self.submit("l"+format_string(cid)+format_string(str(len(messages)))+buffer)
