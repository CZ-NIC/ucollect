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
from twisted.python.sendmsg import getsockfam
from twisted.internet import reactor
import twisted.internet.protocol
import twisted.protocols.basic
import logging
import traceback
import socket
from protocol import extract_string, format_string
from multiprocessing import reduction
import client

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
	def __init__(self, parent_pipe, plugins, fastpings):
		self.__parent_pipe = parent_pipe
		self.__plugins=plugins
		self.__fastpings = fastpings

	def connectionMade(self):
		return

	def connectionLost(self, reason):
		return

	def stringReceived(self, string):
		logger.trace("WORKER Received from MSTER: %s", repr(string))
		(msg, params) = (string[0], string[1:])
		if msg == 'l':
			# Passing client from master
			s = socket.fromfd(reduction.recv_handle(self.__parent_pipe), socket.AF_UNIX, socket.SOCK_STREAM)
			logging.debug('received socket: %s', s)
			(cid, params) = extract_string(params)
			(replay_msgs,params)=extract_string(params)
			replay_msgs=int(replay_msgs)
			clientObj=client.ClientFactory(self.__plugins, self.__fastpings, None, True, cid)
			reactor.adoptStreamConnection(s.fileno(), socket.AF_INET, clientObj)
			for i in range(replay_msgs):
				(msg,params)=extract_string(params)
				clientObj.stringReceived(msg)
			logger.debug(" WORKER Got client (fd %s) from master: CID %s msgs %s", s.fileno(), cid, replay_msgs)
			return
		else:
			logger.warn("Unknown message from coordinator: %s", msg)

class CoordinatorWorkerFactory(twisted.internet.protocol.Factory):
	def __init__(self, parent_pipe, plugins, fastpings):
		self.__parent_pipe=parent_pipe
		self.__plugins=plugins
		self.__fastpings = fastpings
    
	def buildProtocol(self, addr):
		return CoordinatorWorkerConn(self.__parent_pipe, self.__plugins, self.__fastpings)

class CoordinatorMasterConn(twisted.protocols.basic.Int32StringReceiver):
	MAX_LENGTH = 1024 ** 3 # A gigabyte should be enough
	def __init__(self, addr, string):
		self.__string=string

	def connectionMade(self):
		logger.trace("Connected to worker")
		self.sendString(self.__string)

	def connectionLost(self, reason):
		logger.trace("Lost connection to worker")

class CoordinatorMasterFactory(twisted.internet.protocol.Factory):
	def __init__(self, string):
		self.__string = string

	def buildProtocol(self, addr):
		return CoordinatorMasterConn(addr, self.__string)
	
