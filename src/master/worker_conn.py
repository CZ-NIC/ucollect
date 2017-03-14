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
from twisted.internet.error import ReactorNotRunning
from twisted.internet import reactor
import twisted.internet.protocol
import twisted.protocols.basic
import logging
import traceback
import socket
import sys
from protocol import extract_string, format_string
import client
from struct import unpack, pack
import sys

#worker's file descriptor no on which worker'll get client's handle (for recvn1msg)
#this is ugly, but spawnProcess wants directly FD numbers...
#worker is created with this file descriptor already opened and connected to socket to master (see spawnProcess in collect-master.py)
WORKER_SOCK_FD = 3

logger = logging.getLogger(name='workerConn')

class WorkerConn(twisted.protocols.basic.Int32StringReceiver):
	"""
	Connection from worker to master.

	Now it just handles passing client from master to worker.
	More will be added in future - timers and etc.
	"""
	MAX_LENGTH = 10240 # Ten kilobytes should be enough
	def __init__(self, plugins, fastpings):
		self.__plugins=plugins
		self.__fastpings = fastpings

	def connectionMade(self):
		logger.debug("Connected to master")
		return

	def connectionLost(self, reason):
		logger.fatal("Lost connection to master")
		try:
			reactor.stop()
		except ReactorNotRunning:
			pass
		return

	def stringReceived(self, string):
		logger.trace("WORKER Received from MASTER: %s", repr(string))
		(msg, params) = (string[0], string[1:])
		if msg == 'l':
			"""
			Receive (already established) client's connection from master, start handling that client.
			"""
			#receive socket
			data, flags, ancillary = recv1msg(WORKER_SOCK_FD, 1024)
			#unpack it
			s = unpack("i", ancillary[0][2])[0]
			logging.debug('received socket: %s', s)
			(cid, params) = extract_string(params)
			(replay_msgs,params) = extract_string(params)
			replay_msgs = int(replay_msgs)
			replay=[]
			for i in range(replay_msgs):
				(msg,params) = extract_string(params)
				replay.append(msg)
			reactor.adoptStreamConnection(s, socket.AF_INET, client.ClientFactory(self.__plugins, self.__fastpings, cid, replay))
			logger.debug("Got client (fd %s) from master: CID %s msgs %s", s, cid, replay_msgs)
			return
		else:
			logger.warn("Unknown message from coordinator: %s", msg)

class WorkerConnFactory(twisted.internet.protocol.Factory):
	def __init__(self, plugins, fastpings):
		self.__plugins = plugins
		self.__fastpings = fastpings
    
	def buildProtocol(self, addr):
		return WorkerConn(self.__plugins, self.__fastpings)
