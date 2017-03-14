#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2013-2017 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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
import twisted.protocols.basic
import random
from protocol import extract_string, format_string
import logging
import auth
import database

logger = logging.getLogger(name='client_master')
sysrand = random.SystemRandom()
challenge_len = 128 # 128 bits of random should be enough for log-in to protect against replay attacks

with database.transaction() as t:
	# As we just started, there's no plugin active anywhere.
	# Mark anything active as no longer active in the history and
	# flush the active ones.
	t.execute("INSERT INTO plugin_history (client, name, timestamp, active) SELECT client, name, CURRENT_TIMESTAMP AT TIME ZONE 'UTC', false FROM active_plugins")
	t.execute("DELETE FROM active_plugins")

class ClientMasterConn(twisted.protocols.basic.Int32StringReceiver):
	MAX_LENGTH = 10240 # Ten kilobytes should be enough
	"""
	Connection from one client. It handles the low-level protocol.
	
	This is just small subset of client communication (that is interesting for master) - only authentication.
	
	After authentication, master passes client (passes its socket) to worker and doesn't communicate with that client anymore.
	The rest could be found in ClientConn in client.py
	"""
	def __init__(self, addr, workers=None):
		self.__workers = workers
		self.__addr = addr
		self.__logged_in = False
		self.__authenticated = False
		self.__cid = None
		self.__auth_buffer = []
		self.__wait_auth = False
		self.session_id = None

	def connectionMade(self):
		# Send challenge for login.
		self.__challenge = ''
		for i in range(0, challenge_len / 8):
			self.__challenge += chr(sysrand.getrandbits(8))
		self.sendString('C' + self.__challenge)
		self.__connected = True
		reactor.callLater(60, self.__check_logged)

	def connectionLost(self, reason):
		self.__connected = False

	def __check_logged(self):
		if self.__connected and not self.__logged_in:
			logger.warn("Client %s didn't log in 60 seconds, dropping", self.cid())
			self.transport.abortConnection()
			self.__connected = False

	def stringReceived(self, string):
		logger.trace("Received from %s: %s", self.cid(), repr(string))
		if self.__wait_auth:
			self.__auth_buffer.append(string)
			return
		(msg, params) = (string[0], string[1:])
		if not self.__logged_in:
			def login_failure(msg):
				logger.warn('Login failure from %s: %s', self.cid(), msg)
				self.sendString('F')
				self.__challenge = None # Prevent more attempts
				# Keep the connection open, but idle. Prevents very fast
				# reconnects.
			if msg == 'L':
				# Client wants to log in.
				# Extract parameters.
				(version, params) = (params[0], params[1:])
				(cid, params) = extract_string(params)
				(response, params) = extract_string(params)
				self.__cid = cid
				if version == 'O':
					self.__cid = self.__cid.encode('hex')
				logger.debug('Client %s sent login info', self.cid())
				if params != '':
					login_failure('Protocol violation')
					return
				log_info = None
				if version != 'O':
					login_failure('Login scheme not implemented')
					return
				# A callback once we receive decision if the client is allowed
				def auth_finished(allowed):
					self.__wait_auth = False
					if allowed:
						#hash client ID to number
						cid_hash=hash(self.__cid)
						#select worker (based on CID hash)
						worker=cid_hash % len(self.__workers)
						logger.info('MASTER Passing client %s (FD %s) to worker %s', self.__cid, self.transport.getHandle().fileno(), worker)
						self.__workers[worker].passClientHandle(self.__cid, self.__auth_buffer, self.transport.getHandle())
						self.__connected = False
						self.transport.abortConnection() #TODO: make sure that this structure is really destroyed (file descriptor is closed after abortConnection)
					else:
						login_failure('Incorrect password')
					self.__auth_buffer = None
				# Ask the authenticator
				if self.__challenge:
					auth.auth(auth_finished, self.__cid, self.__challenge.encode('hex'), response.encode('hex'))
					self.__wait_auth = True
			elif msg == 'S':
				self.__auth_buffer.append(string)
			return
		else:
			logger.warn("Unknown message from client %s: %s", self.cid(), msg)

	def cid(self):
		"""
		The client ID. We use the address until the real client ID is provided by the client.
		for now, but we may want to use something else.
		"""
		if self.__cid:
			return self.__cid
		else:
			return self.__addr


class ClientMasterFactory(twisted.internet.protocol.Factory):
	"""
	Just a factory to create the clients. Stores a reference to the
	plugins and passes them to the client.
	"""
	def __init__(self, workers):
		self.__workers = workers

	def buildProtocol(self, addr):
		return ClientMasterConn(addr, self.__workers)
