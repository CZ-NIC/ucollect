#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2013-2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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
import struct
from protocol import extract_string, format_string
import logging
import activity
import auth
import time
import plugin_versions
import database
import timers

logger = logging.getLogger(name='client')
sysrand = random.SystemRandom()
challenge_len = 128 # 128 bits of random should be enough for log-in to protect against replay attacks

with database.transaction() as t:
	# As we just started, there's no plugin active anywhere. Flush whatever is left in the table.
	t.execute("DELETE FROM active_plugins")

class ClientConn(twisted.protocols.basic.Int32StringReceiver):
	"""
	Connection from one client. It handles the low-level protocol,
	sorts the messages, answers pings, times out, etc.

	It also routes messages to other parts of system.
	"""
	def __init__(self, plugins, addr, fastpings):
		self.__plugins = plugins
		self.__addr = addr
		self.__pings_outstanding = 0
		self.__logged_in = False
		self.__authenticated = False
		self.__cid = None
		self.__auth_buffer = []
		self.__wait_auth = False
		self.__fastpings = fastpings
		self.__proto_version = 0
		self.__available_plugins = {
			'Badconf': 1,
			'Buckets': 1,
			'Count': 1,
			'Sniff': 1
		}
		self.__plugin_versions = {}
		self.MAX_LENGTH = 1024 * 1024 * 1024 # A gigabyte should be enough
		self.last_pong = time.time()
		self.session_id = None

	def has_plugin(self, plugin_name):
		return plugin_name in self.__available_plugins

	def plugin_version(self, plugin_name):
		return self.__available_plugins.get(plugin_name)

	def __ping(self):
		"""
		Send a ping every now and then, to see the client is
		still alive. If it didn't answer many times, drop the
		connection.
		"""
		if self.__pings_outstanding >= 3:
			self.transport.abortConnection()
		self.__pings_outstanding += 1
		self.sendString('P')

	def connectionMade(self):
		# Send challenge for login.
		self.__challenge = ''
		for i in range(0, challenge_len / 8):
			self.__challenge += chr(sysrand.getrandbits(8))
		self.sendString('C' + self.__challenge)
		self.__connected = True
		reactor.callLater(60, self.__check_logged)

	def connectionLost(self, reason):
		if not self.__connected:
			return
		self.__connected = False
		if self.__logged_in:
			logger.info("Connection lost from %s", self.cid())
			self.__pinger.stop()
			self.__plugins.unregister_client(self)
			def log_plugins(transaction):
				logger.debug("Dropping plugin list of %s", self.cid())
				transaction.execute('DELETE FROM active_plugins WHERE client IN (SELECT id FROM clients WHERE name = %s)', (self.cid(),))
				return True
			activity.push(log_plugins)
			activity.log_activity(self.cid(), "logout")
			self.transport.abortConnection()

	def __check_logged(self):
		if self.__connected and not self.__logged_in:
			logger.warn("Client %s didn't log in 60 seconds, dropping", self.cid())
			self.transport.abortConnection()
			self.__connected = False

	def stringReceived(self, string):
		if self.__wait_auth:
			self.__auth_buffer.append(string)
			return
		(msg, params) = (string[0], string[1:])
		logger.trace("Received from %s: %s", self.cid(), repr(string))
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
						self.__authenticated = True
						# Replay the bufferend messages
						for message in self.__auth_buffer:
							self.stringReceived(message)
					else:
						login_failure('Incorrect password')
					self.__auth_buffer = None
				# Ask the authenticator
				if self.__challenge:
					auth.auth(auth_finished, self.__cid, self.__challenge.encode('hex'), response.encode('hex'))
					self.__wait_auth = True
			elif msg == 'H':
				if self.__authenticated:
					if len(params) >= 1:
						(self.__proto_version,) = struct.unpack("!B", params[0])
					if self.__proto_version >= 1:
						self.__available_plugins = {}
					if self.__plugins.register_client(self):
						if self.__proto_version == 0:
							# Activate all the clients in the old version.
							# The new protocol handles activation on plugin-by-plugin basis
							for p in self.__plugins.get_plugins():
								self.__plugins.activate_client(p, self)
						else:
							# Please tell me when there're changes to the allowed plugins
							plugin_versions.add_client(self)
						self.__logged_in = True
						self.__pinger = timers.timer(self.__ping, 45 if self.cid() in self.__fastpings else 120, False)
						activity.log_activity(self.cid(), "login")
						logger.info('Client %s logged in', self.cid())
					else:
						return
				else:
					login_failure('Asked for session before loging in')
					return
			elif msg == 'S':
				if len(params) != 4:
					logger.warn("Wrong session ID length on client %s: %s", self.cid(), len(params))
					return
				(self.session_id,) = struct.unpack("!I", params)
			return
		elif msg == 'P': # Ping. Answer pong.
			self.sendString('p' + params)
		elif msg == 'p': # Pong. Reset the watchdog count
			self.__pings_outstanding = 0
			self.last_pong = time.time()
		elif msg == 'R': # Route data to a plugin
			(plugin, data) = extract_string(params)
			self.__plugins.route_to_plugin(plugin, data, self.cid())
			# TODO: Handle the possibility the plugin doesn't exist somehow (#2705)
		elif msg == 'V': # New list of versions of the client
			if self.__proto_version == 0:
				self.__available_plugins = {}
				while len(params) > 0:
					(name, params) = extract_string(params)
					(version,) = struct.unpack('!H', params[:2])
					self.__available_plugins[name] = version
					params = params[2:]
			else:
				self.__handle_versions(params)
		else:
			logger.warn("Unknown message from client %s: %s", self.cid(), msg)

	def __handle_versions(self, params):
		"""
		Parse the client's message about the plugins it knows.
		Activate and deactivate plugins accordingly.
		"""
		versions = {}
		while len(params) > 0:
			(name, params) = extract_string(params)
			(version, md5_hash) = struct.unpack('!H16s', params[:18])
			(lib, params) = extract_string(params[18:])
			p_activity = params[0]
			params = params[1:]
			versions[name] = {
				'name': name,
				'version': version,
				'hash': md5_hash,
				'activity': (p_activity == 'A'),
				'lib': lib
			}
		self.__check_versions(versions)
		now = database.now()
		def log_versions(transaction):
			logger.debug("Replacing plugin list of %s", self.cid())
			transaction.execute('DELETE FROM active_plugins WHERE client IN (SELECT id FROM clients WHERE name = %s)', (self.cid(),))
			transaction.executemany("INSERT INTO active_plugins (client, name, updated, version, hash, libname, active) SELECT clients.id, %s, %s, %s, %s, %s, %s FROM clients WHERE clients.name = %s", map(lambda plug: (plug['name'], now, plug['version'], plug['hash'].encode('hex'), plug['lib'], plug['activity'], self.cid()), versions.values()))
			return True
		activity.push(log_versions)

	def __check_versions(self, versions):
		"""
		Check the plugin versions provided in the parameter and activate
		or deactivate them as needed. Insert or remove their info from
		data structures and activate/deactivate them in the plugin router.
		"""
		logger.debug("Checking versions on client %s, %s", self.cid(), self)
		required = {}
		change = set()
		available = {}
		for plug_name in versions:
			required[plug_name] = plugin_versions.check_version(plug_name, versions[plug_name]['version'], versions[plug_name]['hash'].encode('hex'))
			if required[plug_name] != versions[plug_name]['activity']:
				change.add(plug_name)
			if required[plug_name]:
				available[plug_name] = versions[plug_name]['version']
		now_active = set(filter(lambda p: required[p], required.keys()))
		prev_active = set(filter(lambda p: self.__plugin_versions[p]['activity'], self.__plugin_versions.keys()))
		for p in prev_active - now_active:
			self.__plugins.deactivate_client(p, self)
		activate = now_active - prev_active
		for p in prev_active & now_active:
			if versions[p]['version'] != self.__plugin_versions[p]['version']:
				self.__plugins.deactivate_client(p, self)
				activate.add(p)
		if change:
			message = 'A' + struct.pack('!L', len(change))
			for c in change:
				message += format_string(c) + struct.pack('!16sc', versions[c]['hash'], 'A' if required[c] else 'I')
				versions[c]['activity'] = required[c]
			self.sendString(message)
		self.__plugin_versions = versions
		self.__available_plugins = available
		for p in activate:
			self.__plugins.activate_client(p, self)

	def cid(self):
		"""
		The client ID. We use the address until the real client ID is provided by the client.
		for now, but we may want to use something else.
		"""
		if self.__cid:
			return self.__cid
		else:
			return self.__addr.name

	def recheck_versions(self):
		"""
		Run the check for versions again. The check might come out
		differently, the configuration in the DB might have changed.
		"""
		if self.__logged_in and self.__connected:
			self.__check_versions(self.__plugin_versions)

class ClientFactory(twisted.internet.protocol.Factory):
	"""
	Just a factory to create the clients. Stores a reference to the
	plugins and passes them to the client.
	"""
	def __init__(self, plugins, fastpings):
		self.__plugins = plugins
		self.__fastpings = fastpings

	def buildProtocol(self, addr):
		return ClientConn(self.__plugins, addr, self.__fastpings)
