from twisted.internet.task import LoopingCall
import twisted.internet.protocol
import twisted.protocols.basic
import random
import hashlib
from protocol import extract_string
import logging
import database
import atsha204

logger = logging.getLogger(name='client')
sysrand = random.SystemRandom()
challenge_len = 128 # 128 bits of random should be enough for log-in to protect against replay attacks

def compute_response(version, login, challenge, password):
	"""
	Compute hash response for the challenge.
	- version: The version of hash to use.
	  * S: Software.
	    (No more versions implemented now)
	  * A: Atsha204
	- challenge: The original challenge
	- password: The shared secret

	Returns None if something failed. Make sure you check for it.
	"""
	if not challenge:
		return None
	if version == 'S':
		return hashlib.sha256(password + challenge + password).digest()
	elif version == 'A':
		full_c = ''
		for i in range(0, 16):
			full_c += '\x00'
		full_c += challenge
		return atsha204.hmac(login, password.decode('hex'), full_c)
	else:
		return None

class ClientConn(twisted.protocols.basic.Int32StringReceiver):
	"""
	Connection from one client. It handles the low-level protocol,
	sorts the messages, answers pings, times out, etc.

	It also routes messages to other parts of system.
	"""
	def __init__(self, plugins, addr):
		self.__plugins = plugins
		self.__addr = addr
		self.__pings_outstanding = 0
		self.__logged_in = False
		self.__authenticated = False
		self.__cid = None

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
		logger.info("Connection made from %s", self.cid())
		# Send challenge for login.
		self.__challenge = ''
		for i in range(0, challenge_len / 8):
			self.__challenge += chr(sysrand.getrandbits(8))
		self.sendString('C' + self.__challenge)

	def connectionLost(self, reason):
		if self.__logged_in:
			logger.info("Connection lost from %s", self.cid())
			self.__pinger.stop()
			self.__plugins.unregister_client(self)
			database.log_activity(self.cid(), "logout")

	def stringReceived(self, string):
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
				logger.debug('Client %s sent login info', self.cid())
				# Client wants to log in.
				# Extract parameters.
				(version, params) = (params[0], params[1:])
				(cid, params) = extract_string(params)
				(response, params) = extract_string(params)
				(challenge, params) = extract_string(params)
				self.__cid = cid
				if version == 'A':
					self.__cid = self.__cid.encode('hex')
				if params != '':
					login_failure('Protocol violation')
					return
				log_info = None
				# Get the password from DB
				with database.transaction() as t:
					t.execute('SELECT passwd, mechanism FROM clients WHERE name = %s', (self.__cid,))
					log_info = t.fetchone()
					if not log_info:
						login_failure('Unknown user')
						return
				if version != log_info[1]:
					login_failure("Mechanism doesn't match")
					return
				# Check his hash
				correct = compute_response(version, cid, self.__challenge, log_info[0])
				if not correct or correct != response:
					login_failure('Incorrect password')
					return
				self.__authenticated = True
				# Send our hash
				self.sendString('L' + compute_response(version, cid, challenge, log_info[0]))
			elif msg == 'H':
				if self.__authenticated:
					self.__logged_in = True
					self.__pinger = LoopingCall(self.__ping)
					self.__pinger.start(30, False)
					self.__plugins.register_client(self)
					database.log_activity(self.cid(), "login")
					logger.debug('Client %s logged in', self.cid())
				else:
					login_failure('Asked for session before loging in')
					return
			return
		elif msg == 'P': # Ping. Answer pong.
			self.sendString('p' + params)
		elif msg == 'p': # Pong. Reset the watchdog count
			self.__pings_outstanding = 0
		elif msg == 'R': # Route data to a plugin
			(plugin, data) = extract_string(params)
			self.__plugins.route_to_plugin(plugin, data, self.cid())
			# TODO: Handle the possibility the plugin doesn't exist somehow.
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
			return self.__addr.host

class ClientFactory(twisted.internet.protocol.Factory):
	"""
	Just a factory to create the clients. Stores a reference to the
	plugins and passes them to the client.
	"""
	def __init__(self, plugins):
		self.__plugins = plugins

	def buildProtocol(self, addr):
		return ClientConn(self.__plugins, addr)
