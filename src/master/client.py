from twisted.internet.task import LoopingCall
import twisted.internet.protocol
import twisted.protocols.basic
from protocol import extract_string
import logging
import database

logger = logging.getLogger(name='client')

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
		with database.transaction() as t:
			t.execute("SELECT id FROM clients WHERE name = %s", (self.cid(),))
			result = t.fetchone()
			if result:
				logger.info("Client %s logged in with ID %s", self.cid(), result[0])
			else:
				logger.info("Client from address %s failed to log in", self.__addr)
				# Keep the connection open, but idle. Stops the client from reconnecting
				# too fast. It will first time out the connection, then it'll reconnect.
				return
			database.log_activity(self.cid(), "login")
		self.__logged_in = True
		self.__pinger = LoopingCall(self.__ping)
		self.__pinger.start(5, False)
		self.__plugins.register_client(self)

	def connectionLost(self, reason):
		if self.__logged_in:
			logger.info("Connection lost from %s", self.cid())
			self.__pinger.stop()
			self.__plugins.unregister_client(self)
			database.log_activity(self.cid(), "logout")

	def stringReceived(self, string):
		if not self.__logged_in:
			return
		(msg, params) = (string[0], string[1:])
		logger.trace("Received from %s: %s", self.cid(), repr(string))
		if msg == 'H':
			pass # No info on 'H'ello yet
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
		The client ID. We use the address for now, but we may
		want to use something else.
		"""
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
