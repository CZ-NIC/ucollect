from twisted.internet.task import LoopingCall
import twisted.internet.protocol
import twisted.protocols.basic

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

	def ping(self):
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
		print("Connection made from " + str(self.__addr))
		self.__pinger = LoopingCall(self.ping)
		self.__pinger.start(5, False)
		self.__plugins.register_client(self)

	def connectionLost(self, reason):
		print("Connection lost from " + str(self.__addr))
		self.__pinger.stop()
		self.__plugins.unregister_client(self)

	def stringReceived(self, string):
		(msg, params) = (string[0], string[1:])
		if msg == 'H':
			pass # No info on 'H'ello yet
		elif msg == 'P': # Ping. Answer pong.
			self.sendString('p' + params)
		elif msg == 'p': # Pong. Reset the watchdog count
			self.__pings_outstanding = 0
		else:
			print("Unknown message " + msg)

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
