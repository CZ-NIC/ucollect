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

	def connectionMade(self):
		print("Connection made from " + str(self.__addr))
		# TODO: Register within the plugins

	def connectionLost(self, reason):
		print("Connection lost from " + str(self.__addr))
		# TODO: Unregister

	def stringReceived(self, string):
		(msg, params) = (string[0], string[1:])
		if msg == 'H':
			pass # No info on 'H'ello yet
		elif msg == 'P': # Ping. Answer pong.
			self.sendString('p' + params)
		else:
			print("Unknown message " + msg)

class ClientFactory(twisted.internet.protocol.Factory):
	"""
	Just a factory to create the clients. Stores a reference to the
	plugins and passes them to the client.
	"""
	def __init__(self, plugins):
		self.__plugins = plugins

	def buildProtocol(self, addr):
		return ClientConn(self.__plugins, addr)
