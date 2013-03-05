from twisted.internet.task import LoopingCall
from twisted.internet import reactor
import plugin

class CountPlugin(plugin.Plugin):
	"""
	The plugin providing basic statisticts, like speed, number of
	dropped packets, etc.
	"""
	def __init__(self, plugins):
		plugin.Plugin.__init__(self, plugins)
		self.__downloader = LoopingCall(self.__init_download)
		self.__downloader.start(5, False)
		self.__data = {}
		self.__stats = {}

	def __init_download(self):
		"""
		Ask all the clients to send their statistics.
		"""
		self.broadcast('D')
		self.broadcast('S')
		# Wait a short time, so they can send us some data and process it after that.
		self.__data = {}
		self.__stats = {}
		reactor.callLater(1, self.__process)
		print("Download")

	def __process(self):
		print("Process")

	def name(self):
		return 'Count'
