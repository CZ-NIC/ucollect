from twisted.internet.task import LoopingCall
from twisted.internet import reactor
import struct
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

	def __process(self):
		if set(self.__data.keys()) != set(self.__stats.keys()):
			print("Warning: stats and data answers don't match")
		print("Information about " + str(len(self.__data)) + " clients")
		names = ('Count', 'IPv6', 'IPv4', 'In', 'Out', 'TCP', 'UDP', 'ICMP', 'LPort', 'SIn', 'SOut', 'Size')
		sums = []
		for i in range(0, 12):
			value = sum(map(lambda d: d[i], self.__data.values()))
			sums.append(value)
			percent = ''
			if i > 0 and i <= 8:
				percent = '\t' + str(100 * value / sums[0]) + '%'
			print(names[i] + ':\t\t\t\t' + str(value) + percent)
		# TODO: Do we want to do more? Like speeds, percents of traffic on v4/v6, etc?
		# It might be nice eye candy.

	def name(self):
		return 'Count'

	def message_from_client(self, message, client):
		count = len(message) / 4
		data = struct.unpack('!' + str(count) + 'L', message)
		if len(data) == 12: # The 'D'ata answer.
			self.__data[client] = data
		else:
			self.__stats[client] = data[1:] # Strip the number of interfaces, uninteresting
