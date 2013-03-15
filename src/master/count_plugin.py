from twisted.internet.task import LoopingCall
from twisted.internet import reactor
import struct
import plugin
import time

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
		# Send a request with current timestamp
		self.broadcast(struct.pack('!Q', time.time()))
		# Wait a short time, so they can send us some data and process it after that.
		self.__data = {}
		self.__stats = {}
		reactor.callLater(1, self.__process)

	def __process(self):
		print("Information about " + str(len(self.__data)) + " clients")
		names = ("Any\t", "IPv4\t", "IPv6\t", "In\t", "Out\t", "TCP\t", "UDP\t", "ICMP\t", 'Low port')
		tcount = 0
		tsize = 0
		for i in range(0, len(names)):
			count = sum(map(lambda d: d[2 * i], self.__data.values()))
			size = sum(map(lambda d: d[2 * i + 1], self.__data.values()))
			if i == 0:
				if count == 0:
					print("No packets")
					return
				else:
					print("\t\t\t\tCount\t\t%\t\tSize\t\t%")
					tcount = count
					tsize = size
			print(names[i] + "\t\t\t" + str(count) + "\t\t" + str(100 * count / tcount) + "\t\t" + str(size) + "\t\t" + str(100 * size / tsize))
		sums = [0, 0, 0]
		print("\t\t\t\tCaptured\t\tDropped\t\tLost in driver\t\tPercent lost")
		def format(name, output):
			try:
				percent = 100 * (output[1] + output[2]) / output[0]
				print(name + '\t' + str(output[0]) + '\t\t\t' + str(output[1]) + '\t\t\t' + str(output[2]) + '\t\t\t' + str(percent) + "%")
			except ZeroDivisionError:
				print(name + "\t---------------------------------------------------------------------------")
		for stat in self.__stats:
			value = self.__stats[stat]
			i = 0
			while value:
				v = list(value[:3])
				value = value[3:]
				name = stat + '[' + str(i) + ']'
				while len(name) < 24:
					name += ' '
				i += 1
				for j in range(0, 3):
					sums[j] += v[j]
				format(name, v)
		format("Total\t\t\t", sums)

	def name(self):
		return 'Count'

	def message_from_client(self, message, client):
		count = len(message) / 4 - 2 # 2 for the timestamp
		data = struct.unpack('!Q' + str(count) + 'L', message)
		if_count = data[1]
		self.__stats[client] = data[2:2 + 3 * if_count]
		self.__data[client] = data[2 + 3 * if_count:]
