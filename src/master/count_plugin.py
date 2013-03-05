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
		self.__last = {}

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
				try:
					percent = '\t' + str(100 * value / sums[0]) + '%'
				except ZeroDivisionError:
					pass
			print(names[i] + ':\t\t\t\t' + str(value) + percent)
		sums = [0, 0, 0]
		print("\t\t\t\tCaptured\t\tDropped\t\tLost in driver\t\tPercent lost")
		def format(name, output):
			try:
				percent = 100 * (output[1] + output[2]) / output[0]
				print(name + '\t' + str(output[0]) + '\t\t\t' + str(output[1]) + '\t\t\t' + str(output[2]) + '\t\t\t' + str(percent) + "%")
			except ZeroDivisionError:
				print(name + "\t---------------------------------------------------------------------------")
		new_last = {}
		for stat in self.__stats:
			value = self.__stats[stat]
			i = 0
			while value:
				v = list(value[:3])
				value = value[3:]
				name = stat + '[' + str(i) + ']'
				new_last[name] = list(v)
				last = self.__last.get(name, [0, 0, 0])
				while len(name) < 24:
					name += ' '
				i += 1
				for j in range(0, 3):
					v[j] -= last[j]
					sums[j] += v[j]
				format(name, v)
		format("Total\t\t\t", sums)
		self.__last = new_last

	def name(self):
		return 'Count'

	def message_from_client(self, message, client):
		count = len(message) / 4
		data = struct.unpack('!' + str(count) + 'L', message)
		if len(data) == 12: # The 'D'ata answer.
			self.__data[client] = data
		else:
			self.__stats[client] = data[1:] # Strip the number of interfaces, uninteresting
