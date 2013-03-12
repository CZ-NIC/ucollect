from twisted.internet.task import LoopingCall
import time
import struct
import plugin
import socket

class BucketsPlugin(plugin.Plugin):
	"""
	Counterpart of the "buckets" plugin in the client. It does
	analysis by hashing data into buckets by several statistics.
	"""
	def __init__(self, plugins):
		plugin.Plugin.__init__(self, plugins)
		self.__bucket_count = 16
		self.__hash_count = 4
		self.__criteria = ['I']
		self.__history_size = 1
		self.__config_version = 1
		self.__max_key_count = 102400
		# Just an arbitrary number
		self.__seed = 872945724987
		self.__downloader = LoopingCall(self.__init_download)
		# FIXME: Adjust the time to something reasonable after the testing.
		self.__downloader.start(5, False)

	def name(self):
		return "Buckets"

	def message_from_client(self, message, client):
		kind = message[0]
		if kind == 'C':
			# It asks for config. Send some.
			self.send('C' + self.__config(), client)
		elif kind == 'G':
			# Generation data.
			# Parse it. Something less error-prone when confused config?
			# FIXME: Part of this won't work with more than 1 criterion
			per_criterion = self.__bucket_count * self.__hash_count + 1
			count = len(self.__criteria) * per_criterion
			deserialized = struct.unpack('!QL' + str(count) + 'L', message[1:])
			(timestamp, version) = deserialized[:2]
			print("Hash buckets from " + client + " since " + time.ctime(timestamp) + " on version " + str(version))
			deserialized = deserialized[3:] # Skip one for the overflow flag
			total = sum(deserialized)
			print("Total " + str(total / self.__hash_count))
			examine = [42, 0] # All in the 0th criterion, and 42 is ID
			while deserialized:
				line = deserialized[:self.__bucket_count]
				i = 0
				maxval = 0
				maxindex = 0
				for v in line:
					if v > maxval:
						maxindex = i
						maxval = v
					i += 1
				print(line)
				deserialized = deserialized[self.__bucket_count:]
				examine.extend([1, maxindex]) # One index in this hash
			msg = struct.pack('!Q' + str(len(examine)) + 'L', timestamp, *examine)
			# Ask for the keys to examine
			self.send('K' + msg, client)
		elif kind == 'K':
			# Got keys from the plugin
			(req_id,) = struct.unpack('!L', message[1:5])
			message = message[5:]
			print("Keys for ID " + str(req_id) + " on " + client)
			while message:
				if message[0] == '\x04': # IPv4
					print(socket.inet_ntop(socket.AF_INET, message[1:5]))
				elif message[0] == '\x06': # IPv6
					print(socket.inet_ntop(socket.AF_INET6, message[1:17]))
				else:
					print("Unknown address type " + message[0])
				message = message[17:]
		else:
			print("Unkown data from Buckets plugin: " + message)

	def __config(self):
		header = struct.pack('!2Q6L' + str(len(self.__criteria)) + 'c', self.__seed, int(time.time()), self.__bucket_count, self.__hash_count, len(self.__criteria), self.__history_size , self.__config_version, self.__max_key_count, *self.__criteria)
		return header

	def __init_download(self):
		"""
		Ask the clients to provide some data.
		"""
		data = struct.pack('!Q', int(time.time()))
		self.broadcast('G' + data)
