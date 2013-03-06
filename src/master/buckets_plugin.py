import struct
import plugin

class BucketsPlugin(plugin.Plugin):
	"""
	Counterpart of the "buckets" plugin in the client. It does
	analysis by hashing data into buckets by several statistics.
	"""
	def __init__(self, plugins):
		plugin.Plugin.__init__(self, plugins)
		self.__bucket_count = 16
		self.__hash_count = 4
		self.__criteria_count = 1
		self.__history_size = 1
		# Just an arbitrary number
		self.__seed = 872945724987

	def name(self):
		return "Buckets"

	def message_from_client(self, message, client):
		kind = message[0]
		if kind == 'C':
			# It asks for config. Send some.
			self.send('C' + self.__config(), client)
		else:
			print("Unkown data from Buckets plugin: " + message)

	def __config(self):
		header = struct.pack('!4LQ', self.__bucket_count, self.__hash_count, self.__criteria_count, self.__history_size , self.__seed)
		# TODO: Describe the criteria to gather
		return header
