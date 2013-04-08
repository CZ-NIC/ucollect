import time
import logging
import struct

logger = logging.getLogger(name='buckets')

class RequestManager:
	def __init__(self):
		self.__requests = {}
		self.__id = 0

	def register(self, callback, timeout):
		nid = self.__id
		self.__id += 1
		self.__id %= 2^32
		self.__requests[nid] = (timeout, callback)
		return nid

	def trim(self):
		t = time.time()
		to_del = []
		for k in self.__requests:
			if self.__requests[k][0] < t:
				to_del.append(k)
		if to_del:
			logging.debug("Requests timeouted: %s", to_del)
		for k in to_del:
			del self.__requests[k]

	def __route(self, rid, data, success):
		if rid in self.__requests:
			# Call the callback
			self.__requests[rid][1](data, success)
			del self.__requests[rid]
		else:
			logging.warn("Response for unknown request %s received, ignoring", rid)

	def response(self, rid, data):
		self.__route(rid, data, True)

	def missing(self, rid):
		self.__route(rid, None, False)

manager = RequestManager()

class Client:
	"""
	Single connected client. It holds some state information about a client and also handles requests
	for keys, callbacks to them, etc.
	"""
	def __init__(self, name, groups, send):
		self.__name = name
		self.__groups = groups
		self.__send = send

	def groups(self):
		return self.__groups

	def name(self):
		return self.__name

	def get_keys(self, criterion, generation, keys, callback):
		# TODO: Caching of the results
		rid = manager.register(callback, time.time() + 60) # One minute as a timeout is enough
		message = struct.pack('!QLL' + str(len(keys)) + 'L', generation, rid, criterion, *keys)
		self.__send('K' + message)
