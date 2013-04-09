import time
import logging
import struct

logger = logging.getLogger(name='buckets')

class RequestManager:
	"""
	Manager keeping track of requests sent to the clients and their IDs.
	"""
	def __init__(self):
		self.__requests = {}
		self.__id = 0

	def register(self, callback, timeout):
		"""
		Register another request. Pass a callback to be called with the received
		answer and a timeout (absolute number of seconds since the epoch), after
		which the callback will be discarded without being called if the client
		doesn't answer.

		The callback is called as `callback(data, success)`, the data is the answer
		from client and success is True in case the client provides the answer.
		If the client sends error, it is called as `callback(None, False)`.

		This method returns new ID to be used for the request.
		"""
		nid = self.__id
		self.__id += 1
		self.__id %= 2^32
		self.__requests[nid] = (timeout, callback)
		return nid

	def trim(self):
		"""
		Drop the callbacks that have timed out.
		"""
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
		"""
		A response from client with the given request ID and data came. The
		method will call the corresponding callback.
		"""
		self.__route(rid, data, True)

	def missing(self, rid):
		"""
		The data to satisfy request with the given request ID is missing on the client.
		The method will call the corresponding callback with success=False.
		"""
		self.__route(rid, None, False)

manager = RequestManager()
"""
Singleton instance of the RequestManager.
"""

class Client:
	"""
	Single connected client. It holds some state information about a client and also handles requests
	for keys, callbacks to them, etc.
	"""
	def __init__(self, name, groups, send):
		"""
		Create the client. Store the name and list of groups the client belongs to.

		The send is a callable which may be used to send message to the remote client.
		"""
		self.__name = name
		self.__groups = groups
		self.__send = send

	def groups(self):
		"""
		Return the list of groups passed to initialization.
		"""
		return self.__groups

	def name(self):
		"""
		Return the name passed to the initialization.
		"""
		return self.__name

	def get_keys(self, criterion, generation, keys, callback):
		"""
		Request keys for given buckets on the client.
		- criterion: index of the criterion in configuration to ask keys for.
		- generation: the timestamp when the generation started.
		- keys: list of keys in the encoded list (eg. length, so many numbers,
		  length, so many numbers, ...)
		- callback: Called with the (raw) response from client when it comes. See
		  the RequestManager to the format of the callback.
		"""
		# TODO: Caching of the results
		rid = manager.register(callback, time.time() + 60) # One minute as a timeout is enough
		message = struct.pack('!QLL' + str(len(keys)) + 'L', generation, rid, criterion, *keys)
		self.__send('K' + message)

	def deactivate(self):
		"""
		Notify the client already disconnected. Do not call any callbacks even if
		the answer comes (seems impossible, but with event-based application, who
		knows).
		"""
		pass
		# TODO: Cancel callbacks/make sure they are not propagated anywhere. Can the callbacks happen now at all?
