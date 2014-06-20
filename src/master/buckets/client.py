#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2013 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

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
		self.__id %= 2**32
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
			logger.debug("Requests timeouted: %s", to_del)
		for k in to_del:
			del self.__requests[k]

	def __route(self, rid, data, success):
		if rid in self.__requests:
			# Call the callback
			self.__requests[rid][1](data, success)
			del self.__requests[rid]
		else:
			logger.warn("Response for unknown request %s received, ignoring", rid)

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

		The client starts in inactive state, needs to be activated first to work.
		"""
		self.__name = name
		self.__groups = groups
		self.__send = send
		self.__active = False
		self.__cache = {}

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
		if not self.__active:
			# We can't ask the client if not active yet, and it doesn't have the
			# data anyway.
			callback(None, False)
			return
		# Any of the levels in the cache dicts may be missing. Asking for exists in each
		# is too long, if there's one missing, it'll raise a key error.
		knames = str(keys)
		try:
			cached = self.__cache[generation][criterion][knames]
		except KeyError:
			logger.trace("Not in cache %s/%s/%s", generation, criterion, knames)
			# Make sure the value is there, waiting with the current callback
			if not generation in self.__cache:
				# if there are too many generations already, erase the oldest one.
				while len(self.__cache) > 3:
					logger.trace("Dropping generation from cache")
					del self.__cache[min(self.__cache.keys())]
				self.__cache[generation] = {}
			ccache = self.__cache[generation].setdefault(criterion, {})
			ccache[knames] = (False, [callback])
			# This will be done once the data comes
			def mycallback(data, success):
				if not self.__active:
					logger.warn("Data (%s/%s/%s) for inactive client %s received", generation, criterion, knames, self.__name)
					return
				logger.trace("Executing callbacks for %s/%s/%s", generation, criterion, knames)
				callbacks = ccache[knames][1]
				ccache[knames] = (True, (data, success))
				for c in callbacks:
					c(data, success)
			# And send the request
			rid = manager.register(mycallback, time.time() + 60) # One minute as a timeout is enough
			message = struct.pack('!QLL' + str(len(keys)) + 'L', 0, rid, criterion, *keys)
			self.__send('K' + message)
		else:
			logger.trace("Found in cache %s/%s/%s", generation, criterion, knames)
			# We get the cached data. Call the callback (outside of the try block), or
			# add the callback to waiting list.
			(received, data) = cached
			if received:
				logger.trace("Calling from cache")
				(reply, success) = data
				callback(reply, success)
			else:
				data.append(callback)

	def deactivate(self):
		"""
		Notify the client already disconnected. Do not call any callbacks even if
		the answer comes (seems impossible, but with event-based application, who
		knows).
		"""
		self.__active = False

	def activate(self):
		"""
		Activate the client. Allows asking it for data.
		"""
		self.__active = True
