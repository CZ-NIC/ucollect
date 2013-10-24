#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2013 CZ.NIC
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

from protocol import format_string
import logging

logger = logging.getLogger(name='plugin')

class Plugin:
	"""
	Base class of a plugin. Use this when writing new plugins. Provides
	several methods to communicate with the clients.

	Provide at least these methods:
	- name(): String ID of the plugin. It must match the name in the client
	    counterpart.
	- message_from_client(message): Called when the client sends some data,
	    usually as a response to some request.
	"""
	def __init__(self, plugins):
		"""
		Initialize. It needs the plugin storage that is to be used
		there. Registers there.
		"""
		self.__plugins = plugins
		plugins.register_plugin(self.name(), self)

	def unregister(self):
		"""
		Unregister from the plugin storage. Call at most once, it
		makes the plugin unusable afterwards.
		"""
		self.__plugins.unregister_plugin(self.name(), self)

	def client_connected(self, client):
		"""
		Called with each newly connected client. A client class
		is passed. It can be used to store the ID (client.cid())
		or directly communicate with it. Please, don't store
		the client itself.
		"""
		pass

	def client_disconnected(self, client):
		"""
		Counterpart of client_connected. It is called after the
		client has already been made unreachable, so there's no
		point in trying to talk to it.
		"""
		pass

	def broadcast(self, message):
		"""
		Broadcast a message from this plugin to all the connected
		clients.
		"""
		logger.trace('Broadcasting message to all clients: %s', repr(message))
		self.__plugins.broadcast(self.__routed_message(message))

	def send(self, message, to):
		"""
		Send a message from this plugin to the client given by name.
		"""
		logger.trace('Sending message to %s: %s', to, repr(message))
		self.__plugins.send(self.__routed_message(message), to)

	def __routed_message(self, message):
		return 'R' + format_string(self.name()) + message

class Plugins:
	"""
	Singleton holding all the active plugins and clients. It
	connects them together.
	"""
	def __init__(self):
		self.__plugins = {}
		self.__clients = {}

	def register_plugin(self, name, plugin):
		"""
		Add a plugin to be used.
		"""
		logger.info('New plugin %s', name)
		self.__plugins[name] = plugin

	def unregister_plugin(self, name):
		"""
		Remove a plugin.
		"""
		logger.info('Remove plugin %s', name)
		del self.__plugins[name]

	def register_client(self, client):
		"""
		When a client connects.
		"""
		if client.cid() in self.__clients:
			logger.warn("Connecting second copy of %s, dropping the first", client.cid())
			# Currently connected. Close the connection and unregister.
			# Pass the client in the dict, not the new one.
			old = self.__clients[client.cid()]
			self.unregister_client(old)
			old.transport.abortConnection()
		self.__clients[client.cid()] = client
		for p in self.__plugins.values():
			p.client_connected(client)

	def unregister_client(self, client):
		"""
		When a client disconnects.
		"""
		if not client.cid() in self.__clients and client == self.__clients[client.cid()]:
			# If the client is not there, or if the client is some newer version, don't remove it.
			for p in self.__plugins.values():
				p.client_disconnected(client)
			del self.__clients[client.cid()]

	def broadcast(self, message):
		"""
		Send a message to all the connected clients.
		"""
		for c in self.__clients.values():
			c.sendString(message)

	def send(self, message, to):
		"""
		Send a message to the named client.
		"""
		# TODO: Client of that name might not exist
		self.__clients[to].sendString(message)

	def route_to_plugin(self, name, message, client):
		"""
		Forward a message to plugin of given name. Pass the name
		of client too.
		"""
		# TODO: The plugin of that name might not exist (#2705)
		self.__plugins[name].message_from_client(message, client)
