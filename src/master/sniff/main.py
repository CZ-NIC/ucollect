#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2014 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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

import logging
import struct

import plugin

logger = logging.getLogger(name='sniff')

class SniffPlugin(plugin.Plugin):
	"""
	Counterpart of the "sniff" plugin in the client. It sends requests
	for running external sniffer plugins on the client.
	"""
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)

	def name(self):
		return "Sniff"

	def __init_pings(self):
		self.broadcast(struct.pack('!L', 42) + 'N')

	def client_connected(self, client):
		"""
		This is here temporarily, for testing.
		"""
		self.__init_pings()

	def message_from_client(self, message, client):
		logger.info("Received message: " + message)
