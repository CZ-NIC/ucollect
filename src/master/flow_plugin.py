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

from twisted.internet import reactor
import plugin
import struct
import logging
import activity

logger = logging.getLogger(name='flow')

def store_flows(client, message):
	pass

class FlowPlugin(plugin.Plugin):
	"""
	Plugin for storing netflow information.
	"""
	def __init__(self, plugins, config):
		self.__conf_id = int(config['version'])
		self.__max_flows = int(config['max_flows'])
		self.__timeout = int(config['timeout']) * 1000

	def message_from_client(self, message, client):
		if message[0] == 'C':
			logger.debug('Sending config to %s', client.cid())
			self.send(struct.pack('!III', self.__conf_id, self.__max_flows, self.__timeout), client.cid())
		elif message[0] == 'D':
			logger.debug('Flows from %s', client.cid())
			activity.log_activity(client, 'flow')
			reactor.callInThread(store_flows, client, message[1:])

	def name(self):
		return 'Flow'
