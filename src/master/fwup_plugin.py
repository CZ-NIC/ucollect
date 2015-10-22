#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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

import plugin
import logging
import database
import diff_addr_store
import struct
from protocol import extract_string

logger = logging.getLogger(name='FWUp')

class FWUpPlugin(plugin.Plugin, diff_addr_store.DiffAddrStore):
	"""
	Plugin for remotely updating firewall IP sets.
	"""
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__sets = {}
		diff_addr_store.DiffAddrStore.__init__(self, logger, "fwup", "fwup_addresses", "set")

	def __build_config(self):
		def convert(name):
			return struct.pack('!I' + str(len(name)) + 'scI', len(name), name, self.__sets[name][0], self.__sets[name][1])
		return ''.join(['C', struct.pack('!II', int(self._conf.get('version', 0)), len(self.__sets))] + map(convert, self.__sets.keys()))

	def _broadcast_config(self):
		# Read the rest of the config
		with database.transaction() as t:
			t.execute("SELECT name, type, maxsize FROM fwup_sets")
			self.__sets = dict(map(lambda (name, tp, maxsize): (name, (tp, maxsize)), t.fetchall()))
		self.__config_message = self.__build_config()
		self.broadcast(self.__config_message)

	def __build_version_info(self, name, epoch, version):
		return 'V' + struct.pack('!II' + str(len(name)) + 'sII', int(self._conf.get('version', 0)), len(name), name, epoch, version)

	def _broadcast_version(self, name, epoch, version):
		self.broadcast(self.__build_version_info(name, epoch, version))

	def message_from_client(self, message, client):
		if message[0] == 'C':
			logger.debug('Sending config to %s', client)
			self.send(self.__config_message, client)
		elif message[0] == 'A':
			(name, rest) = extract_string(message[1:])
			if rest:
				logger.warn("Extra info after version query of %s from %s: %s", name, client, repr(rest))
			version = self._addresses.get(name, (0, 0))
			self.send(self.__build_version_info(name, version[0], version[1]), client)
		else:
			logger.warn('Unknown message opcode %s', message[0])

	def name(self):
		return 'FWUp'
