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

from twisted.internet.task import LoopingCall
import plugin
import logging

logger = logging.getLogger(name='FWUp')

class FWUpPlugin(plugin.Plugin):
	"""
	Plugin for remotely updating firewall IP sets.
	"""
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__conf_checker = LoopingCall(self.__check_conf)
		self.__conf_checker.start(60, True)

	def __check_conf(self):
		logger.trace("Checking FWUp configs")
		# TODO

	def message_from_client(self, message, client):
		pass

	def name(self):
		return 'FWUp'
