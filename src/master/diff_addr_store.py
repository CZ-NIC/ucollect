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
import database

class DiffAddrStore:
	def __init__(self, logger, plugname, table, column):
		self.__logger = logger
		self.__plugname = plugname
		# Get the max epoch for each set. Then get the maximum version for each such set & epoch
		self.__version_query = '''
			SELECT addresses.name, addresses.epoch, MAX(raw_addresses.version)
		FROM
			%TABLE% AS raw_addresses
		JOIN
			(SELECT %COLUMN% AS name, MAX(epoch) AS epoch FROM %TABLE% GROUP BY %COLUMN%) AS addresses
		ON raw_addresses.%COLUMN% = addresses.name AND raw_addresses.epoch = addresses.epoch
		GROUP BY addresses.name, addresses.epoch'''.replace("%TABLE%", table).replace("%COLUMN%", column)
		self._conf = {}
		self._addresses = {}
		self.__conf_checker = LoopingCall(self.__check_conf)
		self.__conf_checker.start(60, True)

	def __check_conf(self):
		self.__logger.trace("Checking " + self.__plugname + " configs")
		with database.transaction() as t:
			t.execute("SELECT name, value FROM config WHERE plugin = '" + self.__plugname + "'")
			config = dict(t.fetchall())
			t.execute(self.__version_query)
			addresses = {}
			for a in t.fetchall():
				(name, epoch, version) = a
				addresses[name] = (epoch, version)
		if self._conf != config:
			self.__logger.info("Config changed, broadcasting")
			self._conf = config
			self._broadcast_config()
		if self._addresses != addresses:
			for a in addresses:
				if self._addresses.get(a) != addresses[a]:
					self.__logger.debug("Broadcasting new version of %s", a)
					self._broadcast_version(a, addresses[a][0], addresses[a][1])
			self._addresses = addresses
