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
import socket
import struct
from protocol import extract_string

def addr_convert(address, logger):
	"""
	Convert the string IP address to binary representation.
	Just try the possibilities one by one, using the first
	one that works.
	"""
	variants = [(address, '')]
	try:
		(ip, port) = address.rsplit(':', 1)
		ip = ip.strip('[]')
		port = struct.pack('!H', int(port))
		variants.append((ip, port))
	except:
		pass
	for (a, p) in variants:
		for family in [socket.AF_INET, socket.AF_INET6]:
			try:
				return socket.inet_pton(family, a) + p
			except Exception as e:
				logger.trace("Addr %s, family %s, error %s", a, family, e)
				excp = e
	raise e

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
		self.__diff_query = '''
			SELECT %TABLE%.address, add
		FROM
			(SELECT
				address, MAX(version) AS version
			FROM
				%TABLE%
			WHERE
				%COLUMN% = %s AND epoch = %s AND version > %s AND version <= %s
			GROUP BY
				address) AS lasts
		JOIN
			%TABLE%
		ON
			%TABLE%.address = lasts.address AND %TABLE%.version = lasts.version
		WHERE
			%TABLE%.%COLUMN% = %s AND epoch = %s
		ORDER BY
			address'''.replace("%TABLE%", table).replace("%COLUMN%", column)
		self._conf = {}
		self._addresses = {}
		self.__cache = {} # Reset whenever the DB contains something new.
		self.__conf_checker = LoopingCall(self.__check_conf)
		self.__conf_checker.start(60, True)

	def __check_conf(self):
		self.__logger.trace("Checking %s configs", self.__plugname)
		with database.transaction() as t:
			t.execute("SELECT name, value FROM config WHERE plugin = '" + self.__plugname + "'")
			config = dict(t.fetchall())
			t.execute(self.__version_query)
			addresses = {}
			for (name, epoch, version) in t.fetchall():
				addresses[name] = (epoch, version)
		addresses_orig = self._addresses
		self._addresses = addresses
		if self._conf != config:
			self.__logger.info("Config changed, broadcasting")
			self._conf = config
			self.__cache = {}
			self._broadcast_config()
		if addresses_orig != addresses:
			self.__cache = {}
			for a in addresses:
				if addresses_orig.get(a) != addresses[a]:
					self.__logger.debug("Broadcasting new version of %s", a)
					self._broadcast_version(a, addresses[a][0], addresses[a][1])

	def __diff_update(self, name, full, epoch, from_version, to_version, prefix):
		key = (name, full, epoch, from_version, to_version)
		if key in self.__cache: # Someone already asked for this, just reuse the result instead of asking the DB
			return self.__cache[key]
		with database.transaction() as t:
			t.execute(self.__diff_query, (name, epoch, from_version, to_version, name, epoch))
			addresses = t.fetchall()
		params = [len(name), name, full, epoch]
		if not full:
			params.append(from_version)
		params.append(to_version)
		result = 'D' + prefix + struct.pack('!I' + str(len(name)) + 's?II' + ('' if full else 'I'), *params)
		for (address, add) in addresses:
			if not add and full:
				continue # Don't mention deleted addresses on full update
			addr = addr_convert(address, self.__logger)
			self.__logger.trace("Addr: %s/%s", repr(addr), len(addr))
			result += struct.pack('!B', len(addr) + add) + addr
		self.__cache[key] = result
		return result

	def _provide_diff(self, message, client, prefix=''):
		(full,) = struct.unpack('!?', message[:1])
		(name, message) = extract_string(message[1:])
		l = 2 if full else 3
		numbers = struct.unpack('!' + str(l) + 'I', message)
		if full:
			(epoch, to_version) = numbers
			from_version = 0
		else:
			(epoch, from_version, to_version) = numbers
		self.__logger.debug('Sending diff for %s@%s from %s to %s to client %s', name, epoch, from_version, to_version, client)
		self.send(self.__diff_update(name, full, epoch, from_version, to_version, prefix), client)
