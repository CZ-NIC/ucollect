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

import struct

from task import Task

class PingTask(Task):
	def __init__(self, message):
		Task.__init__(self)
		self.__message = message

	def name(self):
		return 'Ping'

	def message(self, client):
		return self.__message

	def success(self, client, payload):
		pass

	def failure(self, client, payload):
		pass

def encode_host(hostname, proto, count, size):
	return struct.pack('!cBHL' + str(len(hostname)) + 's', proto, count, size, len(hostname), hostname);

class Pinger:
	def __init__(self, config):
		self.__ping_file = config['ping_file']

	def code(self):
		return 'P'

	def check_schedule(self):
		encoded = ''
		host_count = 0
		with open(self.__ping_file) as f:
			for l in f:
				[proto, count, size, host] = l.split()
				host_count += 1
				encoded += encode_host(host, proto, int(count), int(size))
		return [PingTask(struct.pack('!H', host_count) + encoded)]
