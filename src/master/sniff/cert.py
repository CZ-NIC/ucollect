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

import database
from task import Task
from activity import log_activity

logger = logging.getLogger(name='sniff')

class CertTask(Task):
	def __init__(self, message):
		Task.__init__(self)
		self.__message = message
		with database.transaction() as t:
			t.execute("SELECT CURRENT_TIMESTAMP AT TIME ZONE 'UTC'")
			(self.__batch_time,) = t.fetchone()

	def name(self):
		return 'Cert'

	def message(self, client):
		return self.__message

	def success(self, client, payload):
		print(repr(payload))
		log_activity(client, 'certs')

def encode_host(host, port, starttls, want_cert, want_chain, want_details, want_params):
	# FIXME: Share the magic numbers with the C code somehow?
	flags = starttls | (want_cert << 3) | (want_chain << 4) | (want_details << 5) | (want_params << 6)
	return struct.pack('!BHL' + str(len(host)) + 's', flags, port, len(host), host)

class Cert:
	def __init__(self, config):
		pass

	def code(self):
		return 'C'

	def check_schedule(self):
		logger.debug("Starting cert scan")
		encoded = ''
		host_count = 0
		with database.transaction() as t:
			t.execute('SELECT id, host, port, starttls, want_cert, want_chain, want_details, want_params FROM cert_requests WHERE active')
			requests = t.fetchall()
		for request in requests:
			(rid, host, port, starttls, want_cert, want_chain, want_details, want_params) = request
			host_count += 1
			encoded += encode_host(host, port, starttls, want_cert, want_chain, want_details, want_params)
		return [CertTask(struct.pack('!H', host_count) + encoded)]
