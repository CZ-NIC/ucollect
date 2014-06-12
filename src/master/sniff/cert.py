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
import time

import database
from task import Task
from activity import log_activity
from protocol import extract_string
from twisted.internet import reactor
import dateutil.parser

logger = logging.getLogger(name='sniff')

def store_certs(client, payload, hosts, batch_time):
	with database.transaction() as t:
		for (rid, want_details, want_params) in hosts:
			(count,) = struct.unpack("!B", payload[0])
			payload = payload[1:]
			if count > 0:
				cipher = None
				proto = None
				if want_params:
					(cipher, payload) = extract_string(payload)
					(proto, payload) = extract_string(payload)
				t.execute("INSERT INTO certs (request, client, batch, timestamp, proto, cipher) SELECT %s, clients.id, %s, CURRENT_TIMESTAMP AT TIME ZONE 'UTC', %s, %s FROM clients WHERE name = %s RETURNING id", (rid, batch_time, proto, cipher, client))
				(cert_id,) = t.fetchone()
				for i in range(0, count):
					(cert, payload) = extract_string(payload)
					if want_details:
						(name, payload) = extract_string(payload)
						(expiry, payload) = extract_string(payload)
					else:
						name = None
						expiry = None
					t.execute("INSERT INTO cert_chains (cert, ord, is_full, value, name, expiry) VALUES(%s, %s, %s, %s, %s, %s)", (cert_id, i, len(cert) > 40, cert, name, dateutil.parser.parse(expiry).isoformat() if expiry else None))

class CertTask(Task):
	def __init__(self, message, hosts):
		Task.__init__(self)
		self.__message = message
		self.__hosts = hosts
		with database.transaction() as t:
			t.execute("SELECT CURRENT_TIMESTAMP AT TIME ZONE 'UTC'")
			(self.__batch_time,) = t.fetchone()

	def name(self):
		return 'Cert'

	def message(self, client):
		return self.__message

	def success(self, client, payload):
		reactor.callInThread(store_certs, client, payload, self.__hosts, self.__batch_time)
		log_activity(client, 'certs')

def encode_host(host, port, starttls, want_cert, want_chain, want_details, want_params):
	# FIXME: Share the magic numbers with the C code somehow?
	flags = starttls | (want_cert << 3) | (want_chain << 4) | (want_details << 5) | (want_params << 6)
	return struct.pack('!BHL' + str(len(host)) + 's', flags, port, len(host), host)

class Cert:
	def __init__(self, config):
		self.__last_task = 0
		self.__task_interval = int(config['cert_interval'])

	def code(self):
		return 'C'

	def check_schedule(self):
		now = int(time.time())
		if self.__task_interval + self.__last_task <= now:
			encoded = ''
			host_count = 0
			hosts = []
			with database.transaction() as t:
				t.execute('SELECT id, host, port, starttls, want_cert, want_chain, want_details, want_params FROM cert_requests WHERE active')
				requests = t.fetchall()
			for request in requests:
				(rid, host, port, starttls, want_cert, want_chain, want_details, want_params) = request
				host_count += 1
				encoded += encode_host(host, port, starttls, want_cert, want_chain, want_details, want_params)
				hosts.append((rid, want_details, want_params))
			self.__last_task = now
			return [CertTask(struct.pack('!H', host_count) + encoded, hosts)]
		else:
			logger.debug('Not asking for certs yet')
			return []
