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
import time

from task import Task
import database
from activity import log_activity
import logging
from twisted.internet import reactor

logger = logging.getLogger(name='sniff')

def submit_data(client, payload, hosts, batch_time):
	data = []
	for (rid, count) in hosts:
		(slen, payload) = (payload[:4], payload[4:])
		(slen,) = struct.unpack('!L', slen)
		if slen > 0:
			(ip, times, payload) = (payload[:slen], payload[slen:slen + 4 * count], payload[slen + 4 * count:])
			times = struct.unpack('!' + str(count) + 'L', times)
			times = filter(lambda t: t < 2**31 - 1, times)
		else:
			times = []
			ip = None
		recv = len(times)
		logger.trace('Ping data: ' + repr(times))
		if times:
			ma = max(times)
			mi = min(times)
			avg = sum(times) / recv
		else:
			ma = None
			mi = None
			avg = None
		data.append((batch_time, rid, ip, recv, mi, ma, avg, client))
	logger.trace('Submitting data: ' + repr(data))
	with database.transaction() as t:
		t.executemany("INSERT INTO pings (batch, client, timestamp, request, ip, received, min, max, avg) SELECT %s, clients.id, CURRENT_TIMESTAMP AT TIME ZONE 'UTC', %s, %s, %s, %s, %s, %s FROM clients WHERE name = %s", data);

class PingTask(Task):
	def __init__(self, message, hosts):
		Task.__init__(self)
		self.__message = message
		self.__hosts = hosts
		with database.transaction() as t:
			t.execute("SELECT CURRENT_TIMESTAMP AT TIME ZONE 'UTC'")
			(self.__batch_time,) = t.fetchone()

	def name(self):
		return 'Ping'

	def message(self, client):
		return self.__message

	def success(self, client, payload):
		reactor.callInThread(submit_data, client, payload, self.__hosts, self.__batch_time)
		log_activity(client, 'pings')

def encode_host(hostname, proto, count, size):
	return struct.pack('!cBHL' + str(len(hostname)) + 's', proto, count, size, len(hostname), hostname);

class Pinger:
	def __init__(self, config):
		self.__last_ping = 0
		self.__ping_interval = int(config['ping_interval'])
		self.__batchsize = int(config['ping_batchsize'])

	def code(self):
		return 'P'

	def check_schedule(self):
		now = int(time.time())
		if self.__ping_interval + self.__last_ping <= now:
			encoded = ''
			host_count = 0
			hosts = []
			with database.transaction() as t:
				t.execute("SELECT id, host, proto, amount, size FROM ping_requests WHERE active AND lastrun + interval < CURRENT_TIMESTAMP AT TIME ZONE 'UTC' ORDER BY lastrun + interval LIMIT %s", (self.__batchsize,))
				requests = t.fetchall()
				for request in requests:
					(rid, host, proto, count, size) = request
					host_count += 1
					encoded += encode_host(host, proto, count, size)
					hosts.append((rid, count))
					t.execute("UPDATE ping_requests SET lastrun = CURRENT_TIMESTAMP AT TIME ZONE 'UTC' WHERE id = %s", (rid,))
			self.__last_ping = now
			if hosts:
				return [PingTask(struct.pack('!H', host_count) + encoded, hosts)]
			else:
				logger.debug('No hosts to ping now')
				return []
		else:
			logger.debug('Not pinging yet')
			return []
