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

from task import Task
import logging
import database
from activity import log_activity
from twisted.internet import reactor

logger = logging.getLogger(name='sniff')

def decode(code):
	if code == 'N':
		return True
	elif code == 'D':
		return False
	else:
		return None

def submit_data(client, payload, batch_time):
	with database.transaction() as t:
		t.execute("INSERT INTO nats (batch, client, nat_v4, nat_v6) SELECT %s, clients.id, %s, %s FROM clients WHERE name = %s", (batch_time, decode(payload[0]), decode(payload[1]), client))

class NatTask(Task):
	def __init__(self):
		Task.__init__(self)
		with database.transaction() as t:
			t.execute("SELECT CURRENT_TIMESTAMP AT TIME ZONE 'UTC'")
			(self.__batch_time,) = t.fetchone()

	def name(self):
		return 'Nat'

	def message(self, client):
		return ''

	def success(self, client, payload):
		reactor.callInThread(submit_data, client, payload, self.__batch_time)
		log_activity(client, 'nat')

class Nat:
	def __init__(self, config):
		pass

	def code(self):
		return 'n'

	def check_schedule(self):
		with database.transaction() as t:
			t.execute("SELECT m.m + i.i <= CURRENT_TIMESTAMP AT TIME ZONE 'UTC' FROM (SELECT COALESCE(MAX(batch), TO_TIMESTAMP(0)) AS m FROM nats) AS m CROSS JOIN (SELECT value::INTERVAL AS i FROM config WHERE plugin = 'sniff' AND name = 'nat-interval') AS i;")
			(time_s_up,) = t.fetchone()
			if time_s_up:
				return [NatTask()]
			else:
				logger.debug('Not sniffing NAT yet')
				return []
