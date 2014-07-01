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
import database
import socket

logger = logging.getLogger(name='flow')

def store_flows(client, message, expect_conf_id):
	(header, message) = (message[:12], message[12:])
	(conf_id, calib_time) = struct.unpack('!IQ', header)
	if conf_id != expect_conf_id:
		logger.warn('Flows of different config (%s vs. %s) received from client %s', conf_id, expect_conf_id, client)
		return
	if not message:
		logger.warn('Empty list of flows from %s', client)
		return
	values = []
	while message:
		(flow, message) = (message[:61], message[61:])
		(flags, cin, cout, sin, sout, ploc, prem, tbin, tbout, tein, teout) = struct.unpack('!BIIQQHHQQQQ', flow)
		v6 = flags & 1
		udp = flags & 2
		if v6:
			size = 16
			tp = socket.AF_INET6
		else:
			size = 4
			tp = socket.AF_INET
		(aloc, arem, message) = (message[:size], message[size:2 * size], message[2 * size:])
		(aloc, arem) = map (lambda addr: socket.inet_ntop(tp, addr), (aloc, arem))
		if udp:
			proto = 'U'
		else:
			proto = 'T'
		logger.trace("Flow times: %s, %s, %s, %s, %s (%s/%s packets)", calib_time, tbin, tbout, tein, teout, cin, cout);
		if cin:
			values.append((arem, aloc, prem, ploc, proto, calib_time - tbin, calib_time - tein, sin, cin, client))
		if cout:
			values.append((aloc, arem, ploc, prem, proto, calib_time - tbout, calib_time - teout, sout, cout, client))
	with database.transaction() as t:
		t.executemany("INSERT INTO flows (client, ip_from, ip_to, port_from, port_to, proto, start, stop, size, count) SELECT clients.id, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP AT TIME ZONE 'UTC' - %s * INTERVAL '1 millisecond', CURRENT_TIMESTAMP AT TIME ZONE 'UTC' - %s * INTERVAL '1 millisecond', %s, %s FROM clients WHERE clients.name = %s", values)

class FlowPlugin(plugin.Plugin):
	"""
	Plugin for storing netflow information.
	"""
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__conf_id = int(config['version'])
		self.__max_flows = int(config['max_flows'])
		self.__timeout = int(config['timeout']) * 1000

	def message_from_client(self, message, client):
		if message[0] == 'C':
			logger.debug('Sending config to %s', client)
			self.send('C' + struct.pack('!III', self.__conf_id, self.__max_flows, self.__timeout), client)
		elif message[0] == 'D':
			logger.debug('Flows from %s', client)
			activity.log_activity(client, 'flow')
			reactor.callInThread(store_flows, client, message[1:], self.__conf_id)

	def name(self):
		return 'Flow'
