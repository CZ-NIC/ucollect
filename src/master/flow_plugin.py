#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2014,2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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
import re
import diff_addr_store
import timers
import rate_limit

logger = logging.getLogger(name='flow')
token_re = re.compile('\(?\s*(.*?)\s*([,\(\)])(.*)')

filter_index = {}

class Filter:
	def parse(self, code, param):
		self._code = code
		return param

	def serialize(self):
		return self._code

	def token(self, param):
		match = token_re.match(param)
		if match:
			result = (match.group(1), match.group(2), match.group(3))
		else:
			result = (None, None, None)
		logger.trace("Token@%s: %s: %s", self._code, param, repr(result))
		return result

	def get_subs(self, param):
		self._subs = []
		(tok, sep, rest) = self.token(param)
		while tok is not None:
			if tok != '':
				sub = filter_index[tok]()
				param = sub.parse(tok, rest)
				self._subs.append(sub)
			else:
				param = rest
			if sep != ')':
				(tok, sep, rest) = self.token(param)
			else:
				tok = None
		return param

	def get_values(self, param):
		values = []
		(tok, sep, rest) = self.token(param)
		while tok is not None:
			if tok != '':
				values.append(tok)
			param = rest
			if sep != ')':
				(tok, sep, rest) = self.token(param)
			else:
				tok = None
		return values, param

	def __str__(self):
		return self._code

class FilterSubs(Filter):
	def serialize(self):
		return self._code + struct.pack('!I', len(self._subs)) + ''.join(map(lambda f: f.serialize(), self._subs))

	def parse(self, code, param):
		self._code = code
		return self.get_subs(param)

	def __str__(self):
		return self._code + '(' + ','.join(map(str, self._subs)) + ')'

class Filter1Sub(FilterSubs):
	def serialize(self):
		return self._code + self._subs[0].serialize()

class FilterPort(Filter):
	def serialize(self):
		return self._code + struct.pack('!' + str(len(self._ports) + 1) + 'H', len(self._ports), *self._ports)

	def parse(self, code, param):
		self._code = code
		(ports, param) = self.get_values(param)
		self._ports = map(int, ports)
		return param

	def __str__(self):
		return self._code + '(' + ','.join(map(str, self._ports)) + ')'

def encode_ip(ip):
	try:
		return struct.pack('!B', 4) + socket.inet_pton(socket.AF_INET, ip)
	except Exception:
		return struct.pack('!B', 16) + socket.inet_pton(socket.AF_INET6, ip)

class FilterIP(Filter):
	def serialize(self):
		return self._code + struct.pack('!I', len(self._ips)) + ''.join(map(lambda ip: encode_ip(ip), self._ips))

	def parse(self, code, param):
		self._code = code
		(self._ips, param) = self.get_values(param)
		return param

	def __str__(self):
		return self._code + '(' + ','.join(self._ips) + ')'

class FilterDifferential(Filter):
	def serialize(self):
		return self._code + struct.pack('!I' + str(len(self._name)) + 's', len(self._name), self._name)

	def parse(self, code, param):
		self._code = code
		([self._name], param) = self.get_values(param)
		return param

	def __str__(self):
		return self._code + '(' + self._name + ')'

class FilterRange(Filter):
	def serialize(self):
		try:
			addr = socket.inet_pton(socket.AF_INET, self._addr)
			v6 = False
		except Exception:
			addr = socket.inet_pton(socket.AF_INET6, self._addr)
			v6 = True
		return self._code + struct.pack('!BB', 6 if v6 else 4, self._mask) + addr[:(self._mask + 7) / 8]

	def parse(self, code, param):
		self._code = code
		([self._addr, self._mask], param) = self.get_values(param)
		self._mask = int(self._mask)
		return param

	def __str__(self):
		return self._code + '(' + self._addr + ',' + str(self._mask) + ')'

filter_index = {
	'T': Filter,
	'F': Filter,
	'!': Filter1Sub,
	'&': FilterSubs,
	'|': FilterSubs,
	'i': FilterIP,
	'I': FilterIP,
	'p': FilterPort,
	'P': FilterPort,
	'd': FilterDifferential,
	'D': FilterDifferential,
	'r': FilterRange,
	'R': FilterRange
}

def store_flows(max_records, client, message, expect_conf_id, now):
	(header, message) = (message[:12], message[12:])
	(conf_id, calib_time) = struct.unpack('!IQ', header)
	if conf_id != expect_conf_id:
		logger.warn('Flows of different config (%s vs. %s) received from client %s', conf_id, expect_conf_id, client)
	if not message:
		logger.warn('Empty list of flows from %s', client)
		return
	values = []
	count = 0
	while message:
		(flow, message) = (message[:61], message[61:])
		(flags, cin, cout, sin, sout, ploc, prem, tbin, tbout, tein, teout) = struct.unpack('!BIIQQHHQQQQ', flow)
		v6 = flags & 1
		udp = flags & 2
		in_started = not not (flags & 4)
		out_started = not not (flags & 8)
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
		logger.trace("Flow times: %s, %s, %s, %s, %s (%s/%s packets)", calib_time, tbin, tbout, tein, teout, cin, cout)
		ok = True
		for v in (tbin, tein, tbout, teout):
			if v > 0 and calib_time - v > 86400000:
				logger.error("Time difference out of range for client %s: %s/%s", client, calib_time - v, v)
				ok = False
		if ok:
			values.append((aloc, arem, ploc, prem, proto, now, calib_time - tbin if tbin > 0 else None, now, calib_time - tbout if tbout > 0 else None, now, calib_time - tein if tein > 0 else None, now, calib_time - teout if teout > 0 else None, cin, cout, sin, sout, in_started, out_started, client))
			count += 1
	if count > max_records:
		logger.warn("Unexpectedly high number of flows in the message from client %s - %s connection, max expected %s. Ignoring.", client, count, max_records)
		return
	with database.transaction() as t:
		t.executemany("INSERT INTO biflows (client, ip_local, ip_remote, port_local, port_remote, proto, start_in, start_out, stop_in, stop_out, count_in, count_out, size_in, size_out, seen_start_in, seen_start_out) SELECT clients.id, %s, %s, %s, %s, %s, %s - %s * INTERVAL '1 millisecond', %s - %s * INTERVAL '1 millisecond', %s - %s * INTERVAL '1 millisecond', %s - %s * INTERVAL '1 millisecond', %s, %s, %s, %s, %s, %s FROM clients WHERE clients.name = %s", values)
	logger.debug("Stored %s flows for %s", count, client)

class FlowPlugin(plugin.Plugin, diff_addr_store.DiffAddrStore):
	"""
	Plugin for storing netflow information.
	"""
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__top_filter_cache = {}
		diff_addr_store.DiffAddrStore.__init__(self, logger, "flow", "flow_filters", "filter")
		self.__delayed_config = {}
		self.__delayed_conf_timer = timers.timer(self.__delayed_config_send, 120)
		self.__rate_limiter = rate_limit.RateLimiter(1000, 10000, 60) #maximum 1000 (in average) flows per 60 seconds (peak 10000)

	# A workaround. Currently, clients sometime need to recreate their local
	# data structures, so they ask for configuration. However, the configuration ID
	# is the same, so they throw the config out and then ask again. There's a fix, but
	# until it is propagated we at least rate-limit the configurations.
	#
	# To do so, we keep a dictionary of clients we have seen asking for the config.
	# The first time we see them, we send the config and mark them with False in
	# the __delayed_config dictionary. The second (or any consequitive time) we
	# see the client is already present (it asked at least once before during this while),
	# we don't send anything, but mark it as True -- that means there's an unanswered
	# request. We answer all the unanswered requests at the end of the while and
	# start again.
	def __delayed_config_send(self):
		delayed = self.__delayed_config
		self.__delayed_config = {}
		for client in delayed:
			if delayed[client]:
				# Simulate client asking for the config now
				try:
					self.message_from_client('C', client)
				except Exception:
					# The client might have disappeared since
					pass

	def _broadcast_config(self):
		self.__top_filter_cache = {}
		self.broadcast(self.__build_config(''), lambda version: version < 2)
		self.broadcast(self.__build_config('-diff'), lambda version: version >= 2)
		for a in self._addresses:
			self._broadcast_version(a, self._addresses[a][0], self._addresses[a][1])

	def _broadcast_version(self, name, epoch, version):
		self.broadcast(self.__build_filter_version(name, epoch, version), lambda version: version >= 2)

	def __build_filter_version(self, name, epoch, version):
		return 'U' + struct.pack('!I' + str(len(name)) + 'sII', len(name), name, epoch, version)

	def __build_config(self, filter_suffix):
		filter_data = ''
		fil = self._conf['filter' + filter_suffix]
		if fil in self.__top_filter_cache:
			return self.__top_filter_cache[fil]
		if fil:
			f = filter_index[fil[0]]()
			f.parse(fil[0], fil[1:])
			logger.debug('Filter: %s', f)
			filter_data = f.serialize()
		result = 'C' + struct.pack('!IIII', int(self._conf['version']), int(self._conf['max_flows']), int(self._conf['timeout']), int(self._conf['minpackets'])) + filter_data
		self.__top_filter_cache[fil] = result
		return result

	def message_from_client(self, message, client):
		if message[0] == 'C':
			if client in self.__delayed_config:
				# The client asks for a second time in a short while. Don't send anything now, but do send it a bit later
				logger.info('Delaying config for %s', client)
				self.__delayed_config[client] = True
				return
			logger.debug('Sending config to %s', client)
			self.__delayed_config[client] = False # We know about the client, but it hasn't asked twice yet.
			if self.version(client) < 2:
				self.send(self.__build_config(''), client)
			else:
				self.send(self.__build_config('-diff'), client)
				for a in self._addresses:
					self.send(self.__build_filter_version(a, self._addresses[a][0], self._addresses[a][1]), client)
		elif message[0] == 'D':
			logger.debug('Flows from %s', client)
			activity.log_activity(client, 'flow')
			if not self.__rate_limiter.check_rate(client, 1):
				logger.warn("Storing flows for client %s blocked by rate limiter.", client)
				return
			# the limit for the number of records in a message is 2*max_flows because the client may buffer up to two times the number if he disconnects/reconnects
			reactor.callInThread(store_flows, 2 * int(self._conf['max_flows']), client, message[1:], int(self._conf['version']), database.now())
		elif message[0] == 'U':
			self._provide_diff(message[1:], client)

	def name(self):
		return 'Flow'

	def client_connected(self, client):
		# Just make sure a reconnected client can get its config right away, without waiting for rate limits
		try:
			del self.__delayed_config[client.cid()]
		except KeyError:
			pass
