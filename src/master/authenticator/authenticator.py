#!/usr/bin/python2
#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2013 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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

from twisted.internet import protocol, reactor
from twisted.internet.task import LoopingCall
from twisted.protocols import basic
from threading import Lock
import re
import psycopg2
import ConfigParser
import atsha204
import sys

# Command for challenge-response auth. It is "auth ID Challenge Response" or "half ..."
auth = re.compile(r'^\s*(auth|half)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s*$', re.IGNORECASE)

if len(sys.argv) != 2:
	print "./authenticator.py config_file"
	sys.exit(1)

config_data = ConfigParser.RawConfigParser()
with open(sys.argv[1]) as f:
	config_data.readfp(f, sys.argv[1])

db = None
cursor = None
cred_cache = {}
lock = Lock()

def openDB():
	global db
	global cursor
	db = psycopg2.connect(database=config_data.get('main', 'db'), user=config_data.get('main', 'dbuser'), password=config_data.get('main', 'dbpasswd'))
	cursor = db.cursor()

openDB()

def renew():
	print "Caching auth data"
	cursor.execute('SELECT name, passwd, mechanism, builtin_passwd, slot_id FROM clients')
	lines = cursor.fetchall()
	global cred_cache
	# This should replace the whole dictionary atomically.
	cred_cache = dict(map(lambda l: (l[0], l[1:]), lines))
	db.rollback()
	print "Caching done"

renew()

def renew_safe():
	# Make sure there aren't two attempts to use the DB at once.
	with lock:
		try:
			renew()
		except Exception as e:
			print "Failed to cache data: " + str(e)
			# Reconnect the database, it may have been because of that
			openDB()

renew_timer = LoopingCall(lambda: reactor.callInThread(renew_safe))
renew_timer.start(900, False)

class AuthClient(basic.LineReceiver):
	def connectionMade(self):
		self.delimiter = "\n"

	def lineReceived(self, line):
		if line == "QUIT":
			self.transport.loseConnection()
			print "Asked to terminate"
			return
		print("Line: " + line)
		match = auth.match(line)
		if match:
			mode, client, challenge, response = match.groups()
			log_info = cred_cache.get(client)
			if log_info:
				if log_info[1] == 'Y': # Always answer yes, DEBUG ONLY!
					print "Debug YES"
					self.sendLine('YES')
				elif log_info[1] == 'N': # Always send no, DEBUG ONLY!
					print "Debug NO"
					self.sendLine('NO')
				elif log_info[1] == 'A': # Atsha authentication
					if mode.lower() == 'half':
						challenge = log_info[2] + challenge
					# TODO: Other mechanisms, for debug.
					if len(challenge) != 64 or len(client) != 16 or len(log_info[0]) != 64:
						print "Wrong length" + str(len(challenge)) + '/' + str(len(client)) + '/' + str(len(log_info[0]))
						self.sendLine('NO')
						return
					expected = atsha204.hmac(log_info[3], client.decode('hex'), log_info[0].decode('hex'), challenge.decode('hex'))
					if expected == response.decode('hex'):
						print "Login of " + client
						self.sendLine('YES')
					else:
						print "Doesn't match for " + client
						self.sendLine('NO')
				else:
					print "Bad mechanism " + log_info[1]
					self.sendLine('NO')
			else:
				print "No user " + client.lower()
				self.sendLine('NO')
		else:
			print "Parse error: " + line
			self.sendLine('Parse error')

factory = protocol.ServerFactory()
factory.protocol = AuthClient
reactor.listenTCP(config_data.getint('main', 'port'), factory)
reactor.run()
