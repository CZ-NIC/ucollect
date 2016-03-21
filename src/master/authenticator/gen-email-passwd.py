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
from twisted.protocols import basic
import re
import pgdb
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
db = pgdb.connect(database=config_data.get('main', 'db'), user=config_data.get('main', 'dbuser'), password=config_data.get('main', 'dbpasswd'))
cursor = db.cursor()

for s in ['a']:
	cursor.execute("SELECT name, passwd, slot_id FROM clients WHERE name LIKE '0000000" + s + "%'")
	log_info = cursor.fetchone()
	challenge = ('EF' * 32).decode('hex')
	while log_info:
		print(log_info[0].upper() + ' ' + atsha204.hmac(log_info[2], log_info[0].decode('hex'), log_info[1].decode('hex'), challenge).encode('hex').lower())
		log_info = cursor.fetchone()

