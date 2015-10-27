#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2013,2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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

import psycopg2
import logging
import threading
import traceback
import time
from master_config import get

logger = logging.getLogger(name='database')

class __CursorContext:
	"""
	A context for single transaction on a given cursor. See transaction().
	"""
	def __init__(self, connection):
		self.__connection = connection
		self.__depth = 0
		self.reuse()

	def reuse(self):
		self._cursor = self.__connection.cursor()

	def __enter__(self):
		if not self.__depth:
			logger.debug('Entering transaction %s', self)
		self.__depth += 1
		return self._cursor

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.__depth -= 1
		if self.__depth:
			return # Didn't exit all the contexts yet
		if exc_type:
			logger.debug('Rollback of transaction %s:%s/%s/%s', self, exc_type, exc_val, traceback.format_tb(exc_tb))
			self.__connection.rollback()
		else:
			logger.debug('Commit of transaction %s', self)
			self.__connection.commit()
		self._cursor = None

__cache = threading.local()

def transaction_raw(reuse=True):
	"""
	A single transaction. It is automatically commited on success and
	rolled back on exception. Use as following:

	with database.transaction() as transaction:
		transaction.execute(...)
		transaction.execute(...)

	If reuse is true, the cursor inside may have been used before and
	may be used again later.
	"""
	global __cache
	if 'connection' not in __cache.__dict__:
		logger.debug("Initializing connection to DB")
		retry = True
		while retry:
			try:
				__cache.connection = psycopg2.connect(database=get('db'), user=get('dbuser'), password=get('dbpasswd'), host=get('dbhost'))
				retry = False
			except Exception as e:
				logger.error("Failed to create DB connection (blocking until it works): %s", e)
				time.sleep(1)
	if reuse:
		if 'context' not in __cache.__dict__:
			__cache.context = __CursorContext(__cache.connection)
			logger.debug("Initializing cursor")
		else:
			__cache.context.reuse()
		return __cache.context
	else:
		return __CursorContext(__cache.connection)

def transaction(reuse=True):
	result = transaction_raw(reuse)
	if reuse:
		try: # if the cursor works
			result._cursor.execute("SELECT 1")
			(one,) = result._cursor.fetchone()
			return result
		except (psycopg2.OperationalError, psycopg2.InterfaceError):
			# It is broken. Drop the old cursor and connection and create a new one.
			logger.error("Broken DB connection, recreating")
			global __cache
			del __cache.__dict__['connection']
			del __cache.__dict__['context']
			return transaction_raw(True)
	return result

__time_update = 0
__time_db = 0

def now():
	global __time_update
	global __time_db
	t = time.time()
	if __time_update + 2 < t:
		__time_update = t
		with transaction() as t:
			t.execute("SELECT CURRENT_TIMESTAMP AT TIME ZONE 'UTC'");
			(__time_db,) = t.fetchone()
	return __time_db
