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

import logging
import database
import threading

logger = logging.getLogger(name='activity')

__queue = []
# To be initialized on the first use
__condition = None
__thread = None

def __keep_storing():
	"""
	Run in separate thread. It keeps getting stuff from the queue and pushing it to the database.
	This effectively makes waiting for the databes commit asynchronous.
	"""
	global __condition
	global __queue
	logger.info('Activity thread started')
	run = True
	while run:
		actions = None
		with __condition:
			while not __queue:
				__condition.wait()
			actions = __queue
			__queue = []

		try:
			with database.transaction() as t:
				for (client, activity) in actions:
					if client is None:
						if activity == 'shutdown':
							logger.debug('Doing activity thread shutdown')
							run = False
						else:
							logger.error('Unknown global activity: %s', activity)
					else:
						logger.debug("Pushing %s of %s", activity, client)
						t.execute("INSERT INTO activities (client, timestamp, activity) SELECT clients.id, CURRENT_TIMESTAMP AT TIME ZONE 'UTC', activity_types.id FROM clients CROSS JOIN activity_types WHERE clients.name = %s AND activity_types.name = %s", (client, activity))
		except Exception as e:
			logger.error("Unexpected exception in activity thread, ignoring: %s", e)
	logger.info('Activity thread terminated')

def log_activity(client, activity):
	"""
	Log activity of a client. Pass name of the client (.cid()) and name
	of the activity (eg. "login").
	"""
	logger.debug("Logging %s activity of %s", activity, client)
	global __queue
	global __condition
	global __thread
	if not __condition:
		logger.info('Starting the activity thread')
		# Initialize the thread machinery
		__condition = threading.Condition(threading.Lock())
		__thread = threading.Thread(target=__keep_storing, name='activity')
		__thread.start()
	# Postpone it to separate thread
	with __condition:
		__queue.append((client, activity))
		__condition.notify()

def shutdown():
	global __condition
	global __queue
	if __condition:
		logger.info('Asking the activity thread to shutdown')
		with __condition:
			__queue.append((None, 'shutdown')) # A shutdown marker
			__condition.notify()
		__thread.join()
