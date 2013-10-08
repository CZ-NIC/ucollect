#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2013 CZ.NIC
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

logger = logging.getLogger(name='activity')

def log_activity(client, activity):
	"""
	Log activity of a client. Pass name of the client (.cid()) and name
	of the activity (eg. "login").
	"""
	logger.debug("Logging %s activity of %s", activity, client)
	with database.transaction() as t:
		t.execute("INSERT INTO activities (client, timestamp, activity) SELECT clients.id, NOW(), activity_types.id FROM clients CROSS JOIN activity_types WHERE clients.name = %s AND activity_types.name = %s", (client, activity))
