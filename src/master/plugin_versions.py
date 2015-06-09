#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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

from twisted.internet.task import LoopingCall
from twisted.internet import reactor
import collections
import weakref
import time
import database

__cache = collections.defaultdict(set)
__cache_time = 0
__cache_expiration = 300
__cache_clients = weakref.WeakSet()

def __update_cache():
	"""
	Check if the cache is up to date, if not, reload from database.
	Return if any changes were made.
	"""
	now = time.time()
	global __cache_time
	global __cache_expiration
	global __cache
	if __cache_time + __cache_expiration >= now:
		return False
	with database.transaction() as t:
		t.execute("SELECT name, version, hash FROM known_plugins WHERE status = 'allowed'")
		allowed = t.fetchall()
	parsed = collections.defaultdict(set)
	for v in allowed:
		(name, version, md5_hash) = v
		parsed[name].add((version, md5_hash))
	if __cache == parsed:
		return False
	else:
		__cache = parsed
		__cache_time = now
		return True

def __propagate_now():
	"""
	Propagate the changes to the cache now.
	"""
	clients = list(__cache_clients) # Make a copy of the items, so they don't disappear in mid-iteration
	for c in clients:
		if c is not None: # Just in case it disappeared due to weak references (the doc is not clear on if this can happen or not)
			c.recheck_versions()

def __propagate_cache():
	"""
	Notify the rest of application about new values in the cache.
	Do it in a delayed manner, eg calling later from the event loop,
	not from the current stack. This is to make sure it doesn't disturb
	any handling of the plugins right now.
	"""
	reactor.callLater(1, __propagate_now)

def check_version(name, proto_ver, md5_hash):
	"""
	Look into the database (or into a cache, if the info is not too old)
	and check if the given plugin is to be allowed or not.
	"""
	if __update_cache():
		__propagate_cache()
	global __cache
	p_info = __cache.get(name, set())
	candidates = ((proto_ver, md5_hash), (None, md5_hash), (proto_ver, None), (None, None))
	return any(candidate in p_info for candidate in candidates)

def add_client(client):
	"""
	Add a client to be notified when the configuration of
	which plugins are allowed changes. The client is free
	to disappear if it seems fit.
	"""
	global __cache_clients
	__cache_clients.add(client)

def __time_check():
	"""
	Check repeatedly if the list of allowed plugins changed.
	"""
	if __update_cache():
		__propagate_now()

checker = LoopingCall(__time_check)
checker.start(300) # Once every 5 minutes
