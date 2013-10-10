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

from twisted.internet import threads

__batch = []
__limit = 50

def __process(task):
	# TODO: Exception handling
	(f, args, callback) = task
	return (callback, f(*args))

def __execute(batch):
	"""
	Execute batch of tasks, return the results. To be called in the thread.
	"""
	return map(__process, batch)

def __distribute(result):
	for (callback, tresult) in result:
		callback(tresult)

def flush():
	"""
	Submit all work to execution, even if it doesn't make a full batch yet.
	"""
	if __batch:
		deferred = threads.deferToThread(__execute, __batch)
		deferred.addCallback(__distribute)
		__batch = []

def submit(f, callback, *args):
	"""
	Add another function for thread execution. Call calback once finished.
	"""
	__batch.append((f, args, callback))
	if len(__batch) >= __limit:
		flush()
