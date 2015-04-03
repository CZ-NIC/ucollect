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

from twisted.internet.task import LoopingCall
from twisted.internet import threads, reactor
from twisted.python.failure import Failure
import logging
import plugin

logger = logging.getLogger(name='buckets')

__batch = []
__limit = 50

def __process(task):
	(f, args, callback) = task
	try:
		return (callback, f(*args))
	except Exception as e:
		return (callback, Failure())

def __execute(batch):
	"""
	Execute batch of tasks, return the results. To be called in the thread.
	"""
	logger.debug("Batch execute")
	return map(__process, batch)

def __distribute(result):
	logger.debug("Batch distribute")
	for (callback, tresult) in result:
		callback(tresult)

def flush():
	"""
	Submit all work to execution, even if it doesn't make a full batch yet.
	"""
	global __batch
	if __batch:
		logger.debug("Batch flush")
		deferred = threads.deferToThreadPool(reactor, plugin.pool, __execute, __batch)
		deferred.addCallback(__distribute)
		__batch = []

def submit(f, callback, *args):
	"""
	Add another function for thread execution. Call calback once finished.
	"""
	logger.debug("Batch submit")
	global __batch
	global __limit
	__batch.append((f, args, callback))
	if len(__batch) >= __limit:
		flush()

flusher = LoopingCall(flush)
flusher.start(2, False)
