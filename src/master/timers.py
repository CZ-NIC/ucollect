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
import logging
import traceback
import inspect
import hashlib
from protocol import extract_string, format_string
import struct
import worker2gatekeeper

logger = logging.getLogger(name='timers')


def timer(callback, time, startnow=False):
	def protected():
		try:
			callback()
		except Exception as e:
			logger.error("Exception in timer call: %s", traceback.format_exc())
	result = LoopingCall(protected)
	result.start(time, startnow)
	return result

global_timer_map = {}

def global_timer(name, callback, time, startnow=False):
	"""
	Sets timer (that will be synchronized between all workers).

	It just saves it's identifier and callback internally and requests setting timer on master.
	"""
	global global_timer_map
	global_timer_map[name] = callback
	worker2gatekeeper.send_to_master("T" + struct.pack('!L', time) + format_string(name))
	if startnow:
		callback()

def global_timer_cb(id):
	"""
	Callback for globally synchronized timer.

	It's called upon receiving notification about global timer from master.
	"""
	global global_timer_map
	try:
		global_timer_map[id]()
	except Exception as e:
		logger.error("Error calling: ", e)
