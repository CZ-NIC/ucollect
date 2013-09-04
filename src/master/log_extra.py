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

"""
Enhance the built in logging a little bit.

Add a TRACE level (which is more verbose than DEBUG).
"""

TRACE_LEVEL = 5

logging.addLevelName(TRACE_LEVEL, "TRACE")
def trace(self, message, *args, **kwargs):
	if self.isEnabledFor(TRACE_LEVEL):
		self._log(TRACE_LEVEL, message, args, **kwargs)
logging.Logger.trace = trace
def trace_module(message, *args, **kwargs):
	trace(logging.getLogger(), message, *args, **kwargs)
logging.trace = trace_module
