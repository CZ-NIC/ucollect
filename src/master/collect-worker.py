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

from twisted.internet import reactor, protocol
from twisted.internet.endpoints import UNIXServerEndpoint, UNIXClientEndpoint, TCP4ServerEndpoint
from twisted.internet.error import ReactorNotRunning
from subprocess import Popen
import log_extra
import logging
import logging.handlers
from client import ClientFactory
from coordinator import CoordinatorWorkerFactory, Worker
from plugin import Plugins, pool
import master_config
import socket
import activity
import importlib
import os
import sys

# If we have too many background threads, the GIL slows down the
# main thread and cleants start dropping because we are not able
# to keep up with pings.
reactor.suggestThreadPoolSize(3)

if len(sys.argv) != 3:
	raise Exception('There must be 2 arguments - config file name an path to socket (for communicating with master)')

severity = master_config.get('log_severity')
if severity == 'TRACE':
	severity = log_extra.TRACE_LEVEL
else:
	severity = getattr(logging, severity)
log_file = master_config.get('log_file')
logging.basicConfig(level=severity, format=master_config.get('log_format'))
if log_file != '-':
	handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=int(master_config.get('log_file_size')), backupCount=int(master_config.get('log_file_count')))
	handler.setFormatter(logging.Formatter(fmt=master_config.get('log_format')))
	logging.getLogger().addHandler(handler)

loaded_plugins = {}
plugins = Plugins()
for (plugin, config) in master_config.plugins().items():
	(modulename, classname) = plugin.rsplit('.', 1)
	module = importlib.import_module(modulename)
	constructor = getattr(module, classname)
	loaded_plugins[plugin] = constructor(plugins, config)
	logging.info('Loaded plugin %s from %s', loaded_plugins[plugin].name(), plugin)

ep = UNIXClientEndpoint(reactor, sys.argv[2])
logging.debug('readers %s',reactor.getReaders())
d=ep.connect(CoordinatorWorkerFactory(plugins, frozenset(master_config.get('fastpings'))))
def cant_connect(failure):
	logging.fatal("Can't connect to master: %s", failure)
	reactor.stop()
d.addErrback(cant_connect)
reactor.run()

logging.info('Finishing up')
pool.stop()
activity.shutdown()
logging.info('Shutdown done')
