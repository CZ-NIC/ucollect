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
from twisted.internet.endpoints import UNIXServerEndpoint
from twisted.internet.error import ReactorNotRunning
from subprocess import Popen
import log_extra
import logging
import logging.handlers
from client import ClientFactory
from plugin import Plugins
import master_config
import activity
import importlib
import os

reactor.suggestThreadPoolSize(1) # Too much seems to have trouble with locking :-(
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
# Some configuration, to load the port from?
endpoint = UNIXServerEndpoint(reactor, './collect-master.sock')

socat = None

class Socat(protocol.ProcessProtocol):
	def connectionMade(self):
		global socat
		socat = self.transport
		logging.info('Started proxy')

	def processEnded(self, status):
		global socat
		if socat:
			socat = None
			try:
				reactor.stop()
				# Don't report lost proxy if we're already terminating
				logging.fatal('Lost proxy, terminating')
			except ReactorNotRunning:
				pass

	def errReceived(self, data):
		logging.warn('Proxy complained: %s', data)

args = ['./soxy/soxy', master_config.get('cert'), master_config.get('key'), str(master_config.getint('port')), os.getcwd() + '/collect-master.sock']
logging.debug('Starting proxy with: %s', args)
reactor.spawnProcess(Socat(), './soxy/soxy', args=args, env=os.environ)
args = ['./soxy/soxy', master_config.get('cert'), master_config.get('key'), str(master_config.getint('port_compression')), os.getcwd() + '/collect-master.sock', 'compress']
logging.debug('Starting proxy with: %s', args)
reactor.spawnProcess(Socat(), './soxy/soxy', args=args, env=os.environ)

endpoint.listen(ClientFactory(plugins, frozenset(master_config.get('fastpings').split())))
logging.info('Init done')

reactor.run()

logging.info('Finishing up')
if socat:
	soc = socat
	socat = None
	soc.signalProcess('TERM')
activity.shutdown()
logging.info('Shutdown done')
