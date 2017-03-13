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
WorkerProcCnt = 2

if len(sys.argv) != 2:
	raise Exception('There must be exactly 1 argument - config file name')

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

socat = None

class Socat(protocol.ProcessProtocol):
	def connectionMade(self):
		global socat
		socat = self.transport
		logging.info('Started proxy')
	def childDataReceived(self, fd, str):
		logging.info('proxy: %s', str)

	def processEnded(self, status):
		global socat
		if socat:
			socat = None
			try:
				reactor.stop()
				# Don't report lost proxy if we're already terminating
				logging.fatal('Lost proxy, terminating %s', status)
			except ReactorNotRunning:
				pass

	def errReceived(self, data):
		logging.warn('Proxy complained: %s', data)

class WorkerProtocol(protocol.ProcessProtocol):
	def childDataReceived(self, fd, str):
		logging.info('worker: %s', str)

	def processEnded(self, status):
		logging.fatal('worker ended')
		reactor.stop()

	def errReceived(self, data):
		logging.warn('worker complained: %s', data)

workers=[]
workers_prot= []
#endpoint = UNIXServerEndpoint(reactor, './collect-master.sock')
endpoint =  TCP4ServerEndpoint(reactor, 12345)
for i in range(WorkerProcCnt):
	worker_sock = './collect-master-worker-'+str(i)+'.sock'
	parent_sock, child_sock = socket.socketpair()
	args = ['./collect-worker.py', sys.argv[1], worker_sock]
	worker_prot=reactor.spawnProcess(WorkerProtocol(), './collect-worker.py', args=args, env=os.environ, childFDs={0:0, 1:1, 2:2, 3: child_sock.fileno() })
	while not worker_prot.pid:
		sleep(0.25)
	ep = UNIXServerEndpoint(reactor, worker_sock)
	workers.append(Worker(parent_sock, ep))
print workers

args = ['./soxy/soxy', master_config.get('cert'), master_config.get('key'), master_config.get('ca'), str(master_config.getint('port_compression')), '127.0.0.1:12345', 'compress']
logging.debug('Starting proxy with: %s', args)
reactor.spawnProcess(Socat(), './soxy/soxy', args=args, env=os.environ)
endpoint.listen(ClientFactory(plugins, frozenset(master_config.get('fastpings').split()), workers))
logging.info('Init done')

reactor.run()

for w in workers_prot:
	w.signalProcess('TERM')

logging.info('Finishing up')
pool.stop()
if socat:
	soc = socat
	socat = None
	soc.signalProcess('TERM')
activity.shutdown()
logging.info('Shutdown done')
