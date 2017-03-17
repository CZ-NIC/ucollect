#!/usr/bin/python2
#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2013-2017 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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
from twisted.internet.endpoints import UNIXServerEndpoint, TCP4ServerEndpoint
from twisted.internet.error import ReactorNotRunning
import log_extra
import logging
import logging.handlers
from client_gatekeeper import ClientGatekeeperFactory
from worker2gatekeeper import WORKER_SOCK_FD
from gatekeeper2worker import Worker
import master_config
import socket
import activity
import importlib
import os
import sys

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
		try:
			reactor.stop()
		except ReactorNotRunning:
			pass

	def errReceived(self, data):
		logging.warn('worker complained: %s', data)

workers=[]
endpoint =  TCP4ServerEndpoint(reactor, master_config.getint('port_proxy_master'))
for i in range(master_config.getint('workers_cnt')):
	worker_sock = './collect-master-worker-'+str(i)+'.sock' #socket for master - worker communication
	parent_sock, child_sock = socket.socketpair() # raw socket for sending client's file handles
	args = ['./collect-worker.py', sys.argv[1], worker_sock]
	ep = UNIXServerEndpoint(reactor, worker_sock) #master listens on this socket, worker will connect
	workers.append(Worker(parent_sock, ep))
	reactor.spawnProcess(WorkerProtocol(), './collect-worker.py', args=args, env=os.environ, childFDs={0:0, 1:1, 2:2, WORKER_SOCK_FD: child_sock.fileno() })

args = ['./soxy/soxy', master_config.get('cert'), master_config.get('key'), master_config.get('ca'), str(master_config.getint('port_compression')), '127.0.0.1:'+str(master_config.getint('port_proxy_master')), 'compress']
logging.debug('Starting proxy with: %s', args)
reactor.spawnProcess(Socat(), './soxy/soxy', args=args, env=os.environ)
endpoint.listen(ClientGatekeeperFactory(workers))
logging.info('Init done')
reactor.run()


logging.info('Finishing up')

if socat:
	soc = socat
	socat = None
	soc.signalProcess('TERM')
activity.shutdown()
logging.info('Shutdown done')
