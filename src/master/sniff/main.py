#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2014 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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
import struct
import re

import plugin

logger = logging.getLogger(name='sniff')

def encode_host(hostname, proto, count, size):
	return struct.pack('!cBHL' + str(len(hostname)) + 's', proto, count, size, len(hostname), hostname);

class SniffPlugin(plugin.Plugin):
	"""
	Counterpart of the "sniff" plugin in the client. It sends requests
	for running external sniffer plugins on the client.
	"""
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		def getTasker(name):
			(modulename, classname) = name.rsplit('.', 1)
			module = importlib.import_module(modulename)
			result = getattr(module, classname)()
			logger.info('Loaded tasker %s from %s', result.code(), name)
			return result
		self.__taskers = map(getTasker, re.split('\s+', config['taskers']))
		self.__parallel_limit = int(config['parallel_limit'])
		self.__task_timeout = int(config['task_timeout']) * 60
		interval = int(config['interval']) * 60
		self.__checker = LoopingCall(self.__check_schedules)
		self.__checker.start(interval, False)
		self.__connected = plugins.get_clients() # Store function to get list of clients
		self.__active_tasks = {}
		self.__last_id = 0

	def __check_finished(self, task):
		"""
		Check if the task is complete, eg. there are no clients active now.
		"""
		if not task.active_clients:
			logger.info("Task %s/%s finished", task.name(), task.task_id)
			del self.__active_tasks[task.task_id]

	def __send_to_client(self, task):
		"""
		Send the task to some client that didn't get it yet. If no such client is available, do nothing.
		"""
		used = set(task.active_clients.keys()) | task.finished_clients
		available = self.__connected() - used
		if available:
			client = available.pop()
			logger.debug("Sending task %s/%s to %s", task.name(), task.task_id, client)
			message = struct.pack('!Lc', task.task_id, task.code) + task.message(client)
			self.send(message, client)
			# TODO: Schedule timeout
			task.active_clients[client] = 1
		else:
			logger.debug("No clients to send the task to now")

	def __start_task(self, task):
		"""
		Start a task ‒ send it to some set of routers and queue the others.
		"""
		self.__last_id += 1
		self.__last_id %= 2^32
		task_id = self.__last_id
		task.task_id = task_id
		self.__active_tasks[task_id] = task
		logger.info("Starting task %s as id %s", task.name(), task_id)
		for i in range(0, self.__parallel_limit):
			self.__send_to_client(task)
		self.__check_finished(task) # In case we have no clients connected now, we just finished it.

	def __check_schedules(self):
		"""
		Let the taskers check if anything should be started.
		"""
		for tasker in self.__taskers:
			tasks = tasker.check_schedule()
			for task in tasks:
				task.code = self.__tasker.code()
				self.__start_task(task)

	def name(self):
		return "Sniff"

	def __init_pings(self):
		self.broadcast(struct.pack('!LcH', 42, 'P', 3) + encode_host('nxhost.turris.cz', '6', 10, 100) + encode_host('hydra.vorner.cz', '4', 2, 100) + encode_host('hydra.vorner.cz', 'X', 10, 100))

	def client_connected(self, client):
		"""
		This is here temporarily, for testing.
		"""
		self.__init_pings()

	def message_from_client(self, message, client):
		logger.info("Received message: " + repr(message))
