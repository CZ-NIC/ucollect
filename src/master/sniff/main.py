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
from twisted.internet import reactor
import logging
import struct
import re
import importlib

import plugin

logger = logging.getLogger(name='sniff')

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
			result = getattr(module, classname)(config)
			logger.info('Loaded tasker %s from %s', result.code(), name)
			return result
		self.__taskers = map(getTasker, re.split('\s+', config['taskers']))
		self.__parallel_limit = int(config['parallel_limit'])
		self.__task_timeout = int(config['task_timeout']) * 60
		self.__start_interval = int(config['start_interval'])
		interval = int(config['interval']) * 60
		self.__checker = LoopingCall(self.__check_schedules)
		self.__checker.start(interval, False)
		self.__connected = plugins.get_clients # Store function to get list of clients
		self.__active_tasks = {}
		self.__last_id = 0

	def __check_finished(self, task):
		"""
		Check if the task is complete, eg. there are no clients active now.
		"""
		if not task.active_clients: # Everything terminated and we didn't just start a new one
			logger.info("Task %s/%s finished", task.name(), task.task_id)
			task.starter.stop()
			del self.__active_tasks[task.task_id]
			try:
				task.finished()
			except Exception as e:
				logger.error("Failed to wrap up task %s/%s: %s", task.name(), task.task_id, e)

	def __timeout_task(self, task, client):
		"""
		Check if task is still running on the client. If so, cancel it and start
		a new one.
		"""
		if client in task.active_clients:
			logger.warning("Timed out task %s/%s on client %s", task.name(), task.task_id, client)
			abort = struct.pack('!Lc', task.task_id, 'N') # Sending 'NOP' with the same ID cancels the current task
			try:
				self.send(abort, client)
			except Exception as e:
				logger.error("Failed to send abort to client %s: %s", client, e)
			del task.active_clients[client]
			task.finished_clients.add(client)
			task.failure(client, None)
			self.__send_to_client(task)
			self.__check_finished(task)

	def __send_to_client(self, task):
		"""
		Send the task to some client that didn't get it yet. If no such client is available, do nothing.
		"""
		if len(task.active_clients) >= self.__parallel_limit:
			return # Currently the limit is full, start stuff later
		used = set(task.active_clients.keys()) | task.finished_clients
		available = set(self.__connected()) - used
		if available:
			client = available.pop()
			logger.debug("Sending task %s/%s to %s", task.name(), task.task_id, client)
			message = struct.pack('!Lc', task.task_id, task.code) + task.message(client)
			try:
				if not self.send(message, client):
					task.finished_clients.add(client)
					task.failure(client, None)
					# The client doesn't have the sniff plugin, so try with another one
					return self.__send_to_client(task)
			except Exception as e:
				logger.error("Failed to send task %s/%s to client %s: %s", task.name(), task.task_id, client, e)
			reactor.callLater(self.__task_timeout, lambda: self.__timeout_task(task, client))
			task.active_clients[client] = 1
		else:
			logger.debug("No clients to send the task to now (%s/%s)", task.name(), task.task_id)
			self.__check_finished(task)

	def __start_task(self, task):
		"""
		Start a task - send it to some set of routers and queue the others.
		"""
		self.__last_id += 1
		self.__last_id %= 2**32
		task_id = self.__last_id
		task.task_id = task_id
		self.__active_tasks[task_id] = task
		logger.info("Starting task %s as id %s", task.name(), task_id)
		task.starter = LoopingCall(lambda: self.__send_to_client(task))
		task.starter.start(self.__start_interval, True)
		self.__check_finished(task) # In case we have no clients connected now, we just finished it.

	def __check_schedules(self):
		"""
		Let the taskers check if anything should be started.
		"""
		for tasker in self.__taskers:
			tasks = tasker.check_schedule()
			for task in tasks:
				task.code = tasker.code()
				self.__start_task(task)

	def name(self):
		return "Sniff"

	def message_from_client(self, message, client):
		(tid, status, payload) = (message[:4], message[4], message[5:])
		(tid,) = struct.unpack('!L', tid)
		if tid in self.__active_tasks:
			task = self.__active_tasks[tid]
			if client in task.active_clients:
				another = True
				try:
					if status == 'O':
						logger.debug("Answer for task %s/%s from client %s", task.name(), tid, client)
						task.success(client, payload)
					elif status == 'F':
						logger.debug("Failure in task %s/%s on client %s", task.name(), tid, client)
						task.failure(client, payload)
					elif status == 'U':
						logger.warn("Client %s doesn't know how to handle task %s/%s", client, task.name(), tid)
						task.failure(client, None)
					elif status == 'A':
						another = False
						logger.warn("Client %s aborted task %s (may be previous version we don't know about)", client)
				except Exception as e:
					logger.error("Failed to handle answer %s to %s/%s from %s: %s", status, task.name(), tid, client, e)
				if another:
					del task.active_clients[client]
					task.finished_clients.add(client)
					self.__send_to_client(task)
					self.__check_finished(task)
			else:
				logger.warn("Answer from inactive client %s for task %s/%s", client, task.name(), tid)
		else:
			logger.warn("Answer for inactive task %s", tid)
