#!/usr/bin/python
from twisted.internet import reactor
from twisted.internet.endpoints import TCP6ServerEndpoint
import log_extra
import logging
from client import ClientFactory
from plugin import Plugins
import master_config
import importlib

loaded_plugins = {}

logging.basicConfig(level=logging.DEBUG, format='%(name)s@%(module)s:%(lineno)s\t%(asctime)s\t%(levelname)s\t%(message)s')
plugins = Plugins()
for (plugin, config) in master_config.plugins().items():
	(modulename, classname) = plugin.rsplit('.', 1)
	module = importlib.import_module(modulename)
	constructor = getattr(module, classname)
	loaded_plugins[plugin] = constructor(plugins, config)
	logging.info('Loaded plugin %s from %s', loaded_plugins[plugin].name(), plugin)
# Some configuration, to load the port from?
port = master_config.getint('port')
endpoint = TCP6ServerEndpoint(reactor, port)
logging.info('Listening on port %s', port)
endpoint.listen(ClientFactory(plugins))
logging.info('Init done')
reactor.run()
