#!/usr/bin/python
from twisted.internet import reactor
from twisted.internet.endpoints import TCP6ServerEndpoint
import log_extra
import logging
from client import ClientFactory
from plugin import Plugins
import count_plugin
import buckets.main

logging.basicConfig(level=log_extra.TRACE_LEVEL, format='%(name)s@%(module)s:%(lineno)s\t%(asctime)s\t%(levelname)s\t%(message)s')
plugins = Plugins()
count_plugin.CountPlugin(plugins)
buckets.main.BucketsPlugin(plugins)
# Some configuration, to load the port from?
endpoint = TCP6ServerEndpoint(reactor, 5678)
endpoint.listen(ClientFactory(plugins))
logging.info('Init done')
reactor.run()
