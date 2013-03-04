#!/usr/bin/python
from twisted.internet import reactor
from twisted.internet.endpoints import TCP6ServerEndpoint
from client import ClientFactory

plugins = {} # Just a placeholder for now
# Some configuration, to load the port from?
endpoint = TCP6ServerEndpoint(reactor, 5678)
endpoint.listen(ClientFactory(plugins))
reactor.run()
