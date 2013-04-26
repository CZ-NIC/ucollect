import ConfigParser
import sys

if len(sys.argv) != 2:
	raise Exception('There must be exactly 1 argument - config file name')

config_data = ConfigParser.RawConfigParser()
with open(sys.argv[1]) as f:
	config_data.readfp(f, sys.argv[1])

def get(name):
	global config_data
	return config_data.get('main', name)

def getint(name):
	global config_data
	return config_data.getint('main', name)

def plugins():
	global config_data
	sections = set(config_data.sections())
	sections.remove('main')
	return dict(map(lambda plugin: (plugin, dict(config_data.items(plugin))), sections))
