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
