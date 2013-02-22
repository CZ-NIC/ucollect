#!/usr/bin/env python

'''
The ucollect's server. Currently, it is only a minimal peer for testing the
ucollect implementation. It lacks much of what is needed in the real server,
including basic things like support for the plugins, tracking of connected
clients and their live status or even ability to handle multiple clients by
some event loop.

It currently only listens on a socket. When a client connects, it forks.
The forked process interprets some minimal set of messages from the client,
just printing them to stdout. It asks for data from the count plugin from
time to time (the plugin name is hardcoded).

It listens on hardcoded address [::]:5677.
'''

import socket
import signal
import os
import time
import struct

# Avoid zombies. May work only on some systems, but this is testing software
# and it does work on linux, so who cares.
signal.signal(signal.SIGCHLD, signal.SIG_IGN)

listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
listener.bind(('::', 5678, 0, 0))
listener.listen(5)

def read_buf(sock, amount):
	buf = b''
	while amount > 0:
		part = sock.recv(amount)
		if len(part) == 0:
			raise Exception("Socket closed")
		buf += part
		amount -= len(part)
	return buf

def handle_command(sock):
	lenbuf = read_buf(sock, 5)
	(buflen, ctype) = struct.unpack('!Lc', lenbuf)
	# The buflen is including the command
	buf = read_buf(sock, buflen - 1)
	if ctype == 'H':
		print("Client sent 'Hello' with " + str(buflen - 1) + " bytes of data")
	else:
		print("Unknown command " + ctype + " with " + str(buflen - 1) + " bytes of data")

def send_request(sock):
	# Hardcode the message. Ugly.
	# Get data (and reset)
	buf = struct.pack('!LcL5sc', 11, 'R', 5, 'Count', 'D')
	# Get the statistics
	buf += struct.pack('!LcL5sc', 11, 'R', 5, 'Count', 'S')
	sock.sendall(buf)

def handle_client(sock):
	'''
	Handle a socket connection. We fork once again. One process will
	keep reading the messages from the client, the other will keep
	sending requests for information in intervals.

	We don't care about error handling, expecting python to just
	crash if it breaks.
	'''
	if os.fork():
		while True:
			handle_command(sock)
	else:
		while True:
			time.sleep(5) # Once every 5 seconds in a galaxy far far away...
			send_request(sock)

while True:
	(newsock, address) = listener.accept()
	print("New client on address " + str(address))
	if os.fork():
		newsock.close()
	else:
		handle_client(newsock)
		os.exit()
