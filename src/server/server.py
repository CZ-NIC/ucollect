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

def getstr(buf):
	(slen,) = struct.unpack('!L', buf[:4])
	return (buf[4:slen + 4], buf[slen + 4:])

last = (None, 0, 0, 0)

def handle_command(sock):
	lenbuf = read_buf(sock, 5)
	(buflen, ctype) = struct.unpack('!Lc', lenbuf)
	# The buflen is including the command
	buf = read_buf(sock, buflen - 1)
	if ctype == 'H':
		print("Client sent 'Hello' with " + str(buflen - 1) + " bytes of data")
	elif ctype == 'R':
		(plugin, buf) = getstr(buf)
		if plugin == b'Count':
			count = len(buf) / 4
			data = struct.unpack('!' + str(count) + 'L', buf)
			if len(data) == 12: # The 'D'ata answer
				print('===========================================================')
				names = ('Count', 'IPv6', 'IPv4', 'In', 'Out', 'TCP', 'UDP', 'ICMP', 'LPort', 'SIn', 'SOut', 'Size')
				for i in range(0, 12):
					print(names[i] + ':\t\t\t\t' + str(data[i]))
			else:
				print("There are " + str(data[0]) + " interfaces")
				names = ('IF-Dropped', 'Captured', 'Dropped')
				for i in range(1, len(data)):
					print(names[i % 3] + ':\t\t\t' + str(data[i]))
				global last
				if last:
					diffC = data[1] - last[1]
					diffD = data[2] - last[2]
					print("Captured from last time:\t" + str(diffC))
					print("Dropped from last time:\t\t" + str(diffD))
					if diffC > 0:
						print("Drop ration:\t\t\t" + str(100 * diffD / diffC) + "%")
				last = data
		else:
			print("Unknown plugin " + str(plugin))
	elif ctype == 'P':
		# It is ping, send pong
		buf = struct.pack('!Lc', 1, 'p')
		sock.sendall(buf)
	elif ctype == 'p':
		print("Got pong")
	else:
		print("Unknown command " + ctype + " with " + str(buflen - 1) + " bytes of data")

def send_request(sock):
	# Hardcode the message. Ugly.
	# Get data (and reset)
	buf = struct.pack('!LcL5sc', 11, 'R', 5, 'Count', 'D')
	# Get the statistics
	buf += struct.pack('!LcL5sc', 11, 'R', 5, 'Count', 'S')
	# Add one ping, just to test it
	buf += struct.pack('!Lc', 1, 'P')
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
