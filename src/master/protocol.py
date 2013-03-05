import struct

def format_string(string):
	length = len(string)
	return struct.pack('!L' + str(length) + 's', length, string)
