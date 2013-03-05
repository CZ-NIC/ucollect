import struct

def format_string(string):
	length = len(string)
	return struct.pack('!L' + str(length) + 's', length, string)

def extract_string(buf):
	(slen,) = struct.unpack('!L', buf[:4])
	return (buf[4:slen + 4], buf[slen + 4:])
