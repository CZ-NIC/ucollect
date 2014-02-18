#!/usr/bin/python

import os
import sys

# This value needs some testing
MAX_ITEMS_COUNT = 20000
MAX_ITEMS_COUNT = 3

# This names have to be synced with Majordomo plugin
KW_OTHER_PROTO = "both"
KW_OTHER_DSTIP = "all"
KW_OTHER_PORT = "all"

def read_file(db, file):
	with open(file, mode='r') as f:
		for line in f:
			if line:
				protocol, src, dst, port, pcount, psize, dsize = line.split(',')
				pcount = int(pcount)
				psize = int(psize)
				dsize = int(dsize)

			key = (protocol, src, dst, port)

			if key in db:
				db[key]['pcount'] += pcount
				db[key]['psize'] += psize
				db[key]['dsize'] += dsize
			else:
				db[key] = { 'pcount': pcount, 'psize': psize, 'dsize': dsize }

def get_items_from_db(db):
	items = list()
	for key, val in db.items():
		items.append((key[0], key[1], key[2], key[3], val['pcount'], val['psize'], val['dsize']))

	return items

def eliminate_items(db):
	# Init new empty dictionary
	truncated_db = {}
	# Get usual list for sorting
	items = get_items_from_db(db)
	# And sort it
	items.sort(key = lambda k: k[4], reverse=True)

	# Take first MAX_ITEMS_COUNT items with highest packet count and "copy" them to finad DB
	for i in range(0, MAX_ITEMS_COUNT):
		if items[i][2] != KW_OTHER_DSTIP:
			key = (items[i][0], items[i][1], items[i][2], items[i][3])
			truncated_db[key] = { 'pcount': items[i][4], 'psize': items[i][5], 'dsize': items[i][6] }

	# This items are meant to elimination. Take its values and add number to source's 'other' sum
	for i in range(MAX_ITEMS_COUNT, len(items)):
		key = (KW_OTHER_PROTO, items[i][1], KW_OTHER_DSTIP, KW_OTHER_PORT)
		if key not in truncated_db:
			truncated_db[key] = { 'pcount': 0, 'psize': 0, 'dsize': 0 }

		truncated_db[key]['pcount'] += items[i][4]
		truncated_db[key]['psize'] += items[i][5]
		truncated_db[key]['dsize'] += items[i][6]

	return truncated_db

def main():
	if len(sys.argv) != 4:
		print "Usage: %s file1 file2 merge_to\n" % sys.argv[0]
		sys.exit(1)

	db = {}

	# Read files
	read_file(db, sys.argv[1])
	read_file(db, sys.argv[2])

	if len(db) >= MAX_ITEMS_COUNT:
		db = eliminate_items(db)

	# And merge them into file 3
	with open(sys.argv[3], mode='w') as f:
		for key, val in db.items():
			f.write("%s,%s,%s,%s,%d,%d,%d\n" % (key[0], key[1], key[2], key[3], val['pcount'], val['psize'], val['dsize']))

if __name__ == "__main__":
	main()
