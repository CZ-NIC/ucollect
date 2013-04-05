import buckets.stats

class Group:
	"""
	A group of clients. The clients (their IDs) are kept here.

	All the clients in the group have their counts summed together and statistics are computed as if
	they were one point on the network.

	A client may be present in multiple groups at once.

	The client does not care which criterion it is. It is expected that each criterion will have its
	own sets.
	"""
	def __init__(self, hash_count, bucket_count, window_backlog, treshold):
		"""
		Constructor. Parameters:
		- hash_count: Number of independent hash functions.
		- bucket_count: Number of buckets in each hash function.
		- window_backlog: Number of history windows in addition to the current one
		  to keep and compute the statistics from.
		- treshold: Treshold how far a bucket must be from the average to be considered anomalous.
		"""
		self.__members = set()
		self.__hash_count = hash_count
		self.__bucket_count = bucket_count
		self.__window_backlog = window_backlog
		self.__treshold = treshold
		self.__history = []
		self.__current = self.__empty_data()

	def __empty_data(self):
		"""
		Provide empty data to merge the clients into.
		"""
		return map(lambda hnum: map(lambda bnum: [], range(0, self.__bucket_count)), range(0, self.__hash_count))

	def members(self):
		"""
		Return clients present in this group.
		"""
		return self.__members

	def add(self, client):
		"""
		Add a client (by name) to the group.
		"""
		self.__members.add(client)

	def remove(self, client):
		"""
		Remove a client (by name) from the group.
		"""
		self.__members.remove(client)

	def merge(self, counts):
		"""
		Merge batch of counts from single client to the current history window.
		"""
		# We have the data as [timeslot = [hash = [value in bucket]]] and want
		# [hash = [bucket = [value in timeslot]]]. Transpose that.
		# TODO: If we wanted to optimise, we could put this outside, so it's not
		# done for each group. But for now, we don't care.
		new = map(lambda hnum:
			map(lambda bnum:
				map(lambda tslot: tslot[hnum][bnum], counts),
			range(0, self.__bucket_count)),
		range(0, self.__hash_count))
		assert(len(self.__current) == len(new) and len(self.__current) == self.__hash_count)
		for (chash, nhash) in zip(self.__current, new):
			assert(len(chash) == len(nhash) and len(chash) == self.__bucket_count)
			for (cbucket, nbucket) in zip(chash, nhash):
				# Extend them so they are of the same length. As new clients start
				# later, we extend with zeroes on the left side.
				mlen = max(len(cbucket), len(nbucket))
				cbucket[:0] = [0] * (mlen - len(cbucket))
				nbucket[:0] = [0] * (mlen - len(nbucket))
				assert(len(cbucket) == len(nbucket) and len(cbucket) == mlen)
				for i in range(0, len(cbucket)):
					cbucket[i] += nbucket[i]

	def anomalies(self):
		"""
		Compute and return anomalous indices in each hash. Returns list of lists.

		Switch to new history window afterwards, to start gathering anew.
		"""
		self.__history.append(self.__current)
		# Concatenate the windows together.
		batch = map(lambda hnum:
				map(lambda bnum:
					reduce(lambda a, b: a + b, map(lambda hist: hist[hnum][bnum], self.__history)),
				range(0, self.__bucket_count)),
			range(0, self.__hash_count))
		anomalies = map(lambda bucket: buckets.stats.anomalies(bucket, self.__treshold), batch)
		# Clean old history.
		if len(self.__history) > self.__window_backlog:
			self.__history = self.__history[len(self.__history) - self.__window_backlog:]
		self.__current = self.__empty_data()
		return anomalies
