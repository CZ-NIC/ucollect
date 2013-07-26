class RNG:
	# See src/plugins/buckets/rng.c for details, just python reimplementation
	def __init__(self, seed):
		even = seed & 0x5555555555555555;
		odd = seed & 0xAAAAAAAAAAAAAAAA;
		self.__low = (even & 0x00000000FFFFFFFF) | ((even & 0xFFFFFFFF00000000) >> 31)
		self.__high = (odd & 0x00000000FFFFFFFF) | ((odd & 0xFFFFFFFF00000000) >> 33)
		assert self.__low and self.__high

	def get(self):
		self.__low = (36969 * (self.__low & 0xFFFF) + (self.__low >> 16)) & 0xFFFFFFFF
		self.__high = 18000 * (self.__high & 0xFFFF) + (self.__high >> 16) & 0xFFFFFFFF
		return ((self.__high << 16) + self.__low) & 0xFFFFFFFF

class Hash:
	def __init__(self, seed_base, hash_count, hash_line_size):
		rng = RNG(seed_base)
		size = hash_line_size * hash_count
		self.__line_size = hash_line_size
		self.__hash_data = []
		for i in range(0, size):
			self.__hash_data.append(rng.get())

	def get(self, key, func_index):
		result = 0
		index = func_index * self.__line_size
		for c in key:
			result ^= self.__hash_data[index + ord(c)]
			index += 256
		return result
