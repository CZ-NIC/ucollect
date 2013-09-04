#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2013 CZ.NIC
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

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
