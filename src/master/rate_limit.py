#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2017 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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

import timers
import master_config

class RateLimiter():
	"""
	Rate Limiter (per client)

	Implements token bucket for each client.

	Parameters of buckets are:
	 - inflow (how many tokens will be added),
	 - interval (how often tokens will be added),
	 - capacity (maximum number of token).
	Inflow and interval are specified when calling __init__, capacity is set in master configuration (rate_limiter_bucket_capacity).
	The actual capacity (maximum number of tokens in buckets) is rate_limiter_bucket_capacity * inflow.

	rate_limiter_bucket_capacity basically specifies the factor by which the normal limits might be exceeded.
	Eg. with rate_limiter_bucket_capacity=5 clients might send 5 * the normal limits in a burst without being blocked (assuming their rate was below the normal limits before).
	"""
	def __init__(self, inflow, interval=None):
		"""
		Initializes rate-limit (for all clients).

		:param inflow: number of tokens added to bucket
		:param interval: number of second, every [interval] seconds [inflow] tokens are added to each client's bucket. If it's None, adding should be done manually.

		Maximum number of tokens in the bucket is set to inflow * rate_limiter_bucket_capacity, which comes from master configuration.
		"""
		self.__buckets = {}
		self.__inflow = inflow
		self.__max_value = inflow * master_config.getint('rate_limiter_bucket_capacity')
		if interval:
			timers.timer(self.add_tokens_all, interval, False)

	def check_rate(self, client, cost):
		"""
		Checks rate (for specified client).

		It checks whether the operation with given cost (storing certain number of records) is allowed.
		If it's allowed, then its cost is substracted from bucket.
		If it's not, then the number of tokens is not altered.

		Initializes client's bucket if the client is not known. Bucket is always initialized to max_value.
		"""
		if not client in self.__buckets:
			self.__buckets[client] = self.__max_value
		if cost < self.__buckets[client]:
			self.__buckets[client] -= cost
			return True
		else:
			return False

	def add_tokens(self, client):
		"""
		Adds tokens to client's bucket. Does nothing if the client is not known.
		"""
		if not client in self.__buckets:
			return
		self.__buckets[client] = min(self.__buckets[client]+self.__inflow, self.__max_value)

	def add_tokens_all(self):
		"""
		Adds tokens to all client's bucket.
		"""
		for c in self.__buckets.keys():
			self.add_tokens(c)
