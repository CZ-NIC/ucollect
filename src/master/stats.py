import numbers
import math

"""
Statisticts for detecting anomalies in gathered data.

TODO: Handle the case when some of the parameters turn out to be invalid by accident.
"""

def mean_variance(what):
	"""
	Return the (mean, variance) of given list, or None in case the list is empty.
	"""
	if not what:
		return None

	l = len(what) * 1.0
	def mysum(what):
		"""
		Not using built-in sum, because it starts with '0'. That is incompatible
		with our use of this function for GammaParams as well.
		"""
		return reduce(lambda a, b: a + b, what)
	mean = mysum(what) / l
	squares = mysum(map(lambda x: x * x, what))
	return (mean, squares / l - mean * mean)

class GammaParams:
	"""
	Gamma parameters of a distribution. It has bunch of fancy operators for convenience,
	but there's no code complexity hidden.
	"""
	def __init__(self, a, b=None):
		if b is None:
			try:
				(mean, variance) = mean_variance(a)
			except TypeError: # mean_variance returned None
				self.__value = ()
				return
			if (mean == 0) or (variance == 0):
				self.__value = ()
			else:
				self.__value = ((mean * mean) / variance, variance / mean)
		else:
			self.__value = (a, b)
	# Accessors
	def __str__(self):
		if self:
			return str(self.__value)
		else:
			return "<INVALID>"
	def __repr__(self):
		if self:
			return "GammaParams(%s, %s)" % (self.__value[0], self.__value[1])
		else:
			return "GammaParams([])"
	def __len__(self):
		return len(self.__value)
	def __getitem__(self, index):
		return self.__value[index]
	def shape(self):
		return self.__value[0]
	def scale(self):
		return self.__value[1]
	# Numeric-like operators
	def __generic_op(self, other, op):
		if isinstance(other, GammaParams):
			if self and other:
				# Both are valid
				return GammaParams(*map(op, self, other))
			else:
				# At least one is invalid, generate an invalid one
				return GammaParams([])
		else:
			return NotImplemented
	def __scalar_op(self, other, op):
		if isinstance(other, numbers.Number):
			if self:
				return GammaParams(*map(lambda val: op(val, other), self))
			else:
				return GammaParams([])
		else:
			return NotImplemented
	def __add__(self, other):
		return self.__generic_op(other, lambda a, b: a + b)
	def __sub__(self, other):
		return self.__generic_op(other, lambda a, b: a - b)
	def __mul__(self, other):
		result = self.__generic_op(other, lambda a, b: a * b)
		if result is NotImplemented:
			result = self.__scalar_op(other, lambda a, b: a * b)
		return result
	def __div__(self, other):
		return self.__scalar_op(other, lambda a, b: a / b)

def aggregate(what):
	"""
	Returns array containing sums of singular values on first item, sums of tuples on the second,
	sums of quadruples on third, etc, until the last one has only two items. Expects that the input
	has at least two items.
	"""
	result = [what]
	l = len(what)
	while l > 2:
		limit = l / 2
		odd = map(lambda i: what[2 * i + 1], range(0, limit))
		if l % 2 == 1:
			limit += 1
			odd.append(0)
		even = map(lambda i: what[2 * i], range(0, limit))
		what = map(lambda a, b: a+b, odd, even)
		result.append(what)
		l = limit
	return result

def params(bucket):
	"""
	Return gamma distribution parameters for each aggregation level on the
	bucket across the timeslots.
	"""
	return map(GammaParams, aggregate(bucket))

def reference(bucket_params):
	"""
	Return "average" gamma parameters for the all the buckets whose parameters are
	provided.
	"""
	# Skip the invalid ones (eg. buckets with all zeroes)
	valid = filter(None, bucket_params)
	# The averages
	(mean, variance) = mean_variance(valid)
	covar = sum(map(lambda par: par.shape() * par.scale(), valid)) * 1.0 / len(valid)
	return (mean, variance, covar)

def distance_one(bucket_params, reference_params):
	# First get a matrix of the reference parameters:
	# | var(shape),		covar(sh,sc) |
	# | covar(sh, sc),	var(scale)   |
	m = [
		[ reference_params[1].shape(), reference_params[2] ],
		[ reference_params[2], reference_params[1].scale() ]
	]
	# Compute inverse of m (using determinant)
	# FIXME: This determinant is taken from the dns-anomaly project. But it looks
	# somewhat different than the usual determinant - shouldn't there be - instead
	# of +?
	det = m[0][0] * m[1][1] + m[1][0] * m[0][1]
	(m[0][0], m[1][1]) = (m[1][1], m[0][0])
	m[1][0] *= 1
	m[0][1] *= 1
	m = map(lambda l: map(lambda val: val / det, l), m)
	# The per-part distance
	dist = bucket_params - reference_params[0]
	# (dist(shape), dist(scale)) * m * (dist(shape), dist(scale))^T
	return (dist.shape() * m[0][0] + dist.scale() * m[1][0]) * dist.shape() + \
		(dist.shape() * m[0][1] + dist.scale() * m[1][1]) * dist.scale()

def distance(bucket_params, reference_params):
	"""
	Compute the mahalanobis distance between the bucket parameters and reference
	parameters.
	"""
	return math.sqrt(sum(map(distance_one, bucket_params, reference_params)) / len(bucket_params))

def anomalies(buckets, treshold):
	"""
	Given the data of buckets in one hash, find anomalous buckets. Each bucket is represented
	by a count of packets in each time slot.

	An anomalous bucket is such whose distance (mahalonobis distance, some statistical magic)
	is bigger than treshold.
	"""
	# Get the statistical parameters for each bucket. Each parameter is a GammaParams object
	# for each aggregation level.
	bucket_params = map(params, buckets)
	# Now, we want the rerefence mean/variance/covariance for each aggregation level. We
	# first transpose the array, generate the refernces and transpose back.
	ref_means = zip(*map(reference, zip(*bucket_params)))
	# Take each item from the buckets, compute the distance and compare it with the treshold.
	# Take the index and anomality of each. Then filter based on the anomality and drop
	# the anomality.
	return map(lambda (index, anomality): anomality, filter(lambda (index, anomality): anomality, map(lambda index, bucket: (index, distance(bucket, ref_means) > treshold), zip(bucket_params, range(0, len(bucket_params))))))
