import MySQLdb

class __CursorContext:
	"""
	A context for single transaction on a given cursor. See transaction().
	"""
	def __init__(self, connection):
		self.__connection = connection
		self.__cursor = connection.cursor()

	def __enter__(self):
		return self.__cursor

	def __exit__(self, exc_type, exc_val, exc_tb):
		if exc_type:
			self.__connection.rollback()
		else:
			self.__connection.commit()

__connection = None
__context = None

def transaction(reuse=True):
	"""
	A single transaction. It is automatically commited on success and
	rolled back on exception. Use as following:

	with database.transaction() as transaction:
		transaction.execute(...)
		transaction.execute(...)

	If reuse is true, the cursor inside may have been used before and
	may be used again later.
	"""
	global __connection
	global __context
	if __connection is None:
		# TODO: Read from configuration. Hardcoded for now.
		__connection = MySQLdb.connect(user='ucollect', db='ucollect', passwd='123456')

	if reuse:
		if __context is None:
			__context = __CursorContext(__connection)
		return __context
	else:
		return __CursorContext(__connection)

