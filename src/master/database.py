import MySQLdb

class __CursorContext:
	"""
	A context for single transaction on a given cursor. See transaction().
	"""
	def __init__(self, connection):
		self.__connection = connection
		self.__cursor = connection.cursor()
		self.__depth = 0

	def __enter__(self):
		self.__depth += 1
		return self.__cursor

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.__depth -= 1
		if self.__depth:
			return # Didn't exit all the contexts yet
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

def log_activity(client, activity):
	"""
	Log activity of a client. Pass name of the client (.cid()) and name
	of the activity (eg. "login").
	"""
	with transaction() as t:
		t.execute("INSERT INTO activities (client, timestamp, activity) SELECT clients.id, NOW(), activity_types.id FROM clients JOIN activity_types WHERE clients.name = %s AND activity_types.name = %s", (client, activity))
