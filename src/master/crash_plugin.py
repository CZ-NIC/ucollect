import plugin

class CrashPlugin(plugin.Plugin):
	def client_connected(self, client):
		self.send('', client.cid())

	def name(self):
		return 'Crash'
