#
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2013,2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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

#activation of plugin:
#insert into known_plugins (name,status,introduced) values ('Sendline','allowed','2017-09-18 10:31:46.718964');
#create table ludus (client text, value text);

'''
This is the server part of the ucollect plugin for the LUDUS project.
It receives a JSON and stores it into database.
'''


from twisted.internet import reactor
import struct
import plugin
import time
import logging
import database
import activity
import timers
import json
import time
logger = logging.getLogger(name='sendline')

cached_tables={} #'tablename':[date_of_the_last_reload, {'column_name':order,..}, DATA_OF_THE_TABLE] #this cache is supposed to contain only small tables (tens of records...)

def get_porttype_id(type_):
	table_column_ids=cached_tables["ludus_port_types"][1]
	table_data=cached_tables["ludus_port_types"][2]
	
	for record in table_data: #iterate through columns of cached table
		if(record[table_column_ids["name"]]==type_): #access the column "name" of a port type.
			return record[table_column_ids["type_id"]]
	return None


def get_alerttype_id(type_):
	table_column_ids=cached_tables["ludus_alert_types"][1]
	table_data=cached_tables["ludus_alert_types"][2]
	
	for record in table_data: #iterate through columns of cached table
		if(record[table_column_ids["name"]]==type_): #access the column "name" of a port type.
			return record[table_column_ids["type_id"]]
	return None

def get_strategy_id(type_):
	table_column_ids=cached_tables["ludus_strategy_files"][1]
	table_data=cached_tables["ludus_strategy_files"][2]
	
	for record in table_data: #iterate through columns of cached table
		if(record[table_column_ids["name"]]==type_): #access the column "name" of a port type.
			return record[table_column_ids["strategy_id"]]
	return None

def store_counts(data, stats, now):
	logger.info('Storing sendline data')
	with database.transaction() as t:
		for table in ["ludus_port_types", "ludus_strategy_files","ludus_alert_types"]:
			#only renew the cache once per minute.
			#TODO: in production this can be set to a longer interval...
			if(not cached_tables.get(table) or time.time()-cached_tables[table][0]> 1*60): 
				#if the following select returns more than a few tens of lines something is wrong.
				t.execute('SELECT * FROM '+table) 
				data_ = t.fetchall()
				column_names={}
				i=0
				for x in t.description:
					column_names[x[0]]=i
					i+=1
				cached_tables[table]=[time.time(),column_names,data_]
						
		#we should have port_types, strategy_files and alert_types cached in memory

		#TODO: Re: fail: check which information can be missing. We do not want to be _too_ strict.
		for router_id in data.keys():
			try:
				#json size limit.
				if(len(data[router_id])>1024*1024):
					logger.error("Record too long.") #logger.debug
					continue
				json_data=None
				try:
					json_data=json.loads(data[router_id])
				except ValueError as e:
					logger.error("JSON parse error while storing a record: %s", str(e))
					continue
				#insert into Strategy_used
				strategy_id=get_strategy_id(json_data['GameStrategyFileName'])
				if(strategy_id==None):
					logger.error("Strategy not found in database.")
					continue


				#insert into Records
				t.execute("insert into ludus_records (router_id, date_created) values (%s,%s) returning record_id", (router_id,json_data['timestamp']))
				record_id=t.fetchone()[0]

				#insert into Strategy used
				t.execute("insert into ludus_strategy_used (strategy_id,record_id) values (%s,%s)",(strategy_id,record_id))
				
				#insert into Port_information
				port_information=[]
				dobreak=False
				for protocol in json_data['PortInfo'].keys(): #TCP/UDP
					for port in json_data['PortInfo'][protocol].keys(): #port
						type_id=get_porttype_id(json_data['PortInfo'][protocol][port]["type"]) #Honeypot/Production
						if(type_id==None):
							logger.error("Port Type not found in database (Port Type means e.g. Honeypot/Production).")
						else:
							rec=json_data['PortInfo'][protocol][port]
							port_information.append({'record_id':record_id, 'protocol':protocol, 'port_number':port, 'type_id':type_id, 'flow_count':rec["Flows"], 'packets_count':rec["Packets"], 'bytes_count':rec["bytes"], 'alert_count':rec["#Alerts"]})


				port_information2=map(lambda x:(x["record_id"],x["protocol"],x["port_number"],x["type_id"], x["flow_count"], x["packets_count"], x["bytes_count"], x["alert_count"]),port_information)
				t.executemany("insert into ludus_port_information (record_id,protocol,port_number,type_id, flow_count, packets_count,bytes_count, alert_count) values (%s,%s,%s,%s,  %s,%s,%s,%s)", port_information2)		

				#insert into Alert_volumes
				t.execute("insert into ludus_alert_volumes (record_id,severity_1,severity_2,severity_3,severity_4,unique_signatures) values (%s,%s,%s,%s,%s,%s)", (record_id,json_data["alerts"]["# Severity 1"],json_data["alerts"]["# Severity 2"],json_data["alerts"]["# Severity 3"],json_data["alerts"]["# Severity 4"],json_data["alerts"]["# Uniq Signatures"]))

				#insert into Alert_types_per_record
				dobreak=False
				alert_types_per_record=[]
				for alert in json_data['alerts']['Alerts Categories'].keys():
					type_id=get_alerttype_id(alert)
					if(type_id==None):
						logger.error("Alert type not found in database.")
					else:
						alert_types_per_record.append({'record_id':record_id, 'type_id':type_id,'count':json_data['alerts']['Alerts Categories'][alert]})

				alert_types_per_record2=map(lambda x: (x['record_id'],x['type_id'], x['count']),alert_types_per_record)
				t.executemany("insert into ludus_alert_types_per_record (record_id,type_id,count) values (%s,%s,%s) on conflict do nothing",alert_types_per_record2)

				#find all distinct B class networks and create their records in B_class_networks if they do not exist
				network_info_per_record=[]
				for ip in json_data['alerts']['Alerts/DstBClassNet'].keys():
					network_info_per_record.append({'direction':'DEST','__ip__':ip,'__count__':json_data['alerts']['Alerts/DstBClassNet'][ip]})
				for ip in json_data['alerts']['Alerts/SrcBClassNet'].keys():
					network_info_per_record.append({'direction':'SRC','__ip__':ip,'__count__':json_data['alerts']['Alerts/SrcBClassNet'][ip]})

				network_ips2=list(set(map(lambda x:(x["__ip__"],), network_info_per_record)))
				t.executemany("insert into ludus_b_class_networks (ip) values (%s) on conflict do nothing", network_ips2) #on conflict requires postgres 9.5
				

				#insert into Network_info_per_record
				network_info_per_record2=map(lambda x: (x['__ip__'],record_id,x['direction'],x['__count__']), network_info_per_record)
				t.executemany("insert into ludus_network_info_per_record (network_id,record_id,direction,count) values ((select network_id from ludus_b_class_networks where ip=%s limit 1),%s,%s,%s) on conflict do nothing", network_info_per_record2)
				#everything succeeded. We can commit the insertion of a single json.
				
			except Exception as e:
				logger.debug("Exception while storing a record: %s (%s)\nThe record will not be stored.",str(e),str(type(e)))
				raise #TODO: COMMENT THIS.


class SendlinePlugin(plugin.Plugin):
	"""
	The plugin providing basic statisticts, like speed, number of
	dropped packets, etc.
	"""
	def __init__(self, plugins, config):
		plugin.Plugin.__init__(self, plugins)
		self.__interval = int(config['interval'])
		self.__aggregate_delay = int(config['aggregate_delay'])
		self.__downloader = timers.timer(self.__init_download, self.__interval, False)
		self.__data = {}
		self.__stats = {}
		self.__last = int(time.time())
		self.__current = int(time.time())

	def __init_download(self):
		"""
		Ask all the clients to send their statistics.
		"""
		# Send a request with current timestamp
		t = int(time.time())
		self.__last = self.__current
		self.__current = t
		self.broadcast(struct.pack('!Q', t))
		# Wait a short time, so they can send us some data and process it after that.
		self.__data = {}
		self.__stats = {}
		reactor.callLater(self.__aggregate_delay, self.__process)

	def __process(self):
		if not self.__data:
			return # No data to store.
		# As manipulation with DB might be time consuming (as it may be blocking, etc),
		# move it to a separate thread, so we don't block the communication. This is
		# safe -- we pass all the needed data to it as parameters and get rid of our
		# copy, passing the ownership to the task.
		reactor.callInThread(store_counts, self.__data, self.__stats, database.now())
		self.__data = {}
		self.__stats = {}

	def name(self):
		return 'Sendline'

	def message_from_client(self, message, client):
		logger.debug("Data: %s", message)
		activity.log_activity(client, "sendline")
		self.__data[client]=message
		'''
		count = len(message) / 4 - 2 # 2 for the timestamp
		dtype = 'L'
		data = struct.unpack('!Q' + str(count) + 'L', message)
		if data[0] < self.__last:
			logger.info("Data snapshot on %s too old, ignoring (%s vs. %s)", client, data[0], self.__last)
			return
		if_count = data[1]
		self.__stats[client] = data[2:2 + 3 * if_count]
		d = data[2 + 3 * if_count:]
		if len(d) > 32:
			# TODO: Remove this hack. It is temporary for the time when we have both clients
			# sending 32bit sizes and 64bit sizes. If it's too long, it is 64bit - reencode
			# the data and decode as 64bit ints.
			packed = struct.pack("!" + str(len(d)) + 'L', *d)
			d = struct.unpack('!' + str(len(d) / 2) + 'Q', packed)
		self.__data[client] = d
		logger.debug("Data: %s", data)
		if len(self.__data[client]) % 2:
			logger.error("Odd count of data elements (%s) from %s", len(self.__data[client]), client)
		activity.log_activity(client, "counts")
		'''

	def client_connected(self, client):
		"""
		A client connected. Ask for the current counts. It will get ignored (because it'll have time of
		0 probably, or something old anyway), but it resets the client, so we'll get the counts for the
		current snapshot.
		"""
		self.send(struct.pack('!Q', int(time.time())), client.cid())
