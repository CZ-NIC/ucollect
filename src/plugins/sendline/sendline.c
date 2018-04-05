//activation:!!!!!!!!!!!!!!!!!!!!!
//insert into known_plugins (name,status,introduced) values ('Sendline','allowed','2017-09-18 10:31:46.718964');

/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013-2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/


#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"
#include "../../core/loop.h"

#include <arpa/inet.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <endian.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void send_data(struct context *context, char * data){
	if(data!=0){
		size_t len=strlen(data);
		uint8_t *me = mem_pool_alloc(context->temp_pool, len*sizeof(char));
		memcpy(me, data, len*sizeof(char));
		uplink_plugin_send_message(context, me,len*sizeof(char));
	}

}

FILE * get_locked_file_descriptor(const char * filename){
	FILE * f;
	struct stat st1;
	struct stat st2;
	while(1){
		f = fopen(filename, "a+");
		int fd=fileno(f);
		if(flock(fd, LOCK_EX)==0){ //automatically unlocked when we close the handle.
			if( stat(filename,&st1)<0)continue;
			if(fstat(fd      ,&st2)<0)continue;
			if(st1.st_ino==st2.st_ino){ //Make sure that the file was not deleted between opening and locking.
				break;
			}
		}
		fclose(f);
		usleep(100*1000);
	}
	return f;
}


static void initialize(struct context *context) {
/*	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	// We would initialize with {} to zero everything, but iso C doesn't seem to allow that.
	*context->user_data = (struct user_data) {
		.timestamp = 0
	};*/
}

static void communicate(struct context *context, const uint8_t *data, size_t length) {
	char * output_filename="/tmp/ludus_output";
	FILE * f=get_locked_file_descriptor(output_filename);
	char * line=0;
	size_t bufsize=0; //size of the allocated buffer, not length of the loaded line.
	while(getline(&line,&bufsize,f)!=-1){
		send_data(context, line);
		free(line);line=0;
	}
	remove(output_filename);
	fclose(f);
	return;
}

#ifdef STATIC
struct plugin *plugin_info_count(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "Sendline",
		//.packet_callback = packet_handle,
		.init_callback = initialize,
		.uplink_data_callback = communicate,
		.version = 2
	};
	return &plugin;
}
