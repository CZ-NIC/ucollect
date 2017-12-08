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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include <string.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>



struct Linked_list{
  struct Linked_list* next;
  char * data;
  int data_len;
};


//reads the last line of a file. If the very last character of a file is newline we may decide to ignore it.
char * read_last_line(const char * filename, bool ignore_newline_on_last_char){
  FILE *fp = fopen(filename,"r");
  if(fp==0){ //access denied or something alike
    return (char *)0;
  }
  struct Linked_list * first=0; 
  int BUFSIZE=1024;
  size_t last_position,current_position;
  int length_to_load;
  if(0!=fseek(fp,-1, SEEK_END)){ //jump to end.
    char *out=(char *)malloc(sizeof(char));     //the last line of an empty file is empty.
    *out=0;
    fclose(fp);
    return out;
  }

  if(ignore_newline_on_last_char){
    char nl;
    fread(&nl,sizeof(char),1,fp);
    if(nl=='\n'){
	fseek(fp,-1, SEEK_END);
    }//else{ fseek(fp,0, SEEK_END); } //we get the else part automatically because of the read above...
  }
  size_t total=0;
  last_position=ftell(fp);
  while(1){
    if(-1==fseek(fp,-BUFSIZE,SEEK_CUR)){ //-1 => crossed the beginning.
      fseek(fp,0,SEEK_SET);
    }
    current_position=ftell(fp);
    length_to_load=last_position-current_position; //min(distance to beginning, BUFSIZE)
    if(length_to_load==0){
      break;
    }
    last_position=current_position;
    char * data=(char *)malloc(sizeof(char)*(length_to_load+1));
    memset(data, 0, sizeof(char)*(length_to_load+1));
    int loaded_length=fread(data,sizeof(char), length_to_load,fp);
    assert(length_to_load==loaded_length);
    assert(0==fseek(fp,last_position,SEEK_SET)); //return cursor back after the reading;


    //detect newline
    bool newline=false;
    int i;

    for(i=loaded_length-1;i>=0;i--){
      if(data[i]=='\n'){
        newline=true;
        i+=1;
        break;
      }
    }

    if(newline){
      int necessary_len=loaded_length-i;
      if(necessary_len==0){
        free(data);
        data=0;
        break;
      }

      char * newdata=(char *)malloc((necessary_len+1)*sizeof(char));
      memset(newdata,0,necessary_len+1);
      memcpy(newdata,data+i,necessary_len);
      free(data);
      data=newdata;
      newdata=0;
      loaded_length=necessary_len;

    }
    total+=loaded_length;
    struct Linked_list * new_first = (struct Linked_list *) malloc(sizeof(struct Linked_list));
    new_first->next=first;
    first=new_first;
    new_first=0;
    first->data=data;
    data=0;
    first->data_len=loaded_length;

    if(total>500*1000){ //line too long.
      for(struct Linked_list* c=first;c!=0;){
        struct Linked_list * tmp;
        tmp=c;
        c=tmp->next;
        free(tmp->data);
        free(tmp);
      }
      return (char*)0;
    }
    if(loaded_length!=BUFSIZE){ //EOF or found newline -> we have loaded the whole last line.
      break;
    }

  }
  //move the data from linked list to one place in memory.
  size_t total_size=0;
  for(struct Linked_list* c=first;c!=0;c=c->next){
    total_size+=c->data_len;
  }


  char * output=(char *)malloc((total_size+1)*sizeof(char));
  memset(output,0,(total_size+1)*sizeof(char));

  char *ptr=output;

  for(struct Linked_list* c=first;c!=0;){
    memcpy(ptr,c->data,c->data_len);
    ptr+=c->data_len;
    //cleanup
    struct Linked_list * tmp;
    tmp=c;
    c=tmp->next;
    free(tmp->data);
    free(tmp);
  }
  ptr=0;
  fclose(fp);
  return output;
}



static void initialize(struct context *context) {
/*	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	// We would initialize with {} to zero everything, but iso C doesn't seem to allow that.
	*context->user_data = (struct user_data) {
		.timestamp = 0
	};*/
}

static void communicate(struct context *context, const uint8_t *data, size_t length) {
	char * outdata=read_last_line("/tmp/ludus_output",true);
	if(outdata!=0){
		size_t len=strlen(outdata);
		uint8_t *me = mem_pool_alloc(context->temp_pool, len*sizeof(char));
		memcpy(me, outdata, len*sizeof(char));
		free(outdata);
		uplink_plugin_send_message(context, me,len*sizeof(char));
	}
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
		.version = 1
	};
	return &plugin;
}





















