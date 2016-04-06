/*
 *------------------------------------------------------------------
 * ioam_consumer
 * 
 * Copyright (c) 2010 by cisco Systems, Inc.  
 * All rights reserved. 
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <api/vpe_msg_enum.h>

#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vat/json_format.h>
#include "ioam_consumer.h"

#define f64_endian(a)
#define f64_print(a,b)

#define vl_typedefs             /* define message structures */
#include <api/vpe_all_api_h.h> 
#undef vl_typedefs

#define vl_endianfun             /* define message structures */
#include <api/vpe_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) 
#define vl_printfun
#include <api/vpe_all_api_h.h>
#undef vl_printfun

FILE *fp = NULL;

#include <vnet/ip/ip.h>

vl_shmem_hdr_t *shmem_hdr;

typedef struct {
  volatile int sigterm_received;
  int want_to_ioam_consumer_registered;
  u64 msgs_received;

  /* convenience */
  unix_shared_memory_queue_t * vl_input_queue;
  u32 my_client_index;
} test_main_t;

test_main_t test_main;

/* 
 * Satisfy external references when -lvlib is not available.
 */
void vlib_cli_output (struct vlib_main_t * vm, char * fmt, ...)
{
  clib_warning ("vlib_cli_output callled...");
}


static inline u8
fetch_trace_data_size(trace_type)
{
  u8 trace_data_size = 0;

  if (trace_type == TRACE_TYPE_IF_TS_APP)   
    trace_data_size = sizeof(ioam_trace_if_ts_app_t);
  else if(trace_type == TRACE_TYPE_IF)      
    trace_data_size = sizeof(ioam_trace_if_t);
  else if(trace_type == TRACE_TYPE_TS)      
    trace_data_size = sizeof(ioam_trace_ts_t);
  else if(trace_type == TRACE_TYPE_APP)     
    trace_data_size = sizeof(ioam_trace_app_t);
  else if(trace_type == TRACE_TYPE_TS_APP)  
    trace_data_size = sizeof(ioam_trace_ts_app_t);

  return trace_data_size;
}

static void json_format_ioam_data_list_element (vat_json_node_t *node, u32 *elt,
						u8 *trace_type_p)
{ 
  u8  trace_type = *trace_type_p;
  vat_json_node_t *trace_record = vat_json_object_add(node,"trace");

  vat_json_init_object(trace_record); 
  if (trace_type & BIT_TTL_NODEID)
    {
      u32 ttl_node_id_host_byte_order = clib_net_to_host_u32 (*elt);
      vat_json_object_add_uint(trace_record, "ttl", ttl_node_id_host_byte_order>>24);
      vat_json_object_add_uint(trace_record, "node-id",
			      ttl_node_id_host_byte_order & 0x00FFFFFF);
      elt++;
    }
 
  if (trace_type & BIT_ING_INTERFACE && trace_type & BIT_ING_INTERFACE)
    {
      vat_json_object_add_uint(trace_record, "ingress-if",  *elt >> 16);
      vat_json_object_add_uint(trace_record, "egress-id", *elt &0xFFFF);
      elt++;
    }
 
  if (trace_type & BIT_TIMESTAMP)
    {
      vat_json_object_add_uint(trace_record, "timestamp", clib_net_to_host_u32 (*elt));
      elt++;
    }
 
  if (trace_type & BIT_APPDATA)
    {
      vat_json_object_add_uint(trace_record, "app-data", clib_net_to_host_u32(*elt));
      elt++;
    }
 
}


static u8 * json_format_ip6_hop_by_hop_option (u8 * s, ip6_address_t  *flow_id,
					       ip6_hop_by_hop_option_t *opt0)
{
  ioam_trace_option_t * trace0;
  u8 trace_data_size_in_words = 0;
  u32 * elt0;
  int elt_index;
  u8 type0;
  vat_json_node_t node;

  vat_json_init_object(&node);

  vat_json_object_add_ip6(&node, "Flow-id", *(struct in6_addr *)flow_id);
  {
    type0 = opt0->type & HBH_OPTION_TYPE_MASK;
    elt_index = 0;
    switch (type0)
      {
      case HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST:
	trace0 = (ioam_trace_option_t *)opt0;
	trace_data_size_in_words = 
	  fetch_trace_data_size(trace0->ioam_trace_type)/4;
	elt0 = &trace0->elts[0];
	vat_json_node_t *trace = vat_json_object_add(&node, "trace-data");
        vat_json_init_object(trace);
	
	while ((u8 *) elt0 < 
	       ((u8 *)(&trace0->elts[0]) + trace0->hdr.length - 2 
		/* -2 accounts for ioam_trace_type,elts_left */))
	  {
	    json_format_ioam_data_list_element(trace, elt0, &trace0->ioam_trace_type);
	    elt_index++;
	    elt0 += trace_data_size_in_words;
	  }
	
	opt0 = (ip6_hop_by_hop_option_t *) 
	  (((u8 *)opt0) + opt0->length 
	   + sizeof (ip6_hop_by_hop_option_t));
	break;

      case HBH_OPTION_TYPE_IOAM_PROOF_OF_WORK:
	opt0 = (ip6_hop_by_hop_option_t *) 
	  (((u8 *)opt0) + sizeof (ioam_pow_option_t));
	break;
          
      case 0: /* Pad, just stop */
	opt0 = (ip6_hop_by_hop_option_t *) ((u8 *)opt0) + 1;
	break;

      default:
	opt0 = (ip6_hop_by_hop_option_t *) 
	  (((u8 *)opt0) + opt0->length 
	   + sizeof (ip6_hop_by_hop_option_t));
	break;
      }
  }
  vat_json_print(fp, &node);
  vat_json_free(&node);
  return s;
}

ioam_data_callback_t ioam_cb_active = NULL;
void *cb_user_data = NULL;

static void
vl_api_to_ioam_consumer_t_handler (
				   vl_api_to_ioam_consumer_t * mp)
{
  test_main_t * tm = &test_main;
  static u8 *sb;

  if (ioam_cb_active != NULL) {
    /* 
     * This is to export ioam_consumer as a library and provide callback with data to
     * a real consumer 
     */
    ioam_cb_active(IOAM_EVENT_FLOW_RECORD,
		   &mp->flow_id[0], mp->data_length + sizeof(mp->flow_id), cb_user_data);
  }
  tm->msgs_received++;
  if (fp != 0) {
      json_format_ip6_hop_by_hop_option(sb,
                                        (ip6_address_t  *)&mp->flow_id[0],
					(ip6_hop_by_hop_option_t *)&mp->data[0]);
  }    
}    

static void vl_api_want_to_ioam_consumer_reply_t_handler (
							  vl_api_want_to_netconf_server_reply_t *mp)
{
  test_main_t *tm = &test_main;
  int rv = ntohl(mp->retval);
  fformat (stdout, "want to_ioam_consumer reply %d %s\n", rv, 
	   rv >= 0?"All Set!":"Recvd regret");

  if (rv >= 0)
    tm->want_to_ioam_consumer_registered = 1;
}

#define vl_api_version(n,v) static u32 vpe_api_version = v;
#include <api/vpe.api.h>
#undef vl_api_version

void vl_client_add_api_signatures (vl_api_memclnt_create_t *mp)
{
  /*
   * Send the main API signature in slot 0. This bit of code must
   * match the checks in ../vpe/api/api.c: vl_msg_api_version_check().
   */
  mp->api_versions[0] = clib_host_to_net_u32 (vpe_api_version);
}
#define foreach_api_msg						\
  _(TO_IOAM_CONSUMER, to_ioam_consumer)				\
  _(WANT_TO_IOAM_CONSUMER_REPLY, want_to_ioam_consumer_reply)

test_main_t *ioam_consumer_init (void) 
{
  test_main_t * tm = &test_main;
  memset(tm, 0, sizeof(test_main_t));
  return tm;
}

void ioam_wait_for_messages (void)
{
  unix_shared_memory_queue_t *q;
  api_main_t *am = &api_main;
  test_main_t *tm = &test_main;
  uword msg;

  q = am->vl_input_queue;

  while (1) {
     /*
      * Retry a few times
      */
     int retries = 0, res;
     while ((res = unix_shared_memory_queue_sub(q, (u8 *)&msg, 1)) && retries++ < 10) {
       if (res == -1) {
           printf("Waiting for lock\n");
       }
     }
     if (res == 0) {
       vl_msg_api_handler((void *)msg);
     }
    if (tm->sigterm_received) break;
  }

}

int connect_to_vpe(char *name)
{
  int rv=0;
  api_main_t * am = &api_main;
  test_main_t * tm = &test_main;

  if (tm->want_to_ioam_consumer_registered) {
    return(rv);    
  }
     
  fformat (stdout,"\n Connecting to vpe \n");
  rv = vl_client_connect_to_vlib_no_rx_pthread("/vpe-api", name, 128);

#define _(N,n)						\
  vl_msg_api_set_handlers(VL_API_##N, #n,		\
			  vl_api_##n##_t_handler,	\
			  vl_noop_handler,		\
			  vl_api_##n##_t_endian,	\
			  vl_api_##n##_t_print,		\
			  sizeof(vl_api_##n##_t), 1); 
  foreach_api_msg;
#undef _

  shmem_hdr = api_main.shmem_hdr;
  if (rv == 0) {
    tm->vl_input_queue = shmem_hdr->vl_input_queue;
    tm->my_client_index = am->my_client_index;
  }
  return rv;
}

int disconnect_from_vpe(void)
{
  test_main_t * tm = &test_main;
  fformat (stdout,"\n disconnecting from vpe \n");
  vl_client_disconnect_from_vlib();
  tm->want_to_ioam_consumer_registered = 0;
  fformat (stdout,"\n disconnected from vpe \n");
  return 0;
}

static void sigterm_handler (int sig)
{
  test_main_t *tm = &test_main;
  tm->sigterm_received = 1;
}

void
want_to_ioam_consumer (test_main_t *tm, int enable_disable)
{
  vl_api_want_to_ioam_consumer_t * mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->_vl_msg_id = ntohs(VL_API_WANT_TO_IOAM_CONSUMER);
  mp->client_index = tm->my_client_index;
  mp->context = 0x0baddabe;
  mp->enable_disable = enable_disable;
  mp->pid = getpid();
  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *)&mp);
}


int main (int argc, char ** argv)
{
  api_main_t * am = &api_main;
  test_main_t * tm = &test_main;
  unformat_input_t _input, *input = &_input;
  clib_error_t * error = 0;
  char *file_name = NULL;
  int flow_enabled = 1;
   
  unformat_init_command_line (input, argv);
  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)  {
    if (unformat (input, "file-out %s", &file_name))
      ;
    else if (unformat (input, "trace %d", &flow_enabled))
      ;
    else {
      error = 
	clib_error_return 
	(0, "Usage: %s  [file-out file-name] [trace 0/1]\n", argv[0]);
      break;
    }
  }

  if (error) {
    clib_error_report (error);
    exit (1);
  }
  if (file_name) {
    fformat(stdout, "JSON data to be dumped into %s\n", file_name);
    fp = fopen(file_name,"w");
  }
  if (0 == connect_to_vpe("ioam_consumer")) {
    
    tm->vl_input_queue = shmem_hdr->vl_input_queue;
    tm->my_client_index = am->my_client_index;

    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);
    signal(SIGQUIT, sigterm_handler);
    
    fformat(stdout, "Send SIGINT or SIGTERM to quit...\n");
    if (flow_enabled)
      want_to_ioam_consumer(tm,1 /*enable*/);
               
    ioam_wait_for_messages();

  }
  fformat(stdout, "%lu trace messages received\n", tm->msgs_received);
  fformat(stdout, "Exiting...\n");
  
  if (flow_enabled) {
    want_to_ioam_consumer(tm, 0/*enable*/);
  }
  disconnect_from_vpe();
  if(fp) fclose(fp);
  exit (0);
}
