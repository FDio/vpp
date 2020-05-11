/*
 * tracedump.c - tracedump vpp-api-test plug-in
 *
 * Copyright (c) <current-year> <your-organization>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vnet/api_errno.h>
#include <stdbool.h>

#define __plugin_msg_base tracedump_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <tracedump/tracedump.api_enum.h>
#include <tracedump/tracedump.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} tracedump_test_main_t;

tracedump_test_main_t tracedump_test_main;


int
api_trace_set_filters (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_trace_set_filters_t *mp;
  u32 flag;
  u32 count;
  u32 node_index;
  u32 classifier;

  flag = TRACE_FF_NONE;
  count = 50;
  node_index = ~0;
  classifier = ~0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "none"))
	flag = TRACE_FF_NONE;
      else if (unformat (i, "include_node %u", &node_index))
	flag = TRACE_FF_INCLUDE_NODE;
      else if (unformat (i, "exclude_node %u", &node_index))
	flag = TRACE_FF_EXCLUDE_NODE;
      else if (unformat (i, "include_classifier %u", &classifier))
	flag = TRACE_FF_INCLUDE_CLASSIFIER;
      else if (unformat (i, "exclude_classifier %u", &classifier))
	flag = TRACE_FF_EXCLUDE_CLASSIFIER;
      else if (unformat (i, "count %u", &count))
	;
      else
	{
	  clib_warning ("Unknown input: %U\n", format_unformat_error, i);
	  return -99;
	}
    }

  M (TRACE_SET_FILTERS, mp);
  mp->flag = htonl (flag);
  mp->node_index = htonl (node_index);
  mp->count = htonl (count);
  mp->classifier_table_index = htonl (classifier);

  int ret = 0;
  S (mp);
  W (ret);

  return ret;
}


int
api_trace_capture_packets (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_trace_capture_packets_t *mp;
  u32 node_index;
  u32 max;
  bool pre_capture_clear;
  bool use_filter;
  bool verbose;

  node_index = ~0;
  max = 50;
  pre_capture_clear = use_filter = verbose = false;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "node_index %u", &node_index))
	;
      else if (unformat (i, "max %u", &max))
	;
      else if (unformat (i, "pre_capture_clear"))
	pre_capture_clear = false;
      else if (unformat (i, "use_filter"))
	use_filter = false;
      else if (unformat (i, "verbose"))
	verbose = false;
      else
	{
	  clib_warning ("Unknown input: %U\n", format_unformat_error, i);
	  return -99;
	}
    }

  M (TRACE_CAPTURE_PACKETS, mp);
  mp->node_index = htonl (node_index);
  mp->max_packets = htonl (max);
  mp->use_filter = use_filter;
  mp->verbose = verbose;
  mp->pre_capture_clear = pre_capture_clear;

  int ret = 0;
  S (mp);
  W (ret);

  return ret;
}


static void
vl_api_trace_details_t_handler (vl_api_trace_details_t * dmp)
{
  u32 packet_number;
  u32 thread_id, position;

  thread_id = clib_net_to_host_u32 (dmp->thread_id);
  position = clib_net_to_host_u32 (dmp->position);
  packet_number = clib_net_to_host_u32 (dmp->packet_number);
  fformat
    (stdout,
     "thread %d position %d more_this_thread %d more_threads %d done %d\n",
     thread_id, position, (u32) dmp->more_this_thread,
     (u32) dmp->more_threads, (u32) dmp->done);
  fformat (stdout, "Packet %d\n%U\n\n",
	   packet_number, vl_api_format_string, (&dmp->trace_data));
}


static void
vl_api_trace_dump_reply_t_handler (vl_api_trace_dump_reply_t * rmp)
{
  tracedump_test_main_t *ttm = &tracedump_test_main;
  vat_main_t *vam = ttm->vat_main;
  vl_api_trace_dump_t *mp;
  i32 retval = (i32) clib_net_to_host_u32 (rmp->retval);
  u32 thread_id, position;

  if (retval != 0 || rmp->done)
    {
      vam->result_ready = 1;
      vam->retval = retval;

      /* Clear the cache */
      if (retval == 0 && rmp->flush_only == 0)
	{
	  M (TRACE_DUMP, mp);
	  mp->clear_cache = 1;
	  mp->thread_id = 0xFFFFFFFF;
	  mp->position = 0xFFFFFFFF;
	  S (mp);
	}
      return;
    }

  /* Figure out where the next batch starts */
  thread_id = clib_host_to_net_u32 (rmp->last_thread_id);
  position = clib_host_to_net_u32 (rmp->last_position);

  if (rmp->more_threads)
    {
      position = 0;
      thread_id++;
    }
  else
    position++;

  M (TRACE_DUMP, mp);
  mp->clear_cache = 0;
  mp->thread_id = clib_host_to_net_u32 (thread_id);
  mp->position = clib_host_to_net_u32 (position);
  mp->max_records = clib_host_to_net_u32 (10);
  S (mp);
}

static int
api_trace_dump (vat_main_t * vam)
{
  vl_api_trace_dump_t *mp;
  int ret;

  M (TRACE_DUMP, mp);
  mp->clear_cache = 1;
  mp->thread_id = 0;
  mp->position = 0;
  mp->max_records = clib_host_to_net_u32 (10);

  S (mp);

  W (ret);
  return ret;
}

int
api_trace_clear_capture (vat_main_t * vam)
{
  vl_api_trace_clear_capture_t *mp;
  int ret;

  M (TRACE_CLEAR_CAPTURE, mp);
  S (mp);
  W (ret);
  return ret;
}




#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_endianfun
#include <tracedump/tracedump.api.h>
#undef vl_endianfun
#define vl_printfun
#include <tracedump/tracedump.api.h>
#undef vl_printfun

void
manual_setup_message_id_table (vat_main_t * vam)
{
  vl_msg_api_set_handlers (VL_API_TRACE_DETAILS
			   + tracedump_test_main.msg_id_base, "trace_details",
			   vl_api_trace_details_t_handler, vl_noop_handler,
			   vl_api_trace_details_t_endian,
			   vl_api_trace_details_t_print,
			   sizeof (vl_api_trace_details_t), 1);
}

#define VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE manual_setup_message_id_table
#define VL_API_TRACE_DUMP_REPLY_T_HANDLER

#include <tracedump/tracedump.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
