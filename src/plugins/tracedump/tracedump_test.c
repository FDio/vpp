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

static void
vl_api_trace_details_t_handler (vl_api_trace_details_t * dmp)
{
  u32 thread_id, position;

  thread_id = clib_net_to_host_u32 (dmp->thread_id);
  position = clib_net_to_host_u32 (dmp->position);
  fformat
    (stdout,
     "thread %d position %d more_this_thread %d more_threads %d done %d\n",
     thread_id, position, (u32) dmp->more_this_thread,
     (u32) dmp->more_threads, (u32) dmp->done);
  fformat (stdout, "  %U\n", vl_api_format_string, (&dmp->trace_data));
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
