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
vl_api_tracedump_reply_t_handler (vl_api_tracedump_reply_t * rmp)
{
  vat_main_t *vam = tracedump_test_main.vat_main;
  i32 retval = (i32) clib_net_to_host_u32 (rmp->retval);
  u32 thread_id, position;

  vam->async_errors += (retval < 0);

  if (retval == 0)
    {
      thread_id = clib_net_to_host_u32 (rmp->thread_id);
      position = clib_net_to_host_u32 (rmp->position);
      fformat (stdout,
	       "thread %d position %d more_this_thread %d more_threads %d done %d\n",
	       thread_id, position, (u32) rmp->more_this_thread,
	       (u32) rmp->more_threads, (u32) rmp->done);
      fformat (stdout, "  %U\n", vl_api_format_string, (&rmp->trace_data));

      if (rmp->more_this_thread || rmp->more_threads)
	{
	  vl_api_tracedump_t *mp;

	  M (TRACEDUMP, mp);
	  mp->clear_cache = 0;
	  mp->thread_id = clib_host_to_net_u32 (thread_id);
	  if (rmp->more_threads)
	    {
	      mp->thread_id = clib_host_to_net_u32 (thread_id + 1);
	      mp->position = 0;
	    }
	  else
	    mp->position = clib_host_to_net_u32 (position + 1);
	  mp->max_records = clib_host_to_net_u32 (10);

	  S (mp);
	  return;
	}
      /* Are we done, or more to come? */
      if (rmp->done == 1)
	vam->result_ready = 1;
    }
  else
    {
      vam->result_ready = 1;
      if (retval == VNET_API_ERROR_NO_SUCH_ENTRY)
	clib_warning ("No such entry");
    }
}


static int
api_tracedump (vat_main_t * vam)
{
  vl_api_tracedump_t *mp;
  int ret;

  M (TRACEDUMP, mp);
  mp->clear_cache = 1;
  mp->thread_id = 0;
  mp->position = 0;
  mp->max_records = clib_host_to_net_u32 (10);

  S (mp);

  W (ret);
  return ret;
}

/*
 * List of messages that the tracedump test plugin sends,
 * and that the data plane plugin processes
 */
#include <tracedump/tracedump.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
