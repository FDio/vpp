/*
 * tracedump.c - skeleton vpp engine plug-in
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <tracedump/tracedump.h>
#include <vlib/trace.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <tracedump/tracedump.api_enum.h>
#include <tracedump/tracedump.api_types.h>

#define REPLY_MSG_ID_BASE tdmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

tracedump_main_t tracedump_main;

static int
trace_cmp (void *a1, void *a2)
{
  vlib_trace_header_t **t1 = a1;
  vlib_trace_header_t **t2 = a2;
  i64 dt = t1[0]->time - t2[0]->time;
  return dt < 0 ? -1 : (dt > 0 ? +1 : 0);
}

static void toss_client_cache (tracedump_main_t *tdmp, u32 client_index,
                               vlib_trace_header_t *** client_trace_cache)
{
  vlib_trace_header_t **th;
  int i;

  /* Across each vlib main... */
  for (i = 0; i < vec_len (client_trace_cache); i++)
    {
      th = client_trace_cache[i];
      /* Toss the thread's cached data */
      vec_free (th);
    }
  /* And toss the vector of threads */
  vec_free (client_trace_cache);
  tdmp->traces[client_index] = client_trace_cache;
  vec_reset_length (client_trace_cache);
}

/* API message handler */
static void vl_api_tracedump_t_handler
(vl_api_tracedump_t * mp)
{
  vl_api_registration_t *rp;
  vl_api_tracedump_reply_t * rmp;
  tracedump_main_t * tdmp = &tracedump_main;
  vlib_trace_header_t ***client_trace_cache, **th;
  int i, j;
  u32 client_index;
  u32 iterator_thread_id, iterator_position, max_records;
  u8 *s = 0;

  client_index = clib_net_to_host_u32 (mp->client_index);
  ASSERT (client_index < 1000);

  vec_validate_init_empty (tdmp->traces, client_index, 0);

  client_trace_cache = tdmp->traces[client_index];

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    {
      toss_client_cache (tdmp, client_index, client_trace_cache);
      return;
    }
  /* Clear the per-client cache if requested */
  if (mp->clear_cache)
    toss_client_cache (tdmp, client_index, client_trace_cache);

  /* Need a fresh cache for this client? */
  if (vec_len (client_trace_cache) == 0)
    {
      vlib_worker_thread_barrier_sync (&vlib_global_main);

      /* Make a slot for each worker thread */
      vec_validate (client_trace_cache, vec_len(vlib_mains)-1);
      i = 0;

      /* *INDENT-OFF* */
      foreach_vlib_main (
      ({
        vlib_trace_main_t *tm = &this_vlib_main->trace_main;

        /* Filter as directed */
        trace_apply_filter(this_vlib_main);

        pool_foreach (th, tm->trace_buffer_pool,
        ({
          vec_add1 (client_trace_cache[i], th[0]);
        }));

        /* Sort them by increasing time. */
        if (vec_len (client_trace_cache[i]))
          vec_sort_with_function (client_trace_cache[i], trace_cmp);

        i++;
      }));
      vlib_worker_thread_barrier_release (&vlib_global_main);
    }

  /* Save the cache, one way or the other */
  tdmp->traces[client_index] = client_trace_cache;

  /* Now, where were we? */
  iterator_thread_id = clib_net_to_host_u32 (mp->thread_id);
  iterator_position = clib_net_to_host_u32 (mp->position);
  max_records = clib_net_to_host_u32 (mp->max_records);

  for (i = iterator_thread_id; i < vec_len (client_trace_cache); i++)
    for (j = iterator_position; j < vec_len (client_trace_cache[i]); j++)
      {
        if (max_records == 0)
          break;

        th = vec_elt_at_index (client_trace_cache[i], j);

        s = format (s, "Packet %d\n%U\n\n", j + 1, format_vlib_trace,
                    vlib_mains[i], th);

        rmp = vl_msg_api_alloc (sizeof (*rmp)+vec_len(s));
        rmp->_vl_msg_id = htons(VL_API_TRACEDUMP_REPLY+(tdmp->msg_id_base));
        rmp->context = mp->context;
        rmp->retval = 0;
        rmp->thread_id = ntohl(i);
        rmp->position = ntohl(j);
        vl_api_vec_to_api_string (s, &rmp->trace_data);
        rmp->more = 0;
        if (PREDICT_TRUE(j < vec_len (client_trace_cache[i]) ||
                         i < vec_len (client_trace_cache)))
          rmp->more = 1;
        vl_api_send_msg (rp, (u8 *)rmp);
        max_records --;
      }
}

/* API definitions */
#include <tracedump/tracedump.api.c>

static clib_error_t * tracedump_init (vlib_main_t * vm)
{
  tracedump_main_t * tdmp = &tracedump_main;
  api_main_t *am = vlibapi_get_main();

  clib_error_t * error = 0;

  tdmp->vlib_main = vm;
  tdmp->vnet_main = vnet_get_main();

  /* Add our API messages to the global name_crc hash table */
  tdmp->msg_id_base = setup_message_id_table ();

  am->is_mp_safe[tdmp->msg_id_base + VL_API_TRACEDUMP] = 1;

  return error;
}

VLIB_INIT_FUNCTION (tracedump_init);
/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Streaming packet trace dump plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
