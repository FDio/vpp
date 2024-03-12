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


static void
vl_api_trace_set_filters_t_handler (vl_api_trace_set_filters_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  tracedump_main_t *tdmp = &tracedump_main;
  u32 node_index = clib_net_to_host_u32 (mp->node_index);
  u32 flag = clib_net_to_host_u32 (mp->flag);
  u32 count = clib_net_to_host_u32 (mp->count);
  vl_api_trace_set_filters_reply_t *rmp;
  int rv = 0;

  if (flag == TRACE_FF_NONE)
    {
      count = node_index = 0;
    }
  else if (flag != TRACE_FF_INCLUDE_NODE && flag != TRACE_FF_EXCLUDE_NODE)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  vlib_node_t *node;
  node = vlib_get_node (vm, node_index);
  if (!node)
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE;
      goto done;
    }

  trace_filter_set (node_index, flag, count);

done:
  REPLY_MACRO (VL_API_TRACE_SET_FILTERS_REPLY);
}


static void
vl_api_trace_capture_packets_t_handler (vl_api_trace_capture_packets_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  tracedump_main_t *tdmp = &tracedump_main;
  u32 add = clib_net_to_host_u32 (mp->max_packets);
  u32 node_index = clib_net_to_host_u32 (mp->node_index);
  u8 filter = mp->use_filter;
  u8 verbose = mp->verbose;
  u8 pre_clear = mp->pre_capture_clear;
  vl_api_trace_capture_packets_reply_t *rmp;
  int rv = 0;

  if (!vnet_trace_placeholder)
    vec_validate_aligned (vnet_trace_placeholder, 2048,
			  CLIB_CACHE_LINE_BYTES);

  vlib_node_t *node;
  node = vlib_get_node (vm, node_index);
  if (!node)
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE;
      goto done;
    }

  if ((node->flags & VLIB_NODE_FLAG_TRACE_SUPPORTED) == 0)
    {
      /* FIXME: Make a new, better error like "UNSUPPORTED_NODE_OPERATION"? */
      rv = VNET_API_ERROR_NO_SUCH_NODE;
      goto done;
    }

  if (pre_clear)
    vlib_trace_stop_and_clear ();

  trace_update_capture_options (add, node_index, filter, verbose);

done:
  REPLY_MACRO (VL_API_TRACE_CAPTURE_PACKETS_REPLY);
}


static void
vl_api_trace_clear_capture_t_handler (vl_api_trace_clear_capture_t * mp)
{
  vl_api_trace_clear_capture_reply_t *rmp;
  tracedump_main_t *tdmp = &tracedump_main;

  vlib_trace_stop_and_clear ();

  int rv = 0;
  REPLY_MACRO (VL_API_TRACE_CLEAR_CAPTURE_REPLY);
}



static int
trace_cmp (void *a1, void *a2)
{
  vlib_trace_header_t **t1 = a1;
  vlib_trace_header_t **t2 = a2;
  i64 dt = t1[0]->time - t2[0]->time;
  return dt < 0 ? -1 : (dt > 0 ? +1 : 0);
}

static void
toss_client_cache (tracedump_main_t * tdmp, u32 client_index,
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
}

static clib_error_t *
tracedump_cache_reaper (u32 client_index)
{
  tracedump_main_t *tdmp = &tracedump_main;
  vlib_trace_header_t ***client_trace_cache;

  /* Its likely that we won't have a cache entry */
  if (client_index >= vec_len (tdmp->traces))
    return 0;

  client_trace_cache = tdmp->traces[client_index];
  toss_client_cache (tdmp, client_index, client_trace_cache);
  return 0;
}

VL_MSG_API_REAPER_FUNCTION (tracedump_cache_reaper);

/* API message handler */
static void
vl_api_trace_dump_t_handler (vl_api_trace_dump_t * mp)
{
  vl_api_registration_t *rp;
  vl_api_trace_dump_reply_t *rmp;
  vl_api_trace_details_t *dmp;
  tracedump_main_t *tdmp = &tracedump_main;
  vlib_trace_header_t ***client_trace_cache, **th;
  int i, j;
  u32 client_index;
  u32 iterator_thread_id, iterator_position, max_records;
  i32 retval = VNET_API_ERROR_NO_SUCH_ENTRY;
  u32 last_thread_id = ~0, last_position = ~0;
  u8 last_done = 0;
  u8 last_more_this_thread = 0;
  u8 last_more_threads = 0;
  u8 *s = 0;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  /* Use the registration pool index... */
  client_index = rp->vl_api_registration_pool_index;

  vec_validate_init_empty (tdmp->traces, client_index, 0);

  client_trace_cache = tdmp->traces[client_index];

  /* Clear the per-client cache if requested */
  if (mp->clear_cache)
    {
      toss_client_cache (tdmp, client_index, client_trace_cache);
      client_trace_cache = 0;
    }

  /* Now, where were we? */
  iterator_thread_id = clib_net_to_host_u32 (mp->thread_id);
  iterator_position = clib_net_to_host_u32 (mp->position);
  max_records = clib_net_to_host_u32 (mp->max_records);

  /* Don't overflow the existing queue space for shared memory API clients. */
  if (rp->vl_input_queue)
    {
      svm_queue_t *q = rp->vl_input_queue;
      u32 queue_slots_available = q->maxsize - q->cursize;
      int chunk = (queue_slots_available > 0) ? queue_slots_available - 1 : 0;
      if (chunk < max_records)
	max_records = chunk;
    }

  /* Need a fresh cache for this client? */
  if (vec_len (client_trace_cache) == 0
      && (iterator_thread_id != ~0 || iterator_position != ~0))
    {
      vlib_worker_thread_barrier_sync (vlib_get_first_main ());

      /* Make a slot for each worker thread */
      vec_validate (client_trace_cache, vlib_get_n_threads () - 1);
      i = 0;

      foreach_vlib_main ()
	{
	  vlib_trace_main_t *tm = &this_vlib_main->trace_main;

	  /* Filter as directed */
	  trace_apply_filter (this_vlib_main);

	  pool_foreach (th, tm->trace_buffer_pool)
	    {
	      vec_add1 (client_trace_cache[i], th[0]);
	    }

	  /* Sort them by increasing time. */
	  if (vec_len (client_trace_cache[i]))
	    vec_sort_with_function (client_trace_cache[i], trace_cmp);

	  i++;
	}
      vlib_worker_thread_barrier_release (vlib_get_first_main ());
    }

  /* Save the cache, one way or the other */
  tdmp->traces[client_index] = client_trace_cache;

  for (i = iterator_thread_id; i < vec_len (client_trace_cache); i++)
    {
      for (j = iterator_position; j < vec_len (client_trace_cache[i]); j++)
	{
	  if (max_records == 0)
	    break;

	  retval = 0;
	  th = &client_trace_cache[i][j];

	  vec_reset_length (s);

	  s =
	    format (s, "%U", format_vlib_trace, vlib_get_first_main (), th[0]);

	  dmp = vl_msg_api_alloc (sizeof (*dmp) + vec_len (s));
	  dmp->_vl_msg_id =
	    htons (VL_API_TRACE_DETAILS + (tdmp->msg_id_base));
	  dmp->context = mp->context;
	  last_thread_id = dmp->thread_id = ntohl (i);
	  last_position = dmp->position = ntohl (j);
	  vl_api_vec_to_api_string (s, &dmp->trace_data);
	  dmp->packet_number = htonl (j);
	  dmp->more_threads = 0;
	  dmp->more_this_thread = 0;

	  /* Last record in the batch? */
	  if (max_records == 1)
	    {
	      /* More threads, but not more in this thread? */
	      if (j == (vec_len (client_trace_cache[i]) - 1))
		last_more_threads = dmp->more_threads = 1;
	      else
		last_more_this_thread = dmp->more_this_thread = 1;
	    }
	  /* Done, may or may not be at the end of a batch. */
	  dmp->done = 0;
	  if (i == (vec_len (client_trace_cache) - 1) &&
	      j == (vec_len (client_trace_cache[i]) - 1))
	    {
	      last_done = dmp->done = 1;
	      last_more_threads = dmp->more_threads = 0;
	      last_more_this_thread = dmp->more_this_thread = 0;
	      vl_api_send_msg (rp, (u8 *) dmp);
	      goto doublebreak;
	    }
	  last_done = dmp->done;
	  vl_api_send_msg (rp, (u8 *) dmp);

	  max_records--;
	}
      iterator_position = 0;
    }

doublebreak:;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_TRACE_DUMP_REPLY + (tdmp->msg_id_base));
  rmp->context = mp->context;
  rmp->retval = clib_host_to_net_u32 (retval);
  rmp->last_thread_id = last_thread_id;
  rmp->last_position = last_position;
  rmp->done = last_done;
  rmp->more_this_thread = last_more_this_thread;
  rmp->more_threads = last_more_threads;

  /* Tag cleanup flushes to make life easy for the client */
  if (iterator_thread_id == ~0 && iterator_position == ~0)
    {
      rmp->retval = 0;
      rmp->done = 1;
      rmp->flush_only = 1;
    }
  vl_api_send_msg (rp, (u8 *) rmp);

  vec_free (s);
}

/* API message handler */
static void
vl_api_trace_v2_dump_t_handler (vl_api_trace_v2_dump_t *mp)
{
  vl_api_registration_t *rp;
  vl_api_trace_v2_details_t *dmp;
  tracedump_main_t *tdmp = &tracedump_main;
  vlib_trace_header_t ***client_trace_cache, **th;
  int i, j;
  u32 client_index;
  u32 first_position, max, first_thread_id, last_thread_id;
  u32 n_threads = vlib_get_n_threads ();
  u8 *s = 0;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  client_index = rp->vl_api_registration_pool_index;

  vec_validate_init_empty (tdmp->traces, client_index, 0);

  client_trace_cache = tdmp->traces[client_index];

  if (mp->clear_cache)
    {
      toss_client_cache (tdmp, client_index, client_trace_cache);
      client_trace_cache = 0;
    }

  /* Now, where were we? */
  first_thread_id = last_thread_id = clib_net_to_host_u32 (mp->thread_id);
  first_position = clib_net_to_host_u32 (mp->position);
  max = clib_net_to_host_u32 (mp->max);

  if (first_thread_id == ~0)
    {
      first_thread_id = 0;
      last_thread_id = n_threads - 1;
    }

  /* Don't overflow the existing queue space for shared memory API clients. */
  if (rp->vl_input_queue)
    {
      svm_queue_t *q = rp->vl_input_queue;
      u32 queue_slots_available = q->maxsize - q->cursize;
      int chunk = (queue_slots_available > 0) ? queue_slots_available - 1 : 0;
      /* split available slots among requested threads */
      if (chunk < max * (last_thread_id - first_thread_id + 1))
	max = chunk / (last_thread_id - first_thread_id + 1);
    }

  /* Need a fresh cache for this client? */
  if (vec_len (client_trace_cache) == 0 && first_position != ~0)
    {
      vlib_worker_thread_barrier_sync (vlib_get_first_main ());

      /* Make a slot for each worker thread */
      vec_validate (client_trace_cache, n_threads - 1);
      i = 0;

      foreach_vlib_main ()
	{
	  vlib_trace_main_t *tm = &this_vlib_main->trace_main;

	  /* Filter as directed */
	  trace_apply_filter (this_vlib_main);

	  pool_foreach (th, tm->trace_buffer_pool)
	    {
	      vec_add1 (client_trace_cache[i], th[0]);
	    }

	  /* Sort them by increasing time. */
	  if (vec_len (client_trace_cache[i]))
	    vec_sort_with_function (client_trace_cache[i], trace_cmp);

	  i++;
	}
      vlib_worker_thread_barrier_release (vlib_get_first_main ());
    }

  /* Save the cache, one way or the other */
  tdmp->traces[client_index] = client_trace_cache;

  for (i = first_thread_id;
       i <= last_thread_id && i < vec_len (client_trace_cache); i++)
    {
      // dump a number of 'max' packets per thead
      for (j = first_position;
	   j < vec_len (client_trace_cache[i]) && j < first_position + max;
	   j++)
	{
	  th = &client_trace_cache[i][j];

	  vec_reset_length (s);

	  s =
	    format (s, "%U", format_vlib_trace, vlib_get_first_main (), th[0]);

	  dmp = vl_msg_api_alloc (sizeof (*dmp) + vec_len (s));
	  dmp->_vl_msg_id =
	    htons (VL_API_TRACE_V2_DETAILS + (tdmp->msg_id_base));
	  dmp->context = mp->context;
	  dmp->thread_id = ntohl (i);
	  dmp->position = ntohl (j);
	  dmp->more = j < vec_len (client_trace_cache[i]) - 1;
	  vl_api_vec_to_api_string (s, &dmp->trace_data);

	  vl_api_send_msg (rp, (u8 *) dmp);
	}
    }

  vec_free (s);
}

static void
vl_api_trace_clear_cache_t_handler (vl_api_trace_clear_cache_t *mp)
{
  vl_api_registration_t *rp;
  tracedump_main_t *tdmp = &tracedump_main;
  vlib_trace_header_t ***client_trace_cache;
  vl_api_trace_clear_cache_reply_t *rmp;
  u32 client_index;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  client_index = rp->vl_api_registration_pool_index;
  vec_validate_init_empty (tdmp->traces, client_index, 0);
  client_trace_cache = tdmp->traces[client_index];
  toss_client_cache (tdmp, client_index, client_trace_cache);

  int rv = 0;
  REPLY_MACRO (VL_API_TRACE_CLEAR_CACHE_REPLY);
}

static void
vl_api_trace_set_filter_function_t_handler (
  vl_api_trace_set_filter_function_t *mp)
{
  vl_api_trace_set_filter_function_reply_t *rmp;
  tracedump_main_t *tdmp = &tracedump_main;
  unformat_input_t input = { 0 };
  vlib_is_packet_traced_fn_t *f;
  char *filter_name;
  int rv = 0;
  filter_name = vl_api_from_api_to_new_c_string (&mp->filter_function_name);
  unformat_init_cstring (&input, filter_name);
  if (unformat (&input, "%U", unformat_vlib_trace_filter_function, &f) == 0)
    {
      rv = -1;
      goto done;
    }
  vlib_set_trace_filter_function (f);
done:
  unformat_free (&input);
  vec_free (filter_name);
  REPLY_MACRO (VL_API_TRACE_SET_FILTER_FUNCTION_REPLY);
}

static void
vl_api_trace_filter_function_dump_t_handler (
  vl_api_trace_filter_function_dump_t *mp)
{
  vl_api_registration_t *rp;
  vl_api_trace_filter_function_details_t *dmp;
  tracedump_main_t *tdmp = &tracedump_main;
  vlib_trace_filter_main_t *tfm = &vlib_trace_filter_main;
  vlib_trace_filter_function_registration_t *reg =
    tfm->trace_filter_registration;
  vlib_main_t *vm = vlib_get_main ();
  vlib_is_packet_traced_fn_t *current =
    vm->trace_main.current_trace_filter_function;
  rp = vl_api_client_index_to_registration (mp->client_index);

  if (rp == 0)
    return;

  while (reg)
    {
      dmp = vl_msg_api_alloc (sizeof (*dmp) + strlen (reg->name));
      dmp->_vl_msg_id =
	htons (VL_API_TRACE_FILTER_FUNCTION_DETAILS + (tdmp->msg_id_base));
      dmp->context = mp->context;
      vl_api_c_string_to_api_string (reg->name, &dmp->name);
      dmp->selected = current == reg->function;
      vl_api_send_msg (rp, (u8 *) dmp);
      reg = reg->next;
    }
}

/* API definitions */
#include <tracedump/tracedump.api.c>

static clib_error_t *
tracedump_init (vlib_main_t * vm)
{
  tracedump_main_t *tdmp = &tracedump_main;
  api_main_t *am = vlibapi_get_main ();

  clib_error_t *error = 0;

  tdmp->vlib_main = vm;
  tdmp->vnet_main = vnet_get_main ();

  /* Add our API messages to the global name_crc hash table */
  tdmp->msg_id_base = setup_message_id_table ();

  vl_api_set_msg_thread_safe (am, tdmp->msg_id_base + VL_API_TRACE_DUMP, 1);
  vl_api_set_msg_thread_safe (am, tdmp->msg_id_base + VL_API_TRACE_V2_DUMP, 1);

  return error;
}

VLIB_INIT_FUNCTION (tracedump_init);
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Streaming packet trace dump plugin",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
