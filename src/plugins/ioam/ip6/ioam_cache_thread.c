/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
/*
 * ioam_cache_thread.c
 * Thread to cleanup ioam cache entries on timeout
 */
#include <vnet/api_errno.h>
#include <vppinfra/pool.h>
#include "ioam_cache.h"

static vlib_node_registration_t ioam_cache_cleanup_process_node;
#define TIMEOUT (20.0)
#define THREAD_PERIOD (10.0)

inline static void check_and_add (ioam_cache_ts_entry_t *ts_entry,
				  u32 pool_index,
				  u32 **vec_entries_expired,
                                  f64 now)
{
  if (ts_entry->created_at + IOAM_CACHE_TS_TIMEOUT <= now)
    {
      vec_add (*vec_entries_expired, &pool_index, 1);
    }
}

static uword
ioam_cache_cleanup_process (vlib_main_t * vm,
			    vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  f64 now;
  f64 timeout = 20.0;
  uword event_type;
  uword *event_data = 0;
  int i, j;
  ioam_cache_ts_entry_t *ts_entry = 0;
  u32 *vec_entries_expired = 0;
  u32 pool_index = 0;
  int no_of_threads = vec_len(vlib_worker_threads);

  cm->cleanup_process_node_index = ioam_cache_cleanup_process_node.index;
  /* Wait for Godot... */
  vlib_process_wait_for_event_or_clock (vm, 1e9);
  event_type = vlib_process_get_events (vm, &event_data);
  if (event_type != 1)
    clib_warning ("bogus kickoff event received, %d", event_type);
  vec_reset_length (event_data);

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type)
	{
	case 2:		/* Stop and Wait for kickoff again */
	  timeout = 1e9;
	  break;
	case 1:		/* kickoff : Check for unsent buffers */
	  timeout = THREAD_PERIOD;
	  break;
	case ~0:		/* timeout */
	  break;
	}
      vec_reset_length (event_data);
      for (i=0; i < no_of_threads; i++)
	{
	  now = vlib_time_now (vm);
	  vec_reset_length(vec_entries_expired);
	  vec_entries_expired = 0;
	  pool_foreach (ts_entry, cm->ioam_ts_pool[i],
			({
			  pool_index = ts_entry - cm->ioam_ts_pool[i];
			  check_and_add(ts_entry, pool_index,
					&vec_entries_expired, now);
			}));

	  if (vec_len(vec_entries_expired) != 0)
	    {
	      while (__sync_lock_test_and_set (cm->lockp_ts[i], 1))
		;
	      for (j=0; j < vec_len(vec_entries_expired); j++)
		{
		  if (pool_is_free_index(cm->ioam_ts_pool[i],
					 vec_entries_expired[j]))
		    continue; //To avoid Debug image assert failure
		  ioam_cache_ts_send(i, vec_entries_expired[j]);
		}
	      vec_free(vec_entries_expired);
	      *cm->lockp_ts[i] = 0;
	    }
	}
    }
  return 0;			/* not so much */
}

VLIB_REGISTER_NODE (ioam_cache_cleanup_process_node, static) =
{
 .function = ioam_cache_cleanup_process,
 .type = VLIB_NODE_TYPE_PROCESS,
 .name = "ioam-cache-cleanup-process",
};
