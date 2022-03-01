/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vppinfra/mem.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include "stat_segment.h"
#include <vpp-api/client/stat_client.h>
#include <vnet/devices/devices.h>

#define STATSEG_MAX_NAMESZ 128

/*
 * Called from main heap
 */

/*
 * Creates a two dimensional vector with the maximum valid index specified in
 * both dimensions as arguments.
 * Must be called on the stat segment heap.
 */
static void
stat_validate_counter_vector2 (vlib_stats_directory_entry_t *ep, u32 max1,
			       u32 max2)
{
  counter_t **counters = ep->data;
  int i;
  vec_validate_aligned (counters, max1, CLIB_CACHE_LINE_BYTES);
  for (i = 0; i <= max1; i++)
    vec_validate_aligned (counters[i], max2, CLIB_CACHE_LINE_BYTES);

  ep->data = counters;
}

static void
stat_validate_counter_vector (vlib_stats_directory_entry_t *ep, u32 max)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  ASSERT (tm->n_vlib_mains > 0);
  stat_validate_counter_vector2 (ep, tm->n_vlib_mains, max);
}


clib_error_t *
vlib_map_stat_segment_init (void)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  vlib_stats_shared_header_t *shared_header;
  void *oldheap;
  uword memory_size, sys_page_sz;
  int mfd;
  char *mem_name = "stat segment";
  void *heap, *memaddr;

  memory_size = sm->memory_size;
  if (memory_size == 0)
    memory_size = STAT_SEGMENT_DEFAULT_SIZE;

  if (sm->log2_page_sz == CLIB_MEM_PAGE_SZ_UNKNOWN)
    sm->log2_page_sz = CLIB_MEM_PAGE_SZ_DEFAULT;

  mfd = clib_mem_vm_create_fd (sm->log2_page_sz, mem_name);

  if (mfd == -1)
    return clib_error_return (0, "stat segment memory fd failure: %U",
			      format_clib_error, clib_mem_get_last_error ());
  /* Set size */
  if ((ftruncate (mfd, memory_size)) == -1)
    {
      close (mfd);
      return clib_error_return (0, "stat segment ftruncate failure");
    }

  memaddr = clib_mem_vm_map_shared (0, memory_size, mfd, 0, mem_name);

  if (memaddr == CLIB_MEM_VM_MAP_FAILED)
    return clib_error_return (0, "stat segment mmap failure");

  sys_page_sz = clib_mem_get_page_size ();

  heap =
    clib_mem_create_heap (((u8 *) memaddr) + sys_page_sz,
			  memory_size - sys_page_sz, 1 /* locked */, mem_name);
  sm->heap = heap;
  sm->memfd = mfd;

  sm->directory_vector_by_name = hash_create_string (0, sizeof (uword));
  sm->shared_header = shared_header = memaddr;

  shared_header->version = STAT_SEGMENT_VERSION;
  shared_header->base = memaddr;

  sm->stat_segment_lockp = clib_mem_alloc (sizeof (clib_spinlock_t));
  clib_spinlock_init (sm->stat_segment_lockp);

  oldheap = clib_mem_set_heap (sm->heap);

  /* Set up the name to counter-vector hash table */
  sm->directory_vector = 0;

  shared_header->epoch = 1;

  /* Scalar stats and node counters */
  vec_validate (sm->directory_vector, STAT_COUNTERS - 1);
#define _(E,t,n,p)							\
  strcpy(sm->directory_vector[STAT_COUNTER_##E].name,  #p "/" #n); \
  sm->directory_vector[STAT_COUNTER_##E].type = STAT_DIR_TYPE_##t;
  foreach_stat_segment_counter_name
#undef _
    /* Save the vector in the shared segment, for clients */
    shared_header->directory_vector = sm->directory_vector;

  clib_mem_set_heap (oldheap);

  vlib_stats_register_mem_heap (heap);

  return 0;
}

/*
 * Node performance counters:
 * total_calls [threads][node-index]
 * total_vectors
 * total_calls
 * total suspends
 */

static inline void
update_node_counters (vlib_stats_segment_t *sm)
{
  vlib_main_t **stat_vms = 0;
  vlib_node_t ***node_dups = 0;
  int i, j;
  static u32 no_max_nodes = 0;

  vlib_node_get_nodes (0 /* vm, for barrier sync */,
		       (u32) ~0 /* all threads */, 1 /* include stats */,
		       0 /* barrier sync */, &node_dups, &stat_vms);

  u32 l = vec_len (node_dups[0]);
  u8 *symlink_name = 0;

  /*
   * Extend performance nodes if necessary
   */
  if (l > no_max_nodes)
    {
      void *oldheap = clib_mem_set_heap (sm->heap);
      vlib_stats_segment_lock ();

      stat_validate_counter_vector (
	&sm->directory_vector[STAT_COUNTER_NODE_CLOCKS], l - 1);
      stat_validate_counter_vector (
	&sm->directory_vector[STAT_COUNTER_NODE_VECTORS], l - 1);
      stat_validate_counter_vector (
	&sm->directory_vector[STAT_COUNTER_NODE_CALLS], l - 1);
      stat_validate_counter_vector (
	&sm->directory_vector[STAT_COUNTER_NODE_SUSPENDS], l - 1);

      vec_validate (sm->nodes, l - 1);
      vlib_stats_directory_entry_t *ep;
      ep = &sm->directory_vector[STAT_COUNTER_NODE_NAMES];
      ep->data = sm->nodes;

      /* Update names dictionary */
      vlib_node_t **nodes = node_dups[0];
      int i;
      for (i = 0; i < vec_len (nodes); i++)
	{
	  vlib_node_t *n = nodes[i];
	  u8 *s = format (0, "%v%c", n->name, 0);
	  if (sm->nodes[n->index])
	    vec_free (sm->nodes[n->index]);
	  sm->nodes[n->index] = s;

#define _(E, t, name, p)                                                      \
  vec_reset_length (symlink_name);                                            \
  symlink_name = format (symlink_name, "/nodes/%U/" #name "%c",               \
			 format_vlib_stats_symlink, s, 0);                    \
  vlib_stats_register_symlink (oldheap, symlink_name, STAT_COUNTER_##E,       \
			       n->index, 0 /* don't lock */);
	  foreach_stat_segment_node_counter_name
#undef _
	}

      vec_free (symlink_name);
      vlib_stats_segment_unlock ();
      clib_mem_set_heap (oldheap);
      no_max_nodes = l;
    }

  for (j = 0; j < vec_len (node_dups); j++)
    {
      vlib_node_t **nodes = node_dups[j];

      for (i = 0; i < vec_len (nodes); i++)
	{
	  counter_t **counters;
	  counter_t *c;
	  vlib_node_t *n = nodes[i];

	  if (j == 0)
	    {
	      if (strncmp ((char *) sm->nodes[n->index], (char *) n->name,
			   strlen ((char *) sm->nodes[n->index])))
		{
		  u32 vector_index;
		  u8 *symlink_new_name = 0;
		  void *oldheap = clib_mem_set_heap (sm->heap);
		  vlib_stats_segment_lock ();
		  u8 *s = format (0, "%v%c", n->name, 0);
#define _(E, t, name, p)                                                      \
  vec_reset_length (symlink_name);                                            \
  symlink_name = format (symlink_name, "/nodes/%U/" #name "%c",               \
			 format_vlib_stats_symlink, sm->nodes[n->index], 0);  \
  clib_mem_set_heap (oldheap); /* Exit stats segment */                       \
  vector_index = vlib_stats_find_directory_index ((u8 *) symlink_name);       \
  ASSERT (vector_index != -1);                                                \
  clib_mem_set_heap (sm->heap); /* Re-enter stat segment */                   \
  vec_reset_length (symlink_new_name);                                        \
  symlink_new_name = format (symlink_new_name, "/nodes/%U/" #name "%c",       \
			     format_vlib_stats_symlink, s, 0);                \
  vlib_stats_rename_symlink (oldheap, vector_index, symlink_new_name);
		  foreach_stat_segment_node_counter_name
#undef _
		    vec_free (symlink_name);
		  vec_free (symlink_new_name);
		  vec_free (sm->nodes[n->index]);
		  sm->nodes[n->index] = s;
		  vlib_stats_segment_unlock ();
		  clib_mem_set_heap (oldheap);
		}
	    }

	  counters = sm->directory_vector[STAT_COUNTER_NODE_CLOCKS].data;
	  c = counters[j];
	  c[n->index] = n->stats_total.clocks - n->stats_last_clear.clocks;

	  counters = sm->directory_vector[STAT_COUNTER_NODE_VECTORS].data;
	  c = counters[j];
	  c[n->index] = n->stats_total.vectors - n->stats_last_clear.vectors;

	  counters = sm->directory_vector[STAT_COUNTER_NODE_CALLS].data;
	  c = counters[j];
	  c[n->index] = n->stats_total.calls - n->stats_last_clear.calls;

	  counters = sm->directory_vector[STAT_COUNTER_NODE_SUSPENDS].data;
	  c = counters[j];
	  c[n->index] = n->stats_total.suspends - n->stats_last_clear.suspends;
	}
      vec_free (node_dups[j]);
    }
  vec_free (node_dups);
  vec_free (stat_vms);
}

static void
do_stat_segment_updates (vlib_main_t *vm, vlib_stats_segment_t *sm)
{
  u64 input_packets;
  f64 dt, now;
  static int num_worker_threads_set;

  /*
   * Set once at the beginning of time.
   * Can't do this from the init routine, which happens before
   * start_workers sets up vlib_mains...
   */
  if (PREDICT_FALSE (num_worker_threads_set == 0))
    {
      vlib_thread_main_t *tm = vlib_get_thread_main ();
      ASSERT (tm->n_vlib_mains > 0);
      stat_provider_register_vector_rate (tm->n_vlib_mains - 1);
      sm->directory_vector[STAT_COUNTER_NUM_WORKER_THREADS].value =
	tm->n_vlib_mains - 1;
      num_worker_threads_set = 1;
    }

  /*
   * Compute the aggregate input rate
   */
  now = vlib_time_now (vm);
  dt = now - sm->directory_vector[STAT_COUNTER_LAST_UPDATE].value;
  input_packets = vnet_get_aggregate_rx_packets ();
  sm->directory_vector[STAT_COUNTER_INPUT_RATE].value =
    (f64) (input_packets - sm->last_input_packets) / dt;
  sm->directory_vector[STAT_COUNTER_LAST_UPDATE].value = now;
  sm->last_input_packets = input_packets;
  sm->directory_vector[STAT_COUNTER_LAST_STATS_CLEAR].value =
    vm->node_main.time_last_runtime_stats_clear;

  if (sm->node_counters_enabled)
    update_node_counters (sm);

  stat_segment_gauges_pool_t *g;
  pool_foreach (g, sm->gauges)
    g->fn (&sm->directory_vector[g->directory_index], g->caller_index);

  /* Heartbeat, so clients detect we're still here */
  sm->directory_vector[STAT_COUNTER_HEARTBEAT].value++;
}

static uword
stat_segment_collector_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
				vlib_frame_t * f)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);

  while (1)
    {
      do_stat_segment_updates (vm, sm);
      vlib_process_suspend (vm, sm->update_interval);
    }
  return 0;			/* or not */
}

VLIB_REGISTER_NODE (stat_segment_collector, static) =
{
.function = stat_segment_collector_process,
.name = "statseg-collector-process",
.type = VLIB_NODE_TYPE_PROCESS,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
