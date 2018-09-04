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
#include <vpp/stats/stats.h>
#undef HAVE_MEMFD_CREATE
#include <vppinfra/linux/syscall.h>

/*
 *  Used only by VPP writers
 */
void
vlib_stat_segment_lock (void)
{
  stats_main_t *sm = &stats_main;
  clib_spinlock_lock (sm->stat_segment_lockp);
  sm->shared_header->in_progress = 1;
}

void
vlib_stat_segment_unlock (void)
{
  stats_main_t *sm = &stats_main;
  sm->shared_header->epoch++;
  sm->shared_header->in_progress = 0;
  clib_spinlock_unlock (sm->stat_segment_lockp);
}

/*
 * Change heap to the stats shared memory segment
 */
void *
vlib_stats_push_heap (void)
{
  stats_main_t *sm = &stats_main;

  ASSERT (sm && sm->shared_header);
  return clib_mem_set_heap (sm->heap);
}

/* Name to vector index hash */
static u32
lookup_or_create_hash_index (void *oldheap, char *name, u32 next_vector_index)
{
  stats_main_t *sm = &stats_main;
  u32 index;
  hash_pair_t *hp;

  hp = hash_get_pair (sm->directory_vector_by_name, name);
  if (!hp)
    {
      hash_set (sm->directory_vector_by_name, name, next_vector_index);
      index = next_vector_index;
    }
  else
    {
      index = hp->value[0];
    }

  return index;
}

void
vlib_stats_pop_heap (void *cm_arg, void *oldheap, stat_directory_type_t type)
{
  vlib_simple_counter_main_t *cm = (vlib_simple_counter_main_t *) cm_arg;
  stats_main_t *sm = &stats_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  char *stat_segment_name;
  stat_segment_directory_entry_t e = { 0 };

  /* Not all counters have names / hash-table entries */
  if (!cm->name && !cm->stat_segment_name)
    {
      clib_mem_set_heap (oldheap);
      return;
    }

  ASSERT (shared_header);

  vlib_stat_segment_lock ();

  /* Lookup hash-table is on the main heap */
  stat_segment_name =
    cm->stat_segment_name ? cm->stat_segment_name : cm->name;
  u32 next_vector_index = vec_len (sm->directory_vector);
  clib_mem_set_heap (oldheap);	/* Exit stats segment */
  u32 vector_index = lookup_or_create_hash_index (oldheap, stat_segment_name,
						  next_vector_index);
  /* Back to stats segment */
  clib_mem_set_heap (sm->heap);	/* Re-enter stat segment */


  /* Update the vector */
  if (vector_index == next_vector_index)
    {				/* New */
      strncpy (e.name, stat_segment_name, 128 - 1);
      e.type = type;
      vec_add1 (sm->directory_vector, e);
      vector_index++;
    }

  stat_segment_directory_entry_t *ep = &sm->directory_vector[vector_index];
  ep->offset = stat_segment_offset (shared_header, cm->counters);	/* Vector of threads of vectors of counters */
  u64 *offset_vector =
    ep->offset_vector ? stat_segment_pointer (shared_header,
					      ep->offset_vector) : 0;

  /* Update the 2nd dimension offset vector */
  int i;
  vec_validate (offset_vector, vec_len (cm->counters) - 1);
  for (i = 0; i < vec_len (cm->counters); i++)
    offset_vector[i] = stat_segment_offset (shared_header, cm->counters[i]);
  ep->offset_vector = stat_segment_offset (shared_header, offset_vector);
  sm->directory_vector[vector_index].offset =
    stat_segment_offset (shared_header, cm->counters);

  /* Reset the client hash table pointer, since it WILL change! */
  shared_header->directory_offset =
    stat_segment_offset (shared_header, sm->directory_vector);

  vlib_stat_segment_unlock ();
  clib_mem_set_heap (oldheap);
}

void
vlib_stats_register_error_index (u8 * name, u64 * em_vec, u64 index)
{
  stats_main_t *sm = &stats_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  stat_segment_directory_entry_t e;
  hash_pair_t *hp;

  ASSERT (shared_header);

  vlib_stat_segment_lock ();

  memcpy (e.name, name, vec_len (name));
  e.name[vec_len (name)] = '\0';
  e.type = STAT_DIR_TYPE_ERROR_INDEX;
  e.offset = index;
  vec_add1 (sm->directory_vector, e);

  /* Warn clients to refresh any pointers they might be holding */
  shared_header->directory_offset =
    stat_segment_offset (shared_header, sm->directory_vector);

  vlib_stat_segment_unlock ();
}

static void
stat_validate_counter_vector (stat_segment_directory_entry_t * ep, u32 max)
{
  stats_main_t *sm = &stats_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  counter_t **counters = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int i;
  u64 *offset_vector = 0;

  vec_validate_aligned (counters, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  for (i = 0; i < tm->n_vlib_mains; i++)
    {
      vec_validate_aligned (counters[i], max, CLIB_CACHE_LINE_BYTES);
      vec_add1 (offset_vector,
		stat_segment_offset (shared_header, counters[i]));
    }
  ep->offset = stat_segment_offset (shared_header, counters);
  ep->offset_vector = stat_segment_offset (shared_header, offset_vector);
}

void
vlib_stats_pop_heap2 (u64 * error_vector, u32 thread_index, void *oldheap)
{
  stats_main_t *sm = &stats_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;

  ASSERT (shared_header);

  vlib_stat_segment_lock ();

  /* Reset the client hash table pointer, since it WILL change! */
  shared_header->error_offset =
    stat_segment_offset (shared_header, error_vector);
  shared_header->directory_offset =
    stat_segment_offset (shared_header, sm->directory_vector);

  vlib_stat_segment_unlock ();
  clib_mem_set_heap (oldheap);
}

clib_error_t *
vlib_map_stat_segment_init (void)
{
  stats_main_t *sm = &stats_main;
  stat_segment_shared_header_t *shared_header;
  stat_segment_directory_entry_t *ep;

  f64 *scalar_data;
  u8 *name;
  void *oldheap;
  u32 *lock;
  int rv;
  ssize_t memory_size;


  int mfd;
  char *mem_name = "stat_segment_test";
  void *memaddr;

  memory_size = sm->memory_size;
  if (memory_size == 0)
    memory_size = STAT_SEGMENT_DEFAULT_SIZE;

  /* Create shared memory segment */
  if ((mfd = memfd_create (mem_name, 0)) < 0)
    return clib_error_return (0, "stat segment memfd_create failure");

  /* Set size */
  if ((ftruncate (mfd, memory_size)) == -1)
    return clib_error_return (0, "stat segment ftruncate failure");

  if ((memaddr =
       mmap (NULL, memory_size, PROT_READ | PROT_WRITE, MAP_SHARED, mfd,
	     0)) == MAP_FAILED)
    return clib_error_return (0, "stat segment mmap failure");

  void *heap;
#if USE_DLMALLOC == 0
  heap = mheap_alloc_with_flags (((u8 *) memaddr) + getpagesize (),
				 memory_size - getpagesize (),
				 MHEAP_FLAG_DISABLE_VM |
				 MHEAP_FLAG_THREAD_SAFE);
#else
  heap =
    create_mspace_with_base (((u8 *) memaddr) + getpagesize (),
			     memory_size - getpagesize (), 1 /* locked */ );
  mspace_disable_expand (heap);
#endif

  sm->heap = heap;
  sm->memfd = mfd;

  sm->directory_vector_by_name = hash_create_string (0, sizeof (uword));
  sm->shared_header = shared_header = memaddr;
  sm->stat_segment_lockp = clib_mem_alloc (sizeof (clib_spinlock_t));
  clib_spinlock_init (sm->stat_segment_lockp);

  oldheap = clib_mem_set_heap (sm->heap);

  /* Set up the name to counter-vector hash table */
  sm->directory_vector = 0;

  shared_header->epoch = 1;

  /* Scalar stats and node counters */
  vec_validate (sm->directory_vector, STAT_COUNTERS - 1);
#define _(E,t,n,p)							\
  strcpy(sm->directory_vector[STAT_COUNTER_##E].name,  "/sys" #p "/" #n); \
  sm->directory_vector[STAT_COUNTER_##E].type = STAT_DIR_TYPE_##t;
  foreach_stat_segment_counter_name
#undef _
    /* Save the vector offset in the shared segment, for clients */
    shared_header->directory_offset =
    stat_segment_offset (shared_header, sm->directory_vector);

  clib_mem_set_heap (oldheap);

  return 0;
}

static int
name_sort_cmp (void *a1, void *a2)
{
  stat_segment_directory_entry_t *n1 = a1;
  stat_segment_directory_entry_t *n2 = a2;

  return strcmp ((char *) n1->name, (char *) n2->name);
}

static u8 *
format_stat_dir_entry (u8 * s, va_list * args)
{
  stat_segment_directory_entry_t *ep =
    va_arg (*args, stat_segment_directory_entry_t *);
  char *type_name;
  char *format_string;

  format_string = "%-74s %-10s %10lld";

  switch (ep->type)
    {
    case STAT_DIR_TYPE_SCALAR_INDEX:
      type_name = "ScalarPtr";
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      type_name = "CMainPtr";
      break;

    case STAT_DIR_TYPE_ERROR_INDEX:
      type_name = "ErrIndex";
      break;

    default:
      type_name = "illegal!";
      break;
    }

  return format (s, format_string, ep->name, type_name, ep->offset);
}

static clib_error_t *
show_stat_segment_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  stats_main_t *sm = &stats_main;
  counter_t *counter;
  hash_pair_t *p;
  stat_segment_directory_entry_t *show_data, *this;
  int i, j;

  int verbose = 0;
  u8 *s;

  if (unformat (input, "verbose"))
    verbose = 1;

  /* Lock even as reader, as this command doesn't handle epoch changes */
  vlib_stat_segment_lock ();
  show_data = vec_dup (sm->directory_vector);
  vlib_stat_segment_unlock ();

  vec_sort_with_function (show_data, name_sort_cmp);

  vlib_cli_output (vm, "%-74s %10s %10s", "Name", "Type", "Value");

  for (i = 0; i < vec_len (show_data); i++)
    {
      vlib_cli_output (vm, "%-100U", format_stat_dir_entry,
		       vec_elt_at_index (show_data, i));
    }

  if (verbose)
    {
      ASSERT (sm->heap);
      vlib_cli_output (vm, "%U", format_mheap, sm->heap, 0 /* verbose */ );
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_stat_segment_command, static) =
{
  .path = "show statistics segment",
  .short_help = "show statistics segment [verbose]",
  .function = show_stat_segment_command_fn,
};
/* *INDENT-ON* */

/*
 * Node performance counters:
 * total_calls [threads][node-index]
 * total_vectors
 * total_calls
 * total suspends
 */

static inline void
update_node_counters (stats_main_t * sm)
{
  vlib_main_t *vm = vlib_mains[0];
  vlib_main_t **stat_vms = 0;
  vlib_node_t ***node_dups = 0;
  int i, j;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  static u32 no_max_nodes = 0;

  vlib_node_get_nodes (0 /* vm, for barrier sync */ ,
		       (u32) ~ 0 /* all threads */ ,
		       1 /* include stats */ ,
		       0 /* barrier sync */ ,
		       &node_dups, &stat_vms);

  u32 l = vec_len (node_dups[0]);

  /*
   * Extend performance nodes if necessary
   */
  if (l > no_max_nodes)
    {
      void *oldheap = clib_mem_set_heap (sm->heap);
      vlib_stat_segment_lock ();

      stat_validate_counter_vector (&sm->directory_vector
				    [STAT_COUNTER_NODE_CLOCKS], l);
      stat_validate_counter_vector (&sm->directory_vector
				    [STAT_COUNTER_NODE_VECTORS], l);
      stat_validate_counter_vector (&sm->directory_vector
				    [STAT_COUNTER_NODE_CALLS], l);
      stat_validate_counter_vector (&sm->directory_vector
				    [STAT_COUNTER_NODE_SUSPENDS], l);

      vlib_stat_segment_unlock ();
      clib_mem_set_heap (oldheap);
      no_max_nodes = l;
    }

  for (j = 0; j < vec_len (node_dups); j++)
    {
      vlib_node_t **nodes = node_dups[j];
      u32 l = vec_len (nodes);

      for (i = 0; i < vec_len (nodes); i++)
	{
	  counter_t **counters;
	  counter_t *c;
	  vlib_node_t *n = nodes[i];

	  counters =
	    stat_segment_pointer (shared_header,
				  sm->directory_vector
				  [STAT_COUNTER_NODE_CLOCKS].offset);
	  c = counters[j];
	  c[n->index] = n->stats_total.clocks - n->stats_last_clear.clocks;

	  counters =
	    stat_segment_pointer (shared_header,
				  sm->directory_vector
				  [STAT_COUNTER_NODE_VECTORS].offset);
	  c = counters[j];
	  c[n->index] = n->stats_total.vectors - n->stats_last_clear.vectors;

	  counters =
	    stat_segment_pointer (shared_header,
				  sm->directory_vector
				  [STAT_COUNTER_NODE_CALLS].offset);
	  c = counters[j];
	  c[n->index] = n->stats_total.calls - n->stats_last_clear.calls;

	  counters =
	    stat_segment_pointer (shared_header,
				  sm->directory_vector
				  [STAT_COUNTER_NODE_SUSPENDS].offset);
	  c = counters[j];
	  c[n->index] =
	    n->stats_total.suspends - n->stats_last_clear.suspends;
	}
    }
}

/*
 * Called by stats_thread_fn, in stats.c, which runs in a
 * separate pthread, which won't halt the parade
 * in single-forwarding-core cases.
 */

void
do_stat_segment_updates (stats_main_t * sm)
{
  vlib_main_t *vm = vlib_mains[0];
  f64 vector_rate;
  u64 input_packets, last_input_packets;
  f64 dt, now;
  vlib_main_t *this_vlib_main;
  int i, start;

  /*
   * Compute the average vector rate across all workers
   */
  vector_rate = 0.0;

  start = vec_len (vlib_mains) > 1 ? 1 : 0;

  for (i = start; i < vec_len (vlib_mains); i++)
    {
      this_vlib_main = vlib_mains[i];
      vector_rate += vlib_last_vector_length_per_node (this_vlib_main);
    }
  vector_rate /= (f64) (i - start);

  sm->directory_vector[STAT_COUNTER_VECTOR_RATE].value =
    vector_rate / ((f64) (vec_len (vlib_mains) - start));

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

  /* Heartbeat, so clients detect we're still here */
  sm->directory_vector[STAT_COUNTER_HEARTBEAT].value++;
}

static clib_error_t *
statseg_config (vlib_main_t * vm, unformat_input_t * input)
{
  stats_main_t *sm = &stats_main;
  uword ms;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "size %U", unformat_memory_size, &sm->memory_size))
	;
      else if (unformat (input, "per-node-counters on"))
	sm->node_counters_enabled = 1;
      else if (unformat (input, "per-node-counters off"))
	sm->node_counters_enabled = 0;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (statseg_config, "statseg");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
