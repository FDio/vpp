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
// TODO: GEE THIS SHOULD NOT BE CALLED ANYWHERE NEAR THE STATS SEGMENT... :-(

static u32
lookup_or_create_hash_index (void *oldheap, char *name, u32 next_vector_index)
{
  stats_main_t *sm = &stats_main;
  u32 index;

  hash_pair_t *hp;

  clib_mem_set_heap (oldheap);	/* Exit stats segment */

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

  /* Back to stats segment */
  clib_mem_set_heap (sm->heap);	/* Re-enter stat segment */
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
  if (!cm->name && !cm->stat_segment_name) {
    clib_mem_set_heap (oldheap);
    return;
  }

  ASSERT (shared_header);

  /* Lookup hash-table is on the main heap */
  stat_segment_name =
    cm->stat_segment_name ? cm->stat_segment_name : cm->name;
  u32 next_vector_index = vec_len (sm->directory_vector);
  u32 vector_index = lookup_or_create_hash_index (oldheap, stat_segment_name,
						  next_vector_index);

  vlib_stat_segment_lock ();

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
    ep->offset_vector ? stat_segment_pointer (shared_header, ep->offset_vector) : 0;

  /* Update the 2nd dimension offset vector */
  int i;
  vec_validate (offset_vector, vec_len (cm->counters) - 1);
  for (i = 0; i < vec_len (cm->counters); i++)
    offset_vector[i] = stat_segment_offset (shared_header, cm->counters[i]);
  ep->offset_vector = stat_segment_offset (shared_header, offset_vector);
  sm->directory_vector[vector_index].offset =
    stat_segment_offset (shared_header, cm->counters);

  /* Reset the client hash table pointer, since it WILL change! */
  shared_header->directory_offset = stat_segment_offset (shared_header, sm->directory_vector);

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
  shared_header->directory_offset = stat_segment_offset(shared_header, sm->directory_vector);

  vlib_stat_segment_unlock ();
}

void
vlib_stats_pop_heap2 (u64 * error_vector, u32 thread_index, void *oldheap)
{
  stats_main_t *sm = &stats_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;

  ASSERT (shared_header);

  vlib_stat_segment_lock ();

  /* Reset the client hash table pointer, since it WILL change! */
  shared_header->error_offset = stat_segment_offset (shared_header, error_vector);
  shared_header->directory_offset = stat_segment_offset (shared_header, sm->directory_vector);

  vlib_stat_segment_unlock ();
  clib_mem_set_heap(oldheap);
}

/*
 * Must be called on the statistics segment, with the locks set
 */
static void
stat_segment_register_counter_index(stat_directory_type_t t, char *name, u32 index)
{
  stats_main_t *sm = &stats_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  stat_segment_directory_entry_t e;

  vec_validate(sm->stats_vector, index);
  e.type = t;
  e.index = index;
  strncpy(e.name, name, 128-1);
  vec_add1 (sm->directory_vector, e);
  shared_header->stats_offset = stat_segment_offset (shared_header, sm->stats_vector);
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
  if ((mfd = memfd_create(mem_name, 0)) < 0)
    return clib_error_return(0, "stat segment memfd_create failure");

  printf("mmap fd: %d\n", mfd);

  /* Set size */
  if ((ftruncate (mfd, memory_size)) == -1)
    return clib_error_return(0, "stat segment ftruncate failure");

  if ((memaddr = mmap (NULL, memory_size, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0)) == MAP_FAILED)
    return clib_error_return(0, "stat segment mmap failure");

  void *heap;
  heap = create_mspace_with_base (((u8 *) memaddr) + getpagesize(), memory_size - getpagesize(), 1 /* locked */ );
  mspace_disable_expand (heap);

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

  /* Set up a few scalar stats */
  stat_segment_register_counter_index(STAT_DIR_TYPE_SCALAR_INDEX, "/sys/vector_rate", STAT_COUNTER_VECTOR_RATE);
  stat_segment_register_counter_index(STAT_DIR_TYPE_SCALAR_INDEX, "/sys/input_rate", STAT_COUNTER_INPUT_RATE);
  stat_segment_register_counter_index(STAT_DIR_TYPE_SCALAR_INDEX, "/sys/last_update", STAT_COUNTER_LAST_UPDATE);
  stat_segment_register_counter_index(STAT_DIR_TYPE_SCALAR_INDEX, "/sys/last_stats_clear", STAT_COUNTER_LAST_STATS_CLEAR);
  stat_segment_register_counter_index(STAT_DIR_TYPE_SCALAR_INDEX, "/sys/heartbeat", STAT_COUNTER_HEARTBEAT);

  /* Save the vector offset in the shared segment, for clients */
  shared_header->directory_offset = stat_segment_offset (shared_header, sm->directory_vector);

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

    case STAT_DIR_TYPE_SERIALIZED_NODES:
      type_name = "SerNodesPtr";
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
  stat_segment_shared_header_t *shared_header = sm->shared_header;
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
      ASSERT (shared_header);
      vlib_cli_output (vm, "%U", format_mheap, shared_header, 0 /* verbose */ );
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

#if 0
static inline void
update_serialized_nodes (stats_main_t * sm)
{
  int i;
  vlib_main_t *vm = vlib_mains[0];
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;
  void *oldheap;
  stat_segment_directory_entry_t *ep;
  hash_pair_t *hp;
  u8 *name_copy;

  ASSERT (ssvmp && ssvmp->sh);

  vec_reset_length (sm->serialized_nodes);

  shared_header = ssvmp->sh;

  oldheap = ssvm_push_heap (shared_header);

  vlib_stat_segment_lock ();
  vlib_node_get_nodes (0 /* vm, for barrier sync */ ,
		       (u32) ~ 0 /* all threads */ ,
		       1 /* include stats */ ,
		       0 /* barrier sync */ ,
		       &sm->node_dups, &sm->stat_vms);

  sm->serialized_nodes = vlib_node_serialize (vm, sm->node_dups,
					      sm->serialized_nodes,
					      0 /* include nexts */ ,
					      1 /* include stats */ );

  hp = hash_get_pair (sm->directory_vector_by_name, "serialized_nodes");
  if (hp)
    {
      name_copy = (u8 *) hp->key;
      ep = (stat_segment_directory_entry_t *) (hp->value[0]);

      if (stat_segment_pointer(shared_header, ep->offset) != sm->serialized_nodes)
	{
	  ep->offset = stat_segment_offset(shared_header, sm->serialized_nodes);
	  /* Warn clients to refresh any pointers they might be holding */
	  refresh_epoch (shared_header);
	}
    }
  else
    {
      name_copy = format (0, "%s%c", "serialized_nodes", 0);
      ep = clib_mem_alloc (sizeof (*ep));
      ep->type = STAT_DIR_TYPE_SERIALIZED_NODES;
      ep->offset = stat_segment_offset(shared_header, sm->serialized_nodes);
      hash_set_mem (sm->directory_vector_by_name, name_copy, ep);

      /* Warn clients to refresh any pointers they might be holding */
      refresh_epoch (shared_header);
    }

  vlib_stat_segment_unlock ();
  ssvm_pop_heap (oldheap);
}
#endif
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

  sm->stats_vector[STAT_COUNTER_VECTOR_RATE] = vector_rate / ((f64) (vec_len (vlib_mains) - start));

  /*
   * Compute the aggregate input rate
   */
  now = vlib_time_now (vm);
  dt = now - sm->stats_vector[STAT_COUNTER_LAST_UPDATE];
  input_packets = vnet_get_aggregate_rx_packets ();
  sm->stats_vector[STAT_COUNTER_INPUT_RATE] = (f64) (input_packets - sm->last_input_packets) / dt;
  sm->stats_vector[STAT_COUNTER_LAST_UPDATE] = now;
  sm->last_input_packets = input_packets;
  sm->stats_vector[STAT_COUNTER_LAST_STATS_CLEAR] = vm->node_main.time_last_runtime_stats_clear;

#if 0
  if (sm->serialize_nodes)
    update_serialized_nodes (sm);
#endif
  /* Heartbeat, so clients detect we're still here */
  sm->stats_vector[STAT_COUNTER_HEARTBEAT]++;
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
      else if (unformat (input, "serialize-nodes on"))
	sm->serialize_nodes = 1;
      else if (unformat (input, "serialize-nodes off"))
	sm->serialize_nodes = 0;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  return 0;
}

static clib_error_t *
test_stats_counters_command_fn (vlib_main_t * vm,
				unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 no_counters = 0;
  clib_error_t *error = 0;
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%d", &no_counters))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  break;
	}
    }

  vlib_simple_counter_main_t counter[no_counters];

  int i;

  for (i = 0; i < no_counters; i++) {
    memset(&counter[i], 0, sizeof(counter[i]));
    counter[i].name = format (0, "/test/counter-%d%c", i, 0);
    vlib_validate_simple_counter(&counter[i], 0);
    vlib_zero_simple_counter (&counter[i], 0);
    vlib_increment_simple_counter(&counter[i], 0, 0, i);
  }



  vlib_cli_output (vm, "Created %d counters\n", no_counters);
  //  vlib_zero_simple_counter (&mm->icmp_relayed, 0);

}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_stats_counters_command, static) = {
    .path = "test stats counters",
    .short_help = "create <n> counters",
    .function = test_stats_counters_command_fn,
};
/* *INDENT-ON* */


VLIB_EARLY_CONFIG_FUNCTION (statseg_config, "statseg");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
