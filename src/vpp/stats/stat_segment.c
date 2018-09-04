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

#include <vpp/stats/stats.h>

void
vlib_stat_segment_lock (void)
{
  stats_main_t *sm = &stats_main;
  vlib_main_t *vm = vlib_get_main ();
  f64 deadman;

  /* 3ms is WAY long enough to be reasonably sure something is wrong */
  deadman = vlib_time_now (vm) + 3e-3;

  while (__sync_lock_test_and_set (&((*sm->stat_segment_lockp)->lock), 1))
    {
      if (vlib_time_now (vm) >= deadman)
	{
	  clib_warning ("BUG: stat segment lock held too long...");
	  break;
	}
    }
}

void
vlib_stat_segment_unlock (void)
{
  stats_main_t *sm = &stats_main;
  clib_spinlock_unlock (sm->stat_segment_lockp);
}

void *
vlib_stats_push_heap (void)
{
  stats_main_t *sm = &stats_main;
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;

  ASSERT (ssvmp && ssvmp->sh);

  shared_header = ssvmp->sh;

  return ssvm_push_heap (shared_header);
}

static u64
get_offset (void *start, void *data)
{
  return (char *) data - (char *) start;
}

static void *
get_pointer (void *start, u64 offset)
{
  return ((char *) start + offset);
}

/* Name to vector index hash */
static u32
lookup_or_create_hash_index (void *oldheap, char *name, u32 next_vector_index)
{
  stats_main_t *sm = &stats_main;
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;
  u32 index;
  ASSERT (ssvmp && ssvmp->sh);
  shared_header = ssvmp->sh;

  hash_pair_t *hp;

  ssvm_pop_heap (oldheap);	/* Exit stats segment */

  hp = hash_get_pair (sm->counter_vector_by_name, name);
  if (!hp)
    {
      hash_set (sm->counter_vector_by_name, name, next_vector_index);
      index = next_vector_index;
    }
  else
    {
      index = hp->value[0];
    }

  /* Back to stats segment */
  //oldheap = ssvm_push_heap (shared_header);
  ssvm_push_heap (shared_header);	/* Re-enter stat segment */
  return index;
}

static void
refresh_epoch (ssvm_shared_header_t * shared_header)
{
  shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH] = (void *)
    ((u64) shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH] + 1);
}

void
vlib_stats_pop_heap (void *cm_arg, void *oldheap, stat_directory_type_t type)
{
  vlib_simple_counter_main_t *cm = (vlib_simple_counter_main_t *) cm_arg;
  stats_main_t *sm = &stats_main;
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;
  char *stat_segment_name;
  stat_segment_directory_entry_t e = { 0 };

  /* Not all counters have names / hash-table entries */
  if (!cm->name && !cm->stat_segment_name)
    {
      ssvm_pop_heap (oldheap);
      return;
    }

  ASSERT (ssvmp && ssvmp->sh);
  shared_header = ssvmp->sh;

  /* Lookup hash-table is on the main heap */
  stat_segment_name =
    cm->stat_segment_name ? cm->stat_segment_name : cm->name;
  u32 next_vector_index = vec_len (sm->counter_vector);
  u32 vector_index = lookup_or_create_hash_index (oldheap, stat_segment_name,
						  next_vector_index);

  vlib_stat_segment_lock ();

  /* Update the vector */
  if (vector_index == next_vector_index)
    {				/* New */
      strncpy (e.name, stat_segment_name, 128 - 1);
      e.type = type;
      vec_add1 (sm->counter_vector, e);
      vector_index++;
    }

  stat_segment_directory_entry_t *ep = &sm->counter_vector[vector_index];
  ep->offset = get_offset (shared_header, cm->counters);	/* Vector of threads of vectors of counters */
  u64 *offset_vector =
    ep->offset_vector ? get_pointer (shared_header, ep->offset_vector) : 0;

  /* Update the 2nd dimension offset vector */
  int i;
  vec_validate (offset_vector, vec_len (cm->counters) - 1);
  for (i = 0; i < vec_len (cm->counters); i++)
    offset_vector[i] = get_offset (shared_header, cm->counters[i]);
  ep->offset_vector = get_offset (shared_header, offset_vector);
  sm->counter_vector[vector_index].offset =
    get_offset (shared_header, cm->counters);

  /* Reset the client hash table pointer, since it WILL change! */
  shared_header->opaque[STAT_SEGMENT_OPAQUE_OFFSET] =
    (void *) get_offset (shared_header, sm->counter_vector);

  /* Warn clients to refresh any pointers they might be holding */
  refresh_epoch (shared_header);

  vlib_stat_segment_unlock ();
  ssvm_pop_heap (oldheap);
}

void
vlib_stats_register_error_index (u8 * name, u64 * em_vec, u64 index)
{
  stats_main_t *sm = &stats_main;
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;
  stat_segment_directory_entry_t e;
  hash_pair_t *hp;

  ASSERT (ssvmp && ssvmp->sh);
  shared_header = ssvmp->sh;

  vlib_stat_segment_lock ();

  memcpy (e.name, name, vec_len (name));
  e.name[vec_len (name)] = '\0';
  e.type = STAT_DIR_TYPE_ERROR_INDEX;
  e.offset = index;
  vec_add1 (sm->counter_vector, e);

  /* Warn clients to refresh any pointers they might be holding */
  refresh_epoch (shared_header);

  vlib_stat_segment_unlock ();
}

void
vlib_stats_pop_heap2 (u64 * error_vector, u32 thread_index, void *oldheap)
{
  stats_main_t *sm = &stats_main;
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;

  ASSERT (ssvmp && ssvmp->sh);

  shared_header = ssvmp->sh;

  vlib_stat_segment_lock ();

  /* Reset the client hash table pointer, since it WILL change! */
  shared_header->opaque[STAT_SEGMENT_OPAQUE_ERROR_OFFSET] = (void *)
    get_offset (shared_header, error_vector);
  shared_header->opaque[STAT_SEGMENT_OPAQUE_OFFSET] = (void *)
    get_offset (shared_header, sm->counter_vector);
  /* Warn clients to refresh any pointers they might be holding */
  refresh_epoch (shared_header);

  vlib_stat_segment_unlock ();
  ssvm_pop_heap (oldheap);
}

clib_error_t *
vlib_map_stat_segment_init (void)
{
  stats_main_t *sm = &stats_main;
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;
  stat_segment_directory_entry_t *ep;
  f64 *scalar_data;
  u8 *name;
  void *oldheap;
  u32 *lock;
  int rv;
  u64 memory_size;

  memory_size = sm->memory_size;
  if (memory_size == 0)
    memory_size = STAT_SEGMENT_DEFAULT_SIZE;

  ssvmp->ssvm_size = memory_size;
  ssvmp->i_am_master = 1;
  ssvmp->my_pid = getpid ();
  ssvmp->name = format (0, "/stats%c", 0);
  ssvmp->requested_va = 0;

  rv = ssvm_master_init (ssvmp, SSVM_SEGMENT_MEMFD);

  if (rv)
    return clib_error_return (0, "stat segment ssvm init failure");
  shared_header = ssvmp->sh;

  oldheap = ssvm_push_heap (shared_header);

  /* Set up the name to counter-vector hash table */
  sm->counter_vector_by_name = hash_create_string (0, sizeof (uword));
  sm->counter_vector = 0;

  sm->stat_segment_lockp = clib_mem_alloc (sizeof (clib_spinlock_t));

  clib_spinlock_init (sm->stat_segment_lockp);
  shared_header->opaque[STAT_SEGMENT_OPAQUE_LOCK] =
    (void *) get_offset (shared_header, *sm->stat_segment_lockp);
  shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH] = (void *) 1;

  /* Set up a few scalar stats */

  scalar_data = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
					CLIB_CACHE_LINE_BYTES);
  sm->vector_rate_ptr = (scalar_data + 0);
  sm->input_rate_ptr = (scalar_data + 1);
  sm->last_runtime_ptr = (scalar_data + 2);
  sm->last_runtime_stats_clear_ptr = (scalar_data + 3);
  sm->heartbeat_ptr = (scalar_data + 4);

  stat_segment_directory_entry_t e;

  e.type = STAT_DIR_TYPE_SCALAR_POINTER;
  strcpy (e.name, "/sys/vector_rate");
  e.offset = get_offset (shared_header, sm->vector_rate_ptr);
  vec_add1 (sm->counter_vector, e);

  e.type = STAT_DIR_TYPE_SCALAR_POINTER;
  strcpy (e.name, "/sys/input_rate");
  e.offset = get_offset (shared_header, sm->input_rate_ptr);
  vec_add1 (sm->counter_vector, e);

  e.type = STAT_DIR_TYPE_SCALAR_POINTER;
  strcpy (e.name, "/sys/last_update");
  e.offset = get_offset (shared_header, sm->last_runtime_ptr);
  vec_add1 (sm->counter_vector, e);

  e.type = STAT_DIR_TYPE_SCALAR_POINTER;
  strcpy (e.name, "/sys/last_stats_clear");
  e.offset = get_offset (shared_header, sm->last_runtime_stats_clear_ptr);
  vec_add1 (sm->counter_vector, e);

  e.type = STAT_DIR_TYPE_SCALAR_POINTER;
  strcpy (e.name, "/sys/heartbeat");
  e.offset = get_offset (shared_header, sm->heartbeat_ptr);
  vec_add1 (sm->counter_vector, e);

  /* Save the vector offset in the shared segment, for clients */
  shared_header->opaque[STAT_SEGMENT_OPAQUE_OFFSET] =
    (void *) get_offset (shared_header, sm->counter_vector);

  ssvm_pop_heap (oldheap);

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
    case STAT_DIR_TYPE_SCALAR_POINTER:
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
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;
  counter_t *counter;
  hash_pair_t *p;
  stat_segment_directory_entry_t *show_data, *this;
  int i, j;

  int verbose = 0;
  u8 *s;

  if (unformat (input, "verbose"))
    verbose = 1;

  vlib_stat_segment_lock ();
  show_data = vec_dup (sm->counter_vector);
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
      ASSERT (ssvmp && ssvmp->sh);

      shared_header = ssvmp->sh;

      vlib_cli_output (vm, "%U", format_mheap,
		       shared_header->heap, 0 /* verbose */ );
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

static inline void
update_serialized_nodes (stats_main_t * sm)
{
#if 0

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

  hp = hash_get_pair (sm->counter_vector_by_name, "serialized_nodes");
  if (hp)
    {
      name_copy = (u8 *) hp->key;
      ep = (stat_segment_directory_entry_t *) (hp->value[0]);

      if (ep->value != sm->serialized_nodes)
	{
	  ep->value = sm->serialized_nodes;
	  /* Warn clients to refresh any pointers they might be holding */
	  refresh_epoch (shared_header);
	}
    }
  else
    {
      name_copy = format (0, "%s%c", "serialized_nodes", 0);
      ep = clib_mem_alloc (sizeof (*ep));
      ep->type = STAT_DIR_TYPE_SERIALIZED_NODES;
      ep->value = sm->serialized_nodes;
      hash_set_mem (sm->counter_vector_by_name, name_copy, ep);

      /* Warn clients to refresh any pointers they might be holding */
      refresh_epoch (shared_header);
    }

  vlib_stat_segment_unlock ();
  ssvm_pop_heap (oldheap);
#endif
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

  *sm->vector_rate_ptr = vector_rate / ((f64) (vec_len (vlib_mains) - start));

  /*
   * Compute the aggregate input rate
   */
  now = vlib_time_now (vm);
  dt = now - sm->last_runtime_ptr[0];
  input_packets = vnet_get_aggregate_rx_packets ();
  *sm->input_rate_ptr = (f64) (input_packets - sm->last_input_packets) / dt;
  sm->last_runtime_ptr[0] = now;
  sm->last_input_packets = input_packets;
  sm->last_runtime_stats_clear_ptr[0] =
    vm->node_main.time_last_runtime_stats_clear;

  if (sm->serialize_nodes)
    update_serialized_nodes (sm);

  /* Heartbeat, so clients detect we're still here */
  (*sm->heartbeat_ptr)++;
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

VLIB_EARLY_CONFIG_FUNCTION (statseg_config, "statseg");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
