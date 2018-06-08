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

void
vlib_stats_pop_heap (void *cm_arg, void *oldheap)
{
  vlib_simple_counter_main_t *cm = (vlib_simple_counter_main_t *) cm_arg;
  stats_main_t *sm = &stats_main;
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;
  char *stat_segment_name;
  stat_segment_directory_entry_t *ep;
  uword *p;

  ASSERT (ssvmp && ssvmp->sh);

  shared_header = ssvmp->sh;

  /* Not all counters have names / hash-table entries */
  if (cm->name || cm->stat_segment_name)
    {
      hash_pair_t *hp;
      u8 *name_copy;

      stat_segment_name = cm->stat_segment_name ?
	cm->stat_segment_name : cm->name;

      clib_spinlock_lock (sm->stat_segment_lockp);

      /* Update hash table. The name must be copied into the segment */
      hp = hash_get_pair (sm->counter_vector_by_name, stat_segment_name);
      if (hp)
	{
	  name_copy = (u8 *) hp->key;
	  ep = (stat_segment_directory_entry_t *) (hp->value[0]);
	  hash_unset_mem (sm->counter_vector_by_name, stat_segment_name);
	  vec_free (name_copy);
	  clib_mem_free (ep);
	}
      name_copy = format (0, "%s%c", stat_segment_name, 0);
      ep = clib_mem_alloc (sizeof (*ep));
      ep->type = STAT_DIR_TYPE_COUNTER_VECTOR;
      ep->value = cm->counters;
      hash_set_mem (sm->counter_vector_by_name, name_copy, ep);

      /* Reset the client hash table pointer, since it WILL change! */
      shared_header->opaque[STAT_SEGMENT_OPAQUE_DIR]
	= sm->counter_vector_by_name;

      /* Warn clients to refresh any pointers they might be holding */
      shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH] = (void *)
	((u64) shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH] + 1);
      clib_spinlock_unlock (sm->stat_segment_lockp);
    }
  ssvm_pop_heap (oldheap);
}

void
vlib_stats_register_error_index (u8 * name, u64 index)
{
  stats_main_t *sm = &stats_main;
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;
  stat_segment_directory_entry_t *ep;
  hash_pair_t *hp;
  u8 *name_copy;
  uword *p;

  ASSERT (ssvmp && ssvmp->sh);

  shared_header = ssvmp->sh;

  clib_spinlock_lock (sm->stat_segment_lockp);

  /* Update hash table. The name must be copied into the segment */
  hp = hash_get_pair (sm->counter_vector_by_name, name);
  if (hp)
    {
      name_copy = (u8 *) hp->key;
      ep = (stat_segment_directory_entry_t *) (hp->value[0]);
      hash_unset_mem (sm->counter_vector_by_name, name);
      vec_free (name_copy);
      clib_mem_free (ep);
    }

  ep = clib_mem_alloc (sizeof (*ep));
  ep->type = STAT_DIR_TYPE_ERROR_INDEX;
  ep->value = (void *) index;

  hash_set_mem (sm->counter_vector_by_name, name, ep);

  /* Reset the client hash table pointer, since it WILL change! */
  shared_header->opaque[STAT_SEGMENT_OPAQUE_DIR] = sm->counter_vector_by_name;

  /* Warn clients to refresh any pointers they might be holding */
  shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH] = (void *)
    ((u64) shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH] + 1);
  clib_spinlock_unlock (sm->stat_segment_lockp);
}

void
vlib_stats_pop_heap2 (u64 * counter_vector, u32 thread_index, void *oldheap)
{
  stats_main_t *sm = &stats_main;
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;
  stat_segment_directory_entry_t *ep;
  hash_pair_t *hp;
  u8 *error_vector_name;
  u8 *name_copy;
  uword *p;

  ASSERT (ssvmp && ssvmp->sh);

  shared_header = ssvmp->sh;

  clib_spinlock_lock (sm->stat_segment_lockp);

  error_vector_name = format (0, "/err/%d/counter_vector%c", thread_index, 0);

  /* Update hash table. The name must be copied into the segment */
  hp = hash_get_pair (sm->counter_vector_by_name, error_vector_name);
  if (hp)
    {
      name_copy = (u8 *) hp->key;
      ep = (stat_segment_directory_entry_t *) (hp->value[0]);
      hash_unset_mem (sm->counter_vector_by_name, error_vector_name);
      vec_free (name_copy);
      clib_mem_free (ep);
    }

  ep = clib_mem_alloc (sizeof (*ep));
  ep->type = STAT_DIR_TYPE_VECTOR_POINTER;
  ep->value = counter_vector;

  hash_set_mem (sm->counter_vector_by_name, error_vector_name, ep);

  /* Reset the client hash table pointer, since it WILL change! */
  shared_header->opaque[STAT_SEGMENT_OPAQUE_DIR] = sm->counter_vector_by_name;

  /* Warn clients to refresh any pointers they might be holding */
  shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH] = (void *)
    ((u64) shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH] + 1);
  clib_spinlock_unlock (sm->stat_segment_lockp);
  ssvm_pop_heap (oldheap);
}

static clib_error_t *
map_stat_segment_init (vlib_main_t * vm)
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

  ssvmp->ssvm_size = 32 << 20;	/*$$$$$ CONFIG PARAM */
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

  sm->stat_segment_lockp = clib_mem_alloc (sizeof (clib_spinlock_t));

  /* Save the hash table address in the shared segment, for clients */
  clib_spinlock_init (sm->stat_segment_lockp);
  shared_header->opaque[STAT_SEGMENT_OPAQUE_LOCK] = sm->stat_segment_lockp;
  shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH] = (void *) 1;

  /* Set up a few scalar stats */

  scalar_data = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
					CLIB_CACHE_LINE_BYTES);
  sm->vector_rate_ptr = (scalar_data + 0);
  sm->input_rate_ptr = (scalar_data + 1);

  name = format (0, "vector_rate%c", 0);
  ep = clib_mem_alloc (sizeof (*ep));
  ep->type = STAT_DIR_TYPE_SCALAR_POINTER;
  ep->value = sm->vector_rate_ptr;

  hash_set_mem (sm->counter_vector_by_name, name, ep);

  name = format (0, "input_rate%c", 0);
  ep = clib_mem_alloc (sizeof (*ep));
  ep->type = STAT_DIR_TYPE_SCALAR_POINTER;
  ep->value = sm->input_rate_ptr;

  hash_set_mem (sm->counter_vector_by_name, name, ep);

  /* Publish the hash table */
  shared_header->opaque[STAT_SEGMENT_OPAQUE_DIR] = sm->counter_vector_by_name;

  ssvm_pop_heap (oldheap);

  return 0;
}

VLIB_INIT_FUNCTION (map_stat_segment_init);

typedef struct
{
  u8 *name;
  stat_segment_directory_entry_t *dir_entry;
} show_stat_segment_t;

static int
name_sort_cmp (void *a1, void *a2)
{
  show_stat_segment_t *n1 = a1;
  show_stat_segment_t *n2 = a2;

  return strcmp ((char *) n1->name, (char *) n2->name);
}

static u8 *
format_stat_dir_entry (u8 * s, va_list * args)
{
  stat_segment_directory_entry_t *ep =
    va_arg (*args, stat_segment_directory_entry_t *);
  char *type_name;
  char *format_string;

  format_string = "%-10s %20llx";

  switch (ep->type)
    {
    case STAT_DIR_TYPE_SCALAR_POINTER:
      type_name = "ScalarPtr";
      break;

    case STAT_DIR_TYPE_VECTOR_POINTER:
      type_name = "VectorPtr";
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR:
      type_name = "CMainPtr";
      break;

    case STAT_DIR_TYPE_ERROR_INDEX:
      type_name = "ErrIndex";
      format_string = "%-10s %20lld";
      break;

    default:
      type_name = "illegal!";
      break;
    }

  return format (s, format_string, type_name, ep->value);
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
  show_stat_segment_t *show_data = 0;
  show_stat_segment_t *this;
  int i;

  int verbose = 0;
  u8 *s;

  if (unformat (input, "verbose"))
    verbose = 1;

  clib_spinlock_lock (sm->stat_segment_lockp);

  /* *INDENT-OFF* */
  hash_foreach_pair (p, sm->counter_vector_by_name,
  ({
    vec_add2 (show_data, this, 1);

    this->name = (u8 *) (p->key);
    this->dir_entry = (stat_segment_directory_entry_t *)(p->value[0]);
  }));
  /* *INDENT-ON* */

  clib_spinlock_unlock (sm->stat_segment_lockp);

  vec_sort_with_function (show_data, name_sort_cmp);

  vlib_cli_output (vm, "%-60s %10s %20s", "Name", "Type", "Value");

  for (i = 0; i < vec_len (show_data); i++)
    {
      this = vec_elt_at_index (show_data, i);

      vlib_cli_output (vm, "%-60s %31U",
		       this->name, format_stat_dir_entry, this->dir_entry);
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

static uword
stat_segment_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		      vlib_frame_t * f)
{
  f64 vector_rate;
  u64 input_packets, last_input_packets;
  f64 last_runtime, dt, now;
  vlib_main_t *this_vlib_main;
  stats_main_t *sm = &stats_main;

  last_runtime = 0.0;
  last_input_packets = 0;

  last_runtime = 0.0;
  last_input_packets = 0;

  while (1)
    {
      vlib_process_suspend (vm, 5.0);

      /*
       * Compute the average vector rate across all workers
       */
      vector_rate = 0.0;

      /* *INDENT-OFF* */
      foreach_vlib_main
      ({
        vector_rate += vlib_last_vector_length_per_node (vm);
      });
      /* *INDENT-ON* */

      *sm->vector_rate_ptr = vector_rate / ((f64) vec_len (vlib_mains));
      now = vlib_time_now (vm);
      dt = now - last_runtime;
      input_packets = vnet_get_aggregate_rx_packets ();
      *sm->input_rate_ptr = (f64) (input_packets - last_input_packets) / dt;
      last_runtime = now;
      last_input_packets = input_packets;
    }

  return 0;			/* not so much */
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (stat_segment_node,static) =
{
  .function = stat_segment_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "stat-segment-process",
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
