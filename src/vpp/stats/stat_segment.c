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
#include <vnet/vnet.h>
#include <vnet/devices/devices.h>	/* vnet_get_aggregate_rx_packets */
#undef HAVE_MEMFD_CREATE
#include <vppinfra/linux/syscall.h>
#include <vpp-api/client/stat_client.h>

stat_segment_main_t stat_segment_main;

/*
 *  Used only by VPP writers
 */
void
vlib_stat_segment_lock (void)
{
  stat_segment_main_t *sm = &stat_segment_main;
  clib_spinlock_lock (sm->stat_segment_lockp);
  sm->shared_header->in_progress = 1;
}

void
vlib_stat_segment_unlock (void)
{
  stat_segment_main_t *sm = &stat_segment_main;
  sm->shared_header->epoch++;
  sm->shared_header->in_progress = 0;
  clib_spinlock_unlock (sm->stat_segment_lockp);
}

/*
 * Change heap to the stats shared memory segment
 */
void *
vlib_stats_push_heap (void *old)
{
  stat_segment_main_t *sm = &stat_segment_main;

  sm->last = old;
  ASSERT (sm && sm->shared_header);
  return clib_mem_set_heap (sm->heap);
}

static u32
lookup_hash_index (u8 * name)
{
  stat_segment_main_t *sm = &stat_segment_main;
  u32 index = STAT_SEGMENT_INDEX_INVALID;
  hash_pair_t *hp;

  /* Must be called in the context of the main heap */
  ASSERT (clib_mem_get_heap () != sm->heap);

  hp = hash_get_pair (sm->directory_vector_by_name, name);
  if (hp)
    {
      index = hp->value[0];
    }

  return index;
}

static void
create_hash_index (u8 * name, u32 index)
{
  stat_segment_main_t *sm = &stat_segment_main;

  /* Must be called in the context of the main heap */
  ASSERT (clib_mem_get_heap () != sm->heap);

  hash_set (sm->directory_vector_by_name, format (0, "%s%c", name, 0), index);
}

static u32
vlib_stats_get_next_vector_index ()
{
  stat_segment_main_t *sm = &stat_segment_main;
  u32 next_vector_index = vec_len (sm->directory_vector);

  ssize_t i;
  vec_foreach_index_backwards (i, sm->directory_vector)
  {
    if (sm->directory_vector[i].type == STAT_DIR_TYPE_EMPTY)
      {
	next_vector_index = i;
	break;
      }
  }

  return next_vector_index;
}

static u32
vlib_stats_create_counter (stat_segment_directory_entry_t * e, void *oldheap)
{
  stat_segment_main_t *sm = &stat_segment_main;

  ASSERT (clib_mem_get_heap () == sm->heap);

  u32 index = vlib_stats_get_next_vector_index ();

  clib_mem_set_heap (oldheap);
  create_hash_index ((u8 *) e->name, index);
  clib_mem_set_heap (sm->heap);

  vec_validate (sm->directory_vector, index);
  sm->directory_vector[index] = *e;

  return index;
}

static void
vlib_stats_delete_counter (u32 index, void *oldheap)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_directory_entry_t *e;

  ASSERT (clib_mem_get_heap () == sm->heap);

  if (index > vec_len (sm->directory_vector))
    return;

  e = &sm->directory_vector[index];

  clib_mem_set_heap (oldheap);
  hash_unset (sm->directory_vector_by_name, &e->name);
  clib_mem_set_heap (sm->heap);

  memset (e, 0, sizeof (*e));
  e->type = STAT_DIR_TYPE_EMPTY;
}

/*
 * Called from main heap
 */
void
vlib_stats_delete_cm (void *cm_arg)
{
  vlib_simple_counter_main_t *cm = (vlib_simple_counter_main_t *) cm_arg;
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_directory_entry_t *e;

  /* Not all counters have names / hash-table entries */
  if (!cm->name && !cm->stat_segment_name)
    {
      return;
    }
  vlib_stat_segment_lock ();

  /* Lookup hash-table is on the main heap */
  char *stat_segment_name =
    cm->stat_segment_name ? cm->stat_segment_name : cm->name;
  u32 index = lookup_hash_index ((u8 *) stat_segment_name);

  e = &sm->directory_vector[index];
  hash_unset (sm->directory_vector_by_name, &e->name);

  void *oldheap = clib_mem_set_heap (sm->heap);	/* Enter stats segment */
  clib_mem_set_heap (oldheap);	/* Exit stats segment */

  memset (e, 0, sizeof (*e));
  e->type = STAT_DIR_TYPE_EMPTY;

  vlib_stat_segment_unlock ();
}

void
vlib_stats_pop_heap (void *cm_arg, void *oldheap, u32 cindex,
		     stat_directory_type_t type)
{
  vlib_simple_counter_main_t *cm = (vlib_simple_counter_main_t *) cm_arg;
  stat_segment_main_t *sm = &stat_segment_main;
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

  clib_mem_set_heap (oldheap);	/* Exit stats segment */
  u32 vector_index = lookup_hash_index ((u8 *) stat_segment_name);
  /* Back to stats segment */
  clib_mem_set_heap (sm->heap);	/* Re-enter stat segment */


  /* Update the vector */
  if (vector_index == STAT_SEGMENT_INDEX_INVALID)
    {				/* New */
      strncpy (e.name, stat_segment_name, 128 - 1);
      e.type = type;
      vector_index = vlib_stats_create_counter (&e, oldheap);
    }

  stat_segment_directory_entry_t *ep = &sm->directory_vector[vector_index];
  ep->data = cm->counters;

  /* Reset the client hash table pointer, since it WILL change! */
  shared_header->directory_vector = sm->directory_vector;

  vlib_stat_segment_unlock ();
  clib_mem_set_heap (oldheap);
}

void
vlib_stats_register_symlink (void *oldheap, u8 *name, u64 counter_index,
			     u64 index, u64 is_simple)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  stat_segment_directory_entry_t e;
  stat_segment_symlink_entry_t se;

  ASSERT (shared_header);

  clib_mem_set_heap (oldheap); /* Exit stats segment */
  u32 vector_index = lookup_hash_index (name);
  /* Back to stats segment */
  clib_mem_set_heap (sm->heap); /* Re-enter stat segment */

  if (vector_index == STAT_SEGMENT_INDEX_INVALID)
    {
      u64 symlink_index = vec_len (sm->symlink_vector);
      se.indexes[0] = counter_index;
      se.indexes[1] = index;
      vec_validate (sm->symlink_vector, symlink_index);
      sm->symlink_vector[symlink_index] = se;

      memcpy (e.name, name, vec_len (name));
      e.name[vec_len (name)] = '\0';
      e.type = is_simple ? STAT_DIR_TYPE_SYMLINK_SIMPLE :
			   STAT_DIR_TYPE_SYMLINK_COMBINED;
      e.index = symlink_index;
      vector_index = vlib_stats_create_counter (&e, oldheap);
    }
  else
    {
      /*In case we need to update the symlink*/
      stat_segment_directory_entry_t *entry =
	vec_elt_at_index (sm->directory_vector, vector_index);
      stat_segment_symlink_entry_t *symlink =
	vec_elt_at_index (sm->symlink_vector, entry->index);
      symlink->indexes[0] = counter_index;
      symlink->indexes[1] = index;
    }

  /* Warn clients to refresh any pointers they might be holding */
  shared_header->directory_vector = sm->directory_vector;
  shared_header->symlink_vector = sm->symlink_vector;
}

void
vlib_stats_register_error_index (void *oldheap, u8 * name, u64 * em_vec,
				 u64 index)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  stat_segment_directory_entry_t e;

  ASSERT (shared_header);

  vlib_stat_segment_lock ();
  clib_mem_set_heap (oldheap);	/* Exit stats segment */
  u32 vector_index = lookup_hash_index (name);
  /* Back to stats segment */
  clib_mem_set_heap (sm->heap);	/* Re-enter stat segment */

  if (vector_index == STAT_SEGMENT_INDEX_INVALID)
    {
      memcpy (e.name, name, vec_len (name));
      e.name[vec_len (name)] = '\0';
      e.type = STAT_DIR_TYPE_ERROR_INDEX;
      e.index = index;
      vector_index = vlib_stats_create_counter (&e, oldheap);

      /* Warn clients to refresh any pointers they might be holding */
      shared_header->directory_vector = sm->directory_vector;
    }

  vlib_stat_segment_unlock ();
}

static void
stat_validate_counter_vector (stat_segment_directory_entry_t * ep, u32 max)
{
  counter_t **counters = ep->data;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int i;

  vec_validate_aligned (counters, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  for (i = 0; i < tm->n_vlib_mains; i++)
    vec_validate_aligned (counters[i], max, CLIB_CACHE_LINE_BYTES);

  ep->data = counters;
}

always_inline void
stat_set_simple_counter (stat_segment_directory_entry_t * ep,
			 u32 thread_index, u32 index, u64 value)
{
  ASSERT (ep->data);
  counter_t **counters = ep->data;
  counter_t *cb = counters[thread_index];
  cb[index] = value;
}

void
vlib_stats_pop_heap2 (u64 * error_vector, u32 thread_index, void *oldheap,
		      int lock)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;

  ASSERT (shared_header);

  if (lock)
    vlib_stat_segment_lock ();

  /* Reset the client hash table pointer, since it WILL change! */
  vec_validate (sm->error_vector, thread_index);
  sm->error_vector[thread_index] = error_vector;

  shared_header->error_vector = sm->error_vector;
  shared_header->directory_vector = sm->directory_vector;

  if (lock)
    vlib_stat_segment_unlock ();
  clib_mem_set_heap (oldheap);
}

clib_error_t *
vlib_map_stat_segment_init (void)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_shared_header_t *shared_header;
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

  heap = clib_mem_create_heap (((u8 *) memaddr) + sys_page_sz, memory_size
			       - sys_page_sz, 1 /* locked */ ,
			       "stat segment");
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

  /* Total shared memory size */
  clib_mem_usage_t usage;
  clib_mem_get_heap_usage (sm->heap, &usage);
  sm->directory_vector[STAT_COUNTER_MEM_STATSEG_TOTAL].value =
    usage.bytes_total;

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

    case STAT_DIR_TYPE_NAME_VECTOR:
      type_name = "NameVector";
      break;

    case STAT_DIR_TYPE_EMPTY:
      type_name = "empty";
      break;

    default:
      type_name = "illegal!";
      break;
    }

  return format (s, format_string, ep->name, type_name, 0);
}

static clib_error_t *
show_stat_segment_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_directory_entry_t *show_data;
  int i;

  int verbose = 0;

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
      stat_segment_directory_entry_t *ep = vec_elt_at_index (show_data, i);

      if (ep->type == STAT_DIR_TYPE_EMPTY)
	continue;

      vlib_cli_output (vm, "%-100U", format_stat_dir_entry,
		       vec_elt_at_index (show_data, i));
    }

  if (verbose)
    {
      ASSERT (sm->heap);
      vlib_cli_output (vm, "%U", format_clib_mem_heap, sm->heap,
		       0 /* verbose */ );
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
update_node_counters (stat_segment_main_t * sm)
{
  vlib_main_t **stat_vms = 0;
  vlib_node_t ***node_dups = 0;
  int i, j;
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
				    [STAT_COUNTER_NODE_CLOCKS], l - 1);
      stat_validate_counter_vector (&sm->directory_vector
				    [STAT_COUNTER_NODE_VECTORS], l - 1);
      stat_validate_counter_vector (&sm->directory_vector
				    [STAT_COUNTER_NODE_CALLS], l - 1);
      stat_validate_counter_vector (&sm->directory_vector
				    [STAT_COUNTER_NODE_SUSPENDS], l - 1);

      vec_validate (sm->nodes, l - 1);
      stat_segment_directory_entry_t *ep;
      ep = &sm->directory_vector[STAT_COUNTER_NODE_NAMES];
      ep->data = sm->nodes;

      /* Update names dictionary */
      vlib_node_t **nodes = node_dups[0];
      int i;
      u8 *symlink_name = 0;
      for (i = 0; i < vec_len (nodes); i++)
	{
	  vlib_node_t *n = nodes[i];
	  u8 *s = 0;
	  s = format (s, "%v%c", n->name, 0);
	  if (sm->nodes[n->index])
	    vec_free (sm->nodes[n->index]);
	  sm->nodes[n->index] = s;

	  vec_reset_length (symlink_name);
	  symlink_name =
	    format (symlink_name, "/nodes/%v/clocks%c", n->name, 0);
	  vlib_stats_register_symlink (oldheap, symlink_name,
				       STAT_COUNTER_NODE_CLOCKS, n->index, 1);

	  vec_reset_length (symlink_name);
	  symlink_name =
	    format (symlink_name, "/nodes/%v/vectors%c", n->name, 0);
	  vlib_stats_register_symlink (oldheap, symlink_name,
				       STAT_COUNTER_NODE_VECTORS, n->index, 1);

	  vec_reset_length (symlink_name);
	  symlink_name =
	    format (symlink_name, "/nodes/%v/calls%c", n->name, 0);
	  vlib_stats_register_symlink (oldheap, symlink_name,
				       STAT_COUNTER_NODE_CALLS, n->index, 1);

	  vec_reset_length (symlink_name);
	  symlink_name =
	    format (symlink_name, "/nodes/%v/suspends%c", n->name, 0);
	  vlib_stats_register_symlink (
	    oldheap, symlink_name, STAT_COUNTER_NODE_SUSPENDS, n->index, 1);
	}
      vec_free (symlink_name);
      vlib_stat_segment_unlock ();
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
	  c[n->index] =
	    n->stats_total.suspends - n->stats_last_clear.suspends;
	}
      vec_free (node_dups[j]);
    }
  vec_free (node_dups);
  vec_free (stat_vms);
}

static void
do_stat_segment_updates (stat_segment_main_t * sm)
{
  vlib_main_t *vm = vlib_mains[0];
  f64 vector_rate;
  u64 input_packets;
  f64 dt, now;
  vlib_main_t *this_vlib_main;
  int i;
  static int num_worker_threads_set;

  /*
   * Set once at the beginning of time.
   * Can't do this from the init routine, which happens before
   * start_workers sets up vlib_mains...
   */
  if (PREDICT_FALSE (num_worker_threads_set == 0))
    {
      void *oldheap = clib_mem_set_heap (sm->heap);
      vlib_stat_segment_lock ();

      stat_validate_counter_vector (&sm->directory_vector
				    [STAT_COUNTER_VECTOR_RATE_PER_WORKER], 0);
      num_worker_threads_set = 1;
      vlib_stat_segment_unlock ();
      clib_mem_set_heap (oldheap);
    }

  /*
   * Compute per-worker vector rates, and the average vector rate
   * across all workers
   */
  vector_rate = 0.0;

  for (i = 0; i < vec_len (vlib_mains); i++)
    {

      f64 this_vector_rate;

      this_vlib_main = vlib_mains[i];

      this_vector_rate = vlib_internal_node_vector_rate (this_vlib_main);
      vlib_clear_internal_node_vector_rate (this_vlib_main);

      vector_rate += this_vector_rate;

      /* Set the per-worker rate */
      stat_set_simple_counter (&sm->directory_vector
			       [STAT_COUNTER_VECTOR_RATE_PER_WORKER], i, 0,
			       this_vector_rate);
    }

  /* And set the system average rate */
  vector_rate /= (f64) (i > 1 ? i - 1 : 1);

  sm->directory_vector[STAT_COUNTER_VECTOR_RATE].value = vector_rate;

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

  /* Stats segment memory heap counter */
  clib_mem_usage_t usage;
  clib_mem_get_heap_usage (sm->heap, &usage);
  sm->directory_vector[STAT_COUNTER_MEM_STATSEG_USED].value =
    usage.bytes_used;

  if (sm->node_counters_enabled)
    update_node_counters (sm);

  /* *INDENT-OFF* */
  stat_segment_gauges_pool_t *g;
  pool_foreach (g, sm->gauges)
   {
    g->fn(&sm->directory_vector[g->directory_index], g->caller_index);
  }
  /* *INDENT-ON* */

  /* Heartbeat, so clients detect we're still here */
  sm->directory_vector[STAT_COUNTER_HEARTBEAT].value++;
}

/*
 * Accept connection on the socket and exchange the fd for the shared
 * memory segment.
 */
static clib_error_t *
stats_socket_accept_ready (clib_file_t * uf)
{
  stat_segment_main_t *sm = &stat_segment_main;
  clib_error_t *err;
  clib_socket_t client = { 0 };

  err = clib_socket_accept (sm->socket, &client);
  if (err)
    {
      clib_error_report (err);
      return err;
    }

  /* Send the fd across and close */
  err = clib_socket_sendmsg (&client, 0, 0, &sm->memfd, 1);
  if (err)
    clib_error_report (err);
  clib_socket_close (&client);

  return 0;
}

static clib_error_t *
stats_segment_socket_init (void)
{
  stat_segment_main_t *sm = &stat_segment_main;
  clib_error_t *error;
  clib_socket_t *s = clib_mem_alloc (sizeof (clib_socket_t));

  memset (s, 0, sizeof (clib_socket_t));
  s->config = (char *) sm->socket_name;
  s->flags = CLIB_SOCKET_F_IS_SERVER | CLIB_SOCKET_F_SEQPACKET |
    CLIB_SOCKET_F_ALLOW_GROUP_WRITE | CLIB_SOCKET_F_PASSCRED;

  if ((error = clib_socket_init (s)))
    return error;

  clib_file_t template = { 0 };
  template.read_function = stats_socket_accept_ready;
  template.file_descriptor = s->fd;
  template.description = format (0, "stats segment listener %s", s->config);
  clib_file_add (&file_main, &template);

  sm->socket = s;

  return 0;
}

static clib_error_t *
stats_segment_socket_exit (vlib_main_t * vm)
{
  /*
   * cleanup the listener socket on exit.
   */
  stat_segment_main_t *sm = &stat_segment_main;
  unlink ((char *) sm->socket_name);
  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (stats_segment_socket_exit);

/* Overrides weak reference in vlib:node_cli.c */
f64
vlib_get_stat_segment_update_rate (void)
{
  return stat_segment_main.update_interval;
}

static uword
stat_segment_collector_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
				vlib_frame_t * f)
{
  stat_segment_main_t *sm = &stat_segment_main;

  while (1)
    {
      do_stat_segment_updates (sm);
      vlib_process_suspend (vm, sm->update_interval);
    }
  return 0;			/* or not */
}

static clib_error_t *
statseg_init (vlib_main_t * vm)
{
  stat_segment_main_t *sm = &stat_segment_main;

  /* set default socket file name when statseg config stanza is empty. */
  if (!vec_len (sm->socket_name))
    sm->socket_name = format (0, "%s/%s%c", vlib_unix_get_runtime_dir (),
			      STAT_SEGMENT_SOCKET_FILENAME, 0);
  return stats_segment_socket_init ();
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (statseg_init) =
{
  .runs_after = VLIB_INITS("unix_input_init"),
};
/* *INDENT-ON* */

clib_error_t *
stat_segment_register_gauge (u8 * name, stat_segment_update_fn update_fn,
			     u32 caller_index)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  void *oldheap;
  stat_segment_directory_entry_t e;
  stat_segment_gauges_pool_t *gauge;

  ASSERT (shared_header);

  u32 vector_index = lookup_hash_index (name);

  if (vector_index != STAT_SEGMENT_INDEX_INVALID)	/* Already registered */
    return clib_error_return (0, "%v is already registered", name);

  memset (&e, 0, sizeof (e));
  e.type = STAT_DIR_TYPE_SCALAR_INDEX;
  memcpy (e.name, name, vec_len (name));

  oldheap = vlib_stats_push_heap (NULL);
  vlib_stat_segment_lock ();
  vector_index = vlib_stats_create_counter (&e, oldheap);

  shared_header->directory_vector = sm->directory_vector;

  vlib_stat_segment_unlock ();
  clib_mem_set_heap (oldheap);

  /* Back on our own heap */
  pool_get (sm->gauges, gauge);
  gauge->fn = update_fn;
  gauge->caller_index = caller_index;
  gauge->directory_index = vector_index;

  return NULL;
}

clib_error_t *
stat_segment_register_state_counter (u8 * name, u32 * index)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  void *oldheap;
  stat_segment_directory_entry_t e;

  ASSERT (shared_header);
  ASSERT (vlib_get_thread_index () == 0);

  u32 vector_index = lookup_hash_index (name);

  if (vector_index != STAT_SEGMENT_INDEX_INVALID)	/* Already registered */
    return clib_error_return (0, "%v is already registered", name);

  memset (&e, 0, sizeof (e));
  e.type = STAT_DIR_TYPE_SCALAR_INDEX;
  memcpy (e.name, name, vec_len (name));

  oldheap = vlib_stats_push_heap (NULL);
  vlib_stat_segment_lock ();

  vector_index = vlib_stats_create_counter (&e, oldheap);

  shared_header->directory_vector = sm->directory_vector;

  vlib_stat_segment_unlock ();
  clib_mem_set_heap (oldheap);

  *index = vector_index;
  return 0;
}

clib_error_t *
stat_segment_deregister_state_counter (u32 index)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  stat_segment_directory_entry_t *e;
  void *oldheap;

  ASSERT (shared_header);

  if (index > vec_len (sm->directory_vector))
    return clib_error_return (0, "%u index does not exist", index);

  e = &sm->directory_vector[index];
  if (e->type != STAT_DIR_TYPE_SCALAR_INDEX)
    return clib_error_return (0, "%u index cannot be deleted", index);

  oldheap = vlib_stats_push_heap (NULL);
  vlib_stat_segment_lock ();

  vlib_stats_delete_counter (index, oldheap);

  vlib_stat_segment_unlock ();
  clib_mem_set_heap (oldheap);

  return 0;
}

void
stat_segment_set_state_counter (u32 index, u64 value)
{
  stat_segment_main_t *sm = &stat_segment_main;

  ASSERT (index < vec_len (sm->directory_vector));
  sm->directory_vector[index].index = value;
}

static clib_error_t *
statseg_config (vlib_main_t * vm, unformat_input_t * input)
{
  stat_segment_main_t *sm = &stat_segment_main;
  sm->update_interval = 10.0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "socket-name %s", &sm->socket_name))
	;
      /* DEPRECATE: default (does nothing) */
      else if (unformat (input, "default"))
	;
      else if (unformat (input, "size %U",
			 unformat_memory_size, &sm->memory_size))
	;
      else if (unformat (input, "page-size %U",
			 unformat_log2_page_size, &sm->log2_page_sz))
	;
      else if (unformat (input, "per-node-counters on"))
	sm->node_counters_enabled = 1;
      else if (unformat (input, "per-node-counters off"))
	sm->node_counters_enabled = 0;
      else if (unformat (input, "update-interval %f", &sm->update_interval))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  /*
   * NULL-terminate socket name string
   * clib_socket_init()->socket_config() use C str*
   */
  if (vec_len (sm->socket_name))
    vec_terminate_c_string (sm->socket_name);

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (statseg_config, "statseg");

static clib_error_t *
statseg_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  stat_segment_main_t *sm = &stat_segment_main;

  void *oldheap = vlib_stats_push_heap (sm->interfaces);
  vlib_stat_segment_lock ();

  vec_validate (sm->interfaces, sw_if_index);
  if (is_add)
    {
      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
      vnet_sw_interface_t *si_sup =
	vnet_get_sup_sw_interface (vnm, si->sw_if_index);
      vnet_hw_interface_t *hi_sup;
      u8 *s = 0;
      u8 *symlink_name = 0;
      u32 vector_index;

      ASSERT (si_sup->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
      hi_sup = vnet_get_hw_interface (vnm, si_sup->hw_if_index);

      s = format (s, "%v", hi_sup->name);
      if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	s = format (s, ".%d", si->sub.id);
      s = format (s, "%c", 0);
      sm->interfaces[sw_if_index] = s;
#define _(E, n, p)                                                            \
  clib_mem_set_heap (oldheap); /* Exit stats segment */                       \
  vector_index = lookup_hash_index ((u8 *) "/" #p "/" #n);                    \
  clib_mem_set_heap (sm->heap); /* Re-enter stat segment */                   \
  vec_reset_length (symlink_name);                                            \
  symlink_name = format (symlink_name, "/interfaces/%s/" #n "%c", s, 0);      \
  vlib_stats_register_symlink (oldheap, symlink_name, vector_index,           \
			       sw_if_index, 1);
      foreach_simple_interface_counter_name
#undef _
#define _(E, n, p)                                                            \
  clib_mem_set_heap (oldheap); /* Exit stats segment */                       \
  vector_index = lookup_hash_index ((u8 *) "/" #p "/" #n);                    \
  clib_mem_set_heap (sm->heap); /* Re-enter stat segment */                   \
  vec_reset_length (symlink_name);                                            \
  symlink_name = format (symlink_name, "/interfaces/%s/" #n "%c", s, 0);      \
  vlib_stats_register_symlink (oldheap, symlink_name, vector_index,           \
			       sw_if_index, 0);
	foreach_combined_interface_counter_name
#undef _
	  vec_free (symlink_name);
    }
  else
    {
      vec_free (sm->interfaces[sw_if_index]);
      sm->interfaces[sw_if_index] = 0;
    }

  stat_segment_directory_entry_t *ep;
  ep = &sm->directory_vector[STAT_COUNTER_INTERFACE_NAMES];
  ep->data = sm->interfaces;

  vlib_stat_segment_unlock ();
  clib_mem_set_heap (oldheap);

  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (statseg_sw_interface_add_del);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (stat_segment_collector, static) =
{
.function = stat_segment_collector_process,
.name = "statseg-collector-process",
.type = VLIB_NODE_TYPE_PROCESS,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
