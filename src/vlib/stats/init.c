/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/file.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>

#define STAT_SEGMENT_SOCKET_FILENAME "stats.sock"

static u32 vlib_loops_stats_counter_index;

static void
vector_rate_collector_fn (vlib_stats_collector_data_t *d)
{
  vlib_main_t *this_vlib_main;
  counter_t **counters, **loops_counters;
  counter_t *cb, *loops_cb;
  f64 vector_rate = 0.0;
  u32 i, n_threads = vlib_get_n_threads ();

  vlib_stats_validate (d->entry_index, 0, n_threads - 1);
  counters = d->entry->data;
  cb = counters[0];

  vlib_stats_validate (vlib_loops_stats_counter_index, 0, n_threads - 1);
  loops_counters =
    vlib_stats_get_entry_data_pointer (vlib_loops_stats_counter_index);
  loops_cb = loops_counters[0];

  for (i = 0; i < n_threads; i++)
    {
      f64 this_vector_rate;
      this_vlib_main = vlib_get_main_by_index (i);

      this_vector_rate = vlib_internal_node_vector_rate (this_vlib_main);
      vlib_clear_internal_node_vector_rate (this_vlib_main);
      cb[i] = this_vector_rate;
      vector_rate += this_vector_rate;

      loops_cb[i] = this_vlib_main->loops_per_second;
    }

  /* And set the system average rate */
  vector_rate /= (f64) (i > 1 ? i - 1 : 1);
  vlib_stats_set_gauge (d->private_data, vector_rate);
}

clib_error_t *
vlib_stats_init (vlib_main_t *vm)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_shared_header_t *shared_header;
  vlib_stats_collector_reg_t reg = {};

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
  sm->locking_thread_index = ~0;
  sm->n_locks = 0;
  clib_spinlock_init (sm->stat_segment_lockp);

  /* Set up the name to counter-vector hash table */
  sm->directory_vector =
    vec_new_heap (typeof (sm->directory_vector[0]), STAT_COUNTERS, heap);
  sm->dir_vector_first_free_elt = CLIB_U32_MAX;

  shared_header->epoch = 1;

  /* Scalar stats and node counters */
#define _(E, t, n, p)                                                         \
  strcpy (sm->directory_vector[STAT_COUNTER_##E].name, p "/" #n);             \
  sm->directory_vector[STAT_COUNTER_##E].type = STAT_DIR_TYPE_##t;
  foreach_stat_segment_counter_name
#undef _
    /* Save the vector in the shared segment, for clients */
    shared_header->directory_vector = sm->directory_vector;

  vlib_stats_register_mem_heap (heap);

  reg.collect_fn = vector_rate_collector_fn;
  reg.private_data = vlib_stats_add_gauge ("/sys/vector_rate");
  reg.entry_index =
    vlib_stats_add_counter_vector ("/sys/vector_rate_per_worker");
  vlib_loops_stats_counter_index =
    vlib_stats_add_counter_vector ("/sys/loops_per_worker");
  vlib_stats_register_collector_fn (&reg);
  vlib_stats_validate (reg.entry_index, 0, vlib_get_n_threads ());
  vlib_stats_validate (vlib_loops_stats_counter_index, 0,
		       vlib_get_n_threads ());

  return 0;
}

static clib_error_t *
statseg_config (vlib_main_t *vm, unformat_input_t *input)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  sm->update_interval = 10.0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "socket-name %s", &sm->socket_name))
	;
      /* DEPRECATE: default (does nothing) */
      else if (unformat (input, "default"))
	;
      else if (unformat (input, "size %U", unformat_memory_size,
			 &sm->memory_size))
	;
      else if (unformat (input, "page-size %U", unformat_log2_page_size,
			 &sm->log2_page_sz))
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

/*
 * Accept connection on the socket and exchange the fd for the shared
 * memory segment.
 */
static clib_error_t *
stats_socket_accept_ready (clib_file_t *uf)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
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
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
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
stats_segment_socket_exit (vlib_main_t *vm)
{
  /*
   * cleanup the listener socket on exit.
   */
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  unlink ((char *) sm->socket_name);
  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (stats_segment_socket_exit);

static clib_error_t *
statseg_init (vlib_main_t *vm)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();

  /* set default socket file name when statseg config stanza is empty. */
  if (!vec_len (sm->socket_name))
    sm->socket_name = format (0, "%s/%s%c", vlib_unix_get_runtime_dir (),
			      STAT_SEGMENT_SOCKET_FILENAME, 0);
  return stats_segment_socket_init ();
}

VLIB_INIT_FUNCTION (statseg_init);
