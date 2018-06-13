/*
 *------------------------------------------------------------------
 * api_format.c
 *
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
 *------------------------------------------------------------------
 */

#include <vpp/app/stat_client.h>

#include <vpp/api/vpe_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define endian fcns */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) fformat (handle, __VA_ARGS__)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

stat_client_main_t stat_client_main;

static void vl_api_map_stats_segment_reply_t_handler
  (vl_api_map_stats_segment_reply_t * mp)
{
  stat_client_main_t *sm = &stat_client_main;
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;
  socket_client_main_t *scm = sm->socket_client_main;
  int rv = ntohl (mp->retval);
  int my_fd, retval;
  clib_error_t *error;

  if (rv != 0)
    {
      fformat (stderr, "ERROR mapping stats segment: %d", rv);
      exit (1);
    }

  /*
   * Check the socket for the magic fd
   */
  error = vl_sock_api_recv_fd_msg (scm->socket_fd, &my_fd, 5);
  if (error)
    {
      clib_error_report (error);
      exit (1);
    }

  memset (ssvmp, 0, sizeof (*ssvmp));
  ssvmp->fd = my_fd;

  /* Note: this closes memfd.fd */
  retval = ssvm_slave_init_memfd (ssvmp);
  if (retval)
    {
      clib_warning ("WARNING: segment map returned %d", retval);
      exit (1);
    }

  fformat (stdout, "Stat segment mapped OK...\n");

  ASSERT (ssvmp && ssvmp->sh);

  /* Pick up the segment lock from the shared memory header */
  shared_header = ssvmp->sh;
  sm->stat_segment_lockp = (clib_spinlock_t *) (shared_header->opaque[0]);
  sm->segment_ready = 1;

  /* No need to keep the socket API connection open */
  close (sm->socket_client_main->socket_fd);
}

#define foreach_api_reply_msg \
_(MAP_STATS_SEGMENT_REPLY, map_stats_segment_reply)

static void
vpp_api_hookup (void)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,	        \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_api_reply_msg;
#undef _
}

static int
connect_to_vpp (stat_client_main_t * sm)
{
  int rv;
  vl_api_map_stats_segment_t *mp;
  api_main_t *am = &api_main;

  sm->socket_client_main = &socket_client_main;

  rv = vl_socket_client_connect ((char *) sm->socket_name,
				 "stat_client",
				 0 /* default socket rx, tx buffer */ );
  if (rv)
    {
      fformat (stderr, "Error connecting to vpp...\n");
      exit (1);
    }

  /* Hook up reply handler */
  vpp_api_hookup ();

  /* Map the stats segment */
  mp = vl_socket_client_msg_alloc (sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MAP_STATS_SEGMENT);
  mp->client_index = am->my_client_index;
  mp->context = 0xdeaddabe;

  /* Send the message */
  vl_socket_client_write ();

  /* Wait for a reply, process it.. */
  vl_socket_client_read (5 /* timeout in seconds */ );

  return 0;
}

#define foreach_cached_pointer                                          \
_(vector_rate, SCALAR_POINTER, &stat_client_main.vector_rate_ptr)       \
_(input_rate, SCALAR_POINTER, &stat_client_main.input_rate_ptr)         \
_(last_update, SCALAR_POINTER, &stat_client_main.last_runtime_ptr)      \
_(last_stats_clear, SCALAR_POINTER,                                     \
  &stat_client_main.last_runtime_stats_clear_ptr)                       \
_(rx, COUNTER_VECTOR, &stat_client_main.intfc_rx_counters)              \
_(tx, COUNTER_VECTOR, &stat_client_main.intfc_tx_counters)              \
_(/err/0/counter_vector, VECTOR_POINTER,                                \
  &stat_client_main.thread_0_error_counts)                              \
_(/err/IP4 source address matches local interface, ERROR_INDEX,         \
  &stat_client_main.source_address_match_error_index)                   \
_(serialized_nodes, SERIALIZED_NODES,                                   \
  &stat_client_main.serialized_nodes)

typedef struct
{
  char *name;
  stat_directory_type_t type;
  void *valuep;
} cached_pointer_t;

cached_pointer_t cached_pointers[] = {
#define _(n,t,p) {#n, STAT_DIR_TYPE_##t, (void *)p},
  foreach_cached_pointer
#undef _
};

static void
maybe_update_cached_pointers (stat_client_main_t * sm,
			      ssvm_shared_header_t * shared_header)
{
  uword *p, *counter_vector_by_name;
  int i;
  stat_segment_directory_entry_t *ep;
  cached_pointer_t *cp;
  u64 *valuep;

  /* Cached pointers OK? */
  if (sm->current_epoch ==
      (u64) shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH])
    return;

  fformat (stdout, "Updating cached pointers...\n");

  /* Nope, fix them... */
  counter_vector_by_name = (uword *)
    shared_header->opaque[STAT_SEGMENT_OPAQUE_DIR];

  for (i = 0; i < ARRAY_LEN (cached_pointers); i++)
    {
      cp = &cached_pointers[i];

      p = hash_get_mem (counter_vector_by_name, cp->name);

      if (p == 0)
	{
	  clib_warning ("WARN: %s not in directory!", cp->name);
	  continue;
	}
      ep = (stat_segment_directory_entry_t *) (p[0]);
      ASSERT (ep->type == cp->type);
      valuep = (u64 *) cp->valuep;
      *valuep = (u64) ep->value;
    }

  /* And remember that we did... */
  sm->current_epoch = (u64) shared_header->opaque[STAT_SEGMENT_OPAQUE_EPOCH];
}

static void
stat_poll_loop (stat_client_main_t * sm)
{
  struct timespec ts, tsrem;
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;
  vlib_counter_t *thread0_rx_counters = 0, *thread0_tx_counters = 0;
  vlib_node_t ***nodes_by_thread;
  vlib_node_t **nodes;
  vlib_node_t *n;
  f64 vector_rate, input_rate;
  u32 len;
  int i, j;
  u32 source_address_match_errors;

  /* Wait until the stats segment is mapped */
  while (!sm->segment_ready)
    {
      ts.tv_sec = 0;
      ts.tv_nsec = 100000000;
      while (nanosleep (&ts, &tsrem) < 0)
	ts = tsrem;
    }

  shared_header = ssvmp->sh;
  ASSERT (ssvmp->sh);

  while (1)
    {
      /* Scrape stats every 5 seconds */
      ts.tv_sec = 5;
      ts.tv_nsec = 0;
      while (nanosleep (&ts, &tsrem) < 0)
	ts = tsrem;

      vec_reset_length (thread0_rx_counters);
      vec_reset_length (thread0_tx_counters);

      /* Grab the stats segment lock */
      clib_spinlock_lock (sm->stat_segment_lockp);

      /* see if we need to update cached pointers */
      maybe_update_cached_pointers (sm, shared_header);

      ASSERT (sm->vector_rate_ptr);
      ASSERT (sm->intfc_rx_counters);
      ASSERT (sm->intfc_tx_counters);

      /* Read data from the segment */
      vector_rate = *sm->vector_rate_ptr;
      input_rate = *sm->input_rate_ptr;

      len = vec_len (sm->intfc_rx_counters[0]);

      ASSERT (len);

      vec_validate (thread0_rx_counters, len - 1);
      vec_validate (thread0_tx_counters, len - 1);

      clib_memcpy (thread0_rx_counters, sm->intfc_rx_counters[0],
		   len * sizeof (vlib_counter_t));
      clib_memcpy (thread0_tx_counters, sm->intfc_tx_counters[0],
		   len * sizeof (vlib_counter_t));

      source_address_match_errors =
	sm->thread_0_error_counts[sm->source_address_match_error_index];

      /* Drop the lock */
      clib_spinlock_unlock (sm->stat_segment_lockp);

      /* And print results... */

      fformat (stdout, "vector_rate %.2f input_rate %.2f\n",
	       vector_rate, input_rate);

      for (i = 0; i < vec_len (thread0_rx_counters); i++)
	{
	  fformat (stdout, "[%d]: %lld rx packets, %lld rx bytes\n",
		   i, thread0_rx_counters[i].packets,
		   thread0_rx_counters[i].bytes);
	  fformat (stdout, "[%d]: %lld tx packets, %lld tx bytes\n",
		   i, thread0_tx_counters[i].packets,
		   thread0_tx_counters[i].bytes);
	}

      fformat (stdout, "%lld source address match errors\n",
	       source_address_match_errors);

      if (sm->serialized_nodes)
	{
	  nodes_by_thread = vlib_node_unserialize (sm->serialized_nodes);

	  /* Across all threads... */
	  for (i = 0; i < vec_len (nodes_by_thread); i++)
	    {
	      u64 n_input, n_output, n_drop, n_punt;
	      u64 n_internal_vectors, n_internal_calls;
	      u64 n_clocks, l, v, c;
	      f64 dt;

	      nodes = nodes_by_thread[i];

	      fformat (stdout, "Thread %d -------------------------\n", i);

	      n_input = n_output = n_drop = n_punt = n_clocks = 0;
	      n_internal_vectors = n_internal_calls = 0;

	      /* Across all nodes */
	      for (j = 0; j < vec_len (nodes); j++)
		{
		  n = nodes[j];

		  /* Exactly stolen from node_cli.c... */
		  l = n->stats_total.clocks - n->stats_last_clear.clocks;
		  n_clocks += l;

		  v = n->stats_total.vectors - n->stats_last_clear.vectors;
		  c = n->stats_total.calls - n->stats_last_clear.calls;

		  switch (n->type)
		    {
		    default:
		      continue;

		    case VLIB_NODE_TYPE_INTERNAL:
		      n_output +=
			(n->flags & VLIB_NODE_FLAG_IS_OUTPUT) ? v : 0;
		      n_drop += (n->flags & VLIB_NODE_FLAG_IS_DROP) ? v : 0;
		      n_punt += (n->flags & VLIB_NODE_FLAG_IS_PUNT) ? v : 0;
		      if (!(n->flags & VLIB_NODE_FLAG_IS_OUTPUT))
			{
			  n_internal_vectors += v;
			  n_internal_calls += c;
			}
		      if (n->flags & VLIB_NODE_FLAG_IS_HANDOFF)
			n_input += v;
		      break;

		    case VLIB_NODE_TYPE_INPUT:
		      n_input += v;
		      break;
		    }

		  if (n->stats_total.calls)
		    {
		      fformat (stdout,
			       "%s (%s): clocks %lld calls %lld vectors %lld ",
			       n->name,
			       n->state_string,
			       n->stats_total.clocks,
			       n->stats_total.calls, n->stats_total.vectors);
		      if (n->stats_total.vectors)
			fformat (stdout, "clocks/pkt %.2f\n",
				 (f64) n->stats_total.clocks /
				 (f64) n->stats_total.vectors);
		      else
			fformat (stdout, "\n");
		    }
		  vec_free (n->name);
		  vec_free (n->next_nodes);
		  vec_free (n);
		}

	      fformat (stdout, "average vectors/node %.2f\n",
		       (n_internal_calls > 0
			? (f64) n_internal_vectors / (f64) n_internal_calls
			: 0));


	      dt = *sm->last_runtime_ptr - *sm->last_runtime_stats_clear_ptr;

	      fformat (stdout,
		       " vectors rates in %.4e, out %.4e, drop %.4e, "
		       "punt %.4e\n",
		       (f64) n_input / dt,
		       (f64) n_output / dt, (f64) n_drop / dt,
		       (f64) n_punt / dt);

	      vec_free (nodes);
	    }
	  vec_free (nodes_by_thread);
	}
      else
	{
	  fformat (stdout, "serialized nodes NULL?\n");
	}

    }
}


int
main (int argc, char **argv)
{
  unformat_input_t _argv, *a = &_argv;
  stat_client_main_t *sm = &stat_client_main;
  u8 *socket_name;
  int rv;

  clib_mem_init (0, 128 << 20);

  unformat_init_command_line (a, argv);

  socket_name = (u8 *) API_SOCKET_FILE;

  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (a, "socket-name %s", &socket_name))
	;
      else
	{
	  fformat (stderr, "%s: usage [socket-name <name>]\n", argv[0]);
	  exit (1);
	}
    }

  sm->socket_name = socket_name;

  rv = connect_to_vpp (sm);

  if (rv)
    {
      fformat (stderr, "Couldn't connect to vpp, does %s exist?\n",
	       socket_name);
      exit (1);
    }

  stat_poll_loop (sm);
  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
