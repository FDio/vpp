/*
 *------------------------------------------------------------------
 * stat_client.c
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

#include <vpp-api/client/stat_client.h>
//#include <vpp/app/stat_client.h>

#include <vlib/vlib.h>
//#include <vppinfra/socket.h>
//#include <svm/ssvm.h>
#include <vpp/stats/stats.h>

typedef struct
{
  u64 current_epoch;

  /* Cached pointers to scalar quantities, these wont change */
  f64 *vector_rate_ptr;
  f64 *input_rate_ptr;
  f64 *last_runtime_ptr;
  f64 *last_runtime_stats_clear_ptr;

  volatile int segment_ready;

  /*
   * Cached pointers to vector quantities,
   * MUST invalidate when the epoch changes
   */
  vlib_counter_t **intfc_rx_counters;
  vlib_counter_t **intfc_tx_counters;
  u8 *serialized_nodes;

  u64 *thread_0_error_counts;
  u64 source_address_match_error_index;

} stat_client_main_t;


stat_client_main_t stat_client_main;

#if 0
#define foreach_cached_pointer                                          \
_(/sys/vector_rate, SCALAR_POINTER, &stat_client_main.vector_rate_ptr)	\
_(/sys/input_rate, SCALAR_POINTER, &stat_client_main.input_rate_ptr)	\
_(/sys/last_update, SCALAR_POINTER, &stat_client_main.last_runtime_ptr)	\
_(/sys/last_stats_clear, SCALAR_POINTER,				\
  &stat_client_main.last_runtime_stats_clear_ptr)                       \
_(/if/rx, COUNTER_VECTOR, &stat_client_main.intfc_rx_counters)		\
_(/if/tx, COUNTER_VECTOR, &stat_client_main.intfc_tx_counters)		\
_(/err/0/counter_vector, VECTOR_POINTER,                                \
  &stat_client_main.thread_0_error_counts)                              \
_(serialized_nodes, SERIALIZED_NODES,                                   \
  &stat_client_main.serialized_nodes)
#endif

char *stat_client_counters[] =
{
   "/sys/vector_rate",
   "/if/rx",
   "/err/ethernet-input/no error",
};


static void
stat_poll_loop (stat_client_main_t * sm)
{
  struct timespec ts, tsrem;
#if 0
  ssvm_private_t *ssvmp = &sm->stat_segment;
  ssvm_shared_header_t *shared_header;
#endif
  vlib_counter_t *thread0_rx_counters = 0, *thread0_tx_counters = 0;
#if 0
  vlib_node_t ***nodes_by_thread;
  vlib_node_t **nodes;
  vlib_node_t *n;
  f64 vector_rate, input_rate;
  u32 len;
  int i, j;
  u32 source_address_match_errors;
#endif

  while (1)
    {
      /* Scrape stats every 5 seconds */
      ts.tv_sec = 5;
      ts.tv_nsec = 0;
      while (nanosleep (&ts, &tsrem) < 0)
	ts = tsrem;

      vec_reset_length (thread0_rx_counters);
      vec_reset_length (thread0_tx_counters);


      stat_segment_collect();

#if 0      
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
		      vec_free (n->name);
		      vec_free (n->next_nodes);
		      vec_free (n);
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
#endif
    }
}

enum stat_client_cmd_e {
  STAT_CLIENT_CMD_LS,
  STAT_CLIENT_CMD_POLL,
  STAT_CLIENT_CMD_DUMP,
};

int
main (int argc, char **argv)
{
  unformat_input_t _argv, *a = &_argv;
  stat_client_main_t *sm = &stat_client_main;
  u8 *stat_segment_name, *pattern = 0;
  int rv;
  enum stat_client_cmd_e cmd;

  clib_mem_init (0, 128 << 20);

  unformat_init_command_line (a, argv);

  stat_segment_name = (u8 *) STAT_SEGMENT_SOCKET_FILE;

  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT) {
    if (unformat (a, "socket-name %s", &stat_segment_name))
      ;
    else if (unformat (a, "ls")) {
      cmd = STAT_CLIENT_CMD_LS;
      if (unformat (a, "%s", &pattern))
	;
    } else if (unformat (a, "dump")) {
      if (unformat (a, "%s", &pattern))
	cmd = STAT_CLIENT_CMD_DUMP;
    } else if (unformat (a, "poll")) {
      if (unformat (a, "%s", &pattern))
	cmd = STAT_CLIENT_CMD_POLL;
    } else {
      fformat (stderr, "%s: usage [socket-name <name>]\n", argv[0]);
      exit (1);
    }
  }

  rv = stat_segment_connect ((char *)stat_segment_name);
  if (rv) {
      fformat (stderr, "Couldn't connect to vpp, does %s exist?\n",
	       stat_segment_name);
      exit (1);
  }

  u8 **dir;
  int i, j;
  stat_segment_data_t *res;

  dir = stat_segment_ls((char *)pattern);

  switch (cmd) {
  case STAT_CLIENT_CMD_LS:
    /* List all counters */
    for (i = 0; i < vec_len (dir); i++) {
      printf("%s\n", (char *)dir[i]);
    }
    break;

  case STAT_CLIENT_CMD_DUMP:
    res = stat_segment_dump(dir);
    for (i = 0; i < vec_len (res); i++) {
      switch (res[i].type) {
      case STAT_DIR_TYPE_COUNTER_VECTOR:
	for (j = 0; j < vec_len (res[i].counter_vec); j++) {
	  fformat (stdout, "[%d]: %lld packets, %lld bytes %s\n",
		   j, res[i].counter_vec[j].packets, res[i].counter_vec[j].bytes, dir[i]);
	}
	break;
      case STAT_DIR_TYPE_ERROR_INDEX:
	fformat(stdout, "%lld %s\n", res[i].error_value, dir[i]);
	break;

      case STAT_DIR_TYPE_SCALAR_POINTER:
	fformat(stdout, "%.2f %s\n", dir[i], res[i].scalar_value, dir[i]);
	break;
	
      default:
	;
      }
    }
    break;

  case STAT_CLIENT_CMD_POLL:
    rv = stat_segment_register(dir);
    if (rv) {
	fformat (stderr, "Couldn't register required counters with stat segment\n");
	exit (1);
    }
    stat_poll_loop (sm);
    break;

  default:
    ;
  }
  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
