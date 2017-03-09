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
#include <vlib/vlib.h>

#include <vppinfra/serialize.h>

extern void vl_msg_api_barrier_sync (void);
extern void vl_msg_api_barrier_release (void);

/* serialized representation of state strings */

#define foreach_state_string_code               \
_(STATE_DONE, "done")                           \
_(STATE_DISABLED, "disabled")                   \
_(STATE_TIME_WAIT, "time wait")                 \
_(STATE_EVENT_WAIT, "event wait")               \
_(STATE_ANY_WAIT, "any wait")                   \
_(STATE_POLLING, "polling")                     \
_(STATE_INTERRUPT_WAIT, "interrupt wait")       \
_(STATE_INTERNAL, "internal")

typedef enum
{
#define _(a,b) a,
  foreach_state_string_code
#undef _
} state_string_enum_t;

static char *state_strings[] = {
#define _(a,b) b,
  foreach_state_string_code
#undef _
};

/*
 * Serialize a vlib_node_main_t. Appends the result to vector.
 * Pass 0 to create a new vector, use vec_reset_length(vector)
 * to recycle a vector / avoid memory allocation, etc.
 * Switch heaps before/after to serialize into API client shared memory.
 */

u8 *
vlib_node_serialize (vlib_node_main_t * nm, u8 * vector,
		     u32 max_threads, int include_nexts, int include_stats)
{
  serialize_main_t _sm, *sm = &_sm;
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_t *n;
  static vlib_node_t ***node_dups;
  vlib_node_t **nodes;
  static vlib_main_t **stat_vms;
  vlib_main_t *stat_vm;
  u8 *namep;
  u32 name_bytes;
  uword i, j, k;
  u64 l, v, c, d;
  state_string_enum_t state_code;
  u32 threads_to_serialize;

  vec_reset_length (node_dups);

  if (vec_len (stat_vms) == 0)
    {
      for (i = 0; i < vec_len (vlib_mains); i++)
	{
	  stat_vm = vlib_mains[i];
	  if (stat_vm)
	    vec_add1 (stat_vms, stat_vm);
	}
    }

  threads_to_serialize = clib_min (max_threads, vec_len (stat_vms));

  /*
   * Barrier sync across stats scraping.
   * Otherwise, the counts will be grossly inaccurate.
   */
  vl_msg_api_barrier_sync ();

  for (j = 0; j < threads_to_serialize; j++)
    {
      stat_vm = stat_vms[j];
      nm = &stat_vm->node_main;

      if (include_stats)
	{
	  for (i = 0; i < vec_len (nm->nodes); i++)
	    {
	      n = nm->nodes[i];
	      vlib_node_sync_stats (stat_vm, n);
	    }
	}

      nodes = vec_dup (nm->nodes);

      vec_add1 (node_dups, nodes);
    }
  vl_msg_api_barrier_release ();

  serialize_open_vector (sm, vector);

  serialize_likely_small_unsigned_integer (sm, vec_len (stat_vms));

  for (j = 0; j < vec_len (stat_vms); j++)
    {
      stat_vm = stat_vms[j];
      nodes = node_dups[j];

      serialize_likely_small_unsigned_integer (sm, vec_len (nodes));

      for (i = 0; i < vec_len (nodes); i++)
	{
	  n = nodes[i];

	  l = n->stats_total.clocks - n->stats_last_clear.clocks;
	  v = n->stats_total.vectors - n->stats_last_clear.vectors;
	  c = n->stats_total.calls - n->stats_last_clear.calls;
	  d = n->stats_total.suspends - n->stats_last_clear.suspends;

	  state_code = STATE_INTERNAL;

	  if (n->type == VLIB_NODE_TYPE_PROCESS)
	    {
	      vlib_process_t *p = vlib_get_process_from_node (vm, n);

	      switch (p->flags
		      & (VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK
			 | VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT))
		{
		default:
		  if (!(p->flags & VLIB_PROCESS_IS_RUNNING))
		    state_code = STATE_DONE;
		  break;

		case VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK:
		  state_code = STATE_TIME_WAIT;
		  break;

		case VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT:
		  state_code = STATE_EVENT_WAIT;
		  break;

		case (VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT | VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK):
		  state_code =
		    STATE_ANY_WAIT;
		  break;
		}
	    }
	  else if (n->type != VLIB_NODE_TYPE_INTERNAL)
	    {
	      state_code = STATE_POLLING;
	      if (n->state == VLIB_NODE_STATE_DISABLED)
		state_code = STATE_DISABLED;
	      else if (n->state == VLIB_NODE_STATE_INTERRUPT)
		state_code = STATE_INTERRUPT_WAIT;
	    }

	  /* See unserialize_cstring */
	  name_bytes = vec_len (n->name);
	  serialize_likely_small_unsigned_integer (sm, name_bytes);
	  namep = serialize_get (sm, name_bytes);
	  memcpy (namep, n->name, name_bytes);

	  serialize_likely_small_unsigned_integer (sm, (u64) state_code);
	  serialize_likely_small_unsigned_integer (sm, n->type);

	  if (include_nexts)
	    {
	      serialize_likely_small_unsigned_integer
		(sm, vec_len (n->next_nodes));
	      for (k = 0; k < vec_len (n->next_nodes); k++)
		serialize_likely_small_unsigned_integer (sm,
							 n->next_nodes[k]);
	    }
	  else
	    serialize_likely_small_unsigned_integer (sm, 0);

	  if (include_stats)
	    {
	      /* stats present */
	      serialize_likely_small_unsigned_integer (sm, 1);
	      /* total clocks */
	      serialize_integer (sm, l, 8);
	      /* Total calls */
	      serialize_integer (sm, c, 8);
	      /* Total vectors */
	      serialize_integer (sm, v, 8);
	      /* Total suspends */
	      serialize_integer (sm, d, 8);
	    }
	  else			/* no stats */
	    serialize_likely_small_unsigned_integer (sm, 0);
	}
      vec_free (nodes);
    }
  return (serialize_close_vector (sm));
}

vlib_node_t ***
vlib_node_unserialize (u8 * vector)
{
  serialize_main_t _sm, *sm = &_sm;
  u32 nnodes, nnexts;
  u32 nstat_vms;
  vlib_node_t *node;
  vlib_node_t **nodes;
  vlib_node_t ***nodes_by_thread = 0;
  int i, j, k;
  u64 l, v, c, d;
  state_string_enum_t state_code;
  int stats_present;

  serialize_open_vector (sm, vector);

  nstat_vms = unserialize_likely_small_unsigned_integer (sm);

  vec_validate (nodes_by_thread, nstat_vms - 1);
  _vec_len (nodes_by_thread) = 0;

  for (i = 0; i < nstat_vms; i++)
    {
      nnodes = unserialize_likely_small_unsigned_integer (sm);

      nodes = 0;
      vec_validate (nodes, nnodes - 1);
      vec_add1 (nodes_by_thread, nodes);

      for (j = 0; j < nnodes; j++)
	{
	  node = 0;
	  vec_validate (node, 0);
	  nodes[j] = node;

	  unserialize_cstring (sm, (char **) &(node->name));
	  state_code = unserialize_likely_small_unsigned_integer (sm);
	  node->state_string = (u8 *) state_strings[state_code];

	  node->type = unserialize_likely_small_unsigned_integer (sm);
	  nnexts = unserialize_likely_small_unsigned_integer (sm);
	  if (nnexts > 0)
	    vec_validate (node->next_nodes, nnexts - 1);
	  for (k = 0; k < nnexts; k++)
	    node->next_nodes[k] =
	      unserialize_likely_small_unsigned_integer (sm);

	  stats_present = unserialize_likely_small_unsigned_integer (sm);

	  if (stats_present)
	    {
	      /* total clocks */
	      unserialize_integer (sm, &l, 8);
	      node->stats_total.clocks = l;
	      node->stats_last_clear.clocks = 0;

	      /* Total calls */
	      unserialize_integer (sm, &c, 8);
	      node->stats_total.calls = c;

	      /* Total vectors */
	      unserialize_integer (sm, &v, 8);
	      node->stats_total.vectors = v;

	      /* Total suspends */
	      unserialize_integer (sm, &d, 8);
	      node->stats_total.suspends = d;
	    }
	}
    }
  return nodes_by_thread;
}

#if TEST_CODE

static clib_error_t *
test_node_serialize_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  vlib_node_main_t *nm = &vm->node_main;
  u8 *vector = 0;
  vlib_node_t ***nodes_by_thread;
  vlib_node_t **nodes;
  vlib_node_t *node;
  vlib_node_t *next_node;
  int i, j, k;
  u32 max_threads = (u32) ~ 0;
  int include_nexts = 0;
  int include_stats = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "max-threads %d", &max_threads))
	;
      else if (unformat (input, "stats"))
	include_stats = 1;
      else if (unformat (input, "nexts"))
	include_nexts = 1;
      else
	break;
    }

  /*
   * Keep the number of memcpy ops to a minimum (e.g. 1).
   * The current size of the serialized vector is
   * slightly under 4K.
   */
  vec_validate (vector, 16383);
  vec_reset_length (vector);

  vector = vlib_node_serialize (nm, vector, max_threads,
				include_nexts, include_stats);

  vlib_cli_output (vm, "result vector %d bytes", vec_len (vector));

  nodes_by_thread = vlib_node_unserialize (vector);

  vec_free (vector);

  for (i = 0; i < vec_len (nodes_by_thread); i++)
    {
      nodes = nodes_by_thread[i];

      vlib_cli_output (vm, "thread %d", i);

      for (j = 0; j < vec_len (nodes); j++)
	{
	  node = nodes[j];

	  vlib_cli_output (vm, "[%d] %s state %s", j, node->name,
			   node->state_string);

	  vlib_cli_output
	    (vm, "    clocks %lld calls %lld suspends"
	     " %lld vectors %lld",
	     node->stats_total.clocks,
	     node->stats_total.calls,
	     node->stats_total.suspends, node->stats_total.vectors);

	  for (k = 0; k < vec_len (node->next_nodes); k++)
	    {
	      if (node->next_nodes[k] != ~0)
		{
		  next_node = nodes[node->next_nodes[k]];
		  vlib_cli_output (vm, "  [%d] %s", k, next_node->name);
		}
	    }
	}
    }

  for (j = 0; j < vec_len (nodes_by_thread); j++)
    {
      nodes = nodes_by_thread[j];

      for (i = 0; i < vec_len (nodes); i++)
	{
	  vec_free (nodes[i]->name);
	  vec_free (nodes[i]->next_nodes);
	  vec_free (nodes[i]);
	}
      vec_free (nodes);
    }
  vec_free (nodes_by_thread);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_node_serialize_node, static) = {
    .path = "test node serialize",
    .short_help = "test node serialize [max-threads NN] nexts stats",
    .function = test_node_serialize_command_fn,
};
/* *INDENT-ON* */
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
