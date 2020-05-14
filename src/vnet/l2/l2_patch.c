/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vppinfra/error.h>

typedef struct
{
  /* vector of dispositions, indexed by rx_sw_if_index */
  u32 *tx_next_by_rx_sw_if_index;
  u32 *tx_sw_if_index_by_rx_sw_if_index;

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2_patch_main_t;

typedef struct
{
  u32 rx_sw_if_index;
  u32 tx_sw_if_index;
} l2_patch_trace_t;

/* packet trace format function */
static u8 *
format_l2_patch_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2_patch_trace_t *t = va_arg (*args, l2_patch_trace_t *);

  s = format (s, "L2_PATCH: rx %d tx %d", t->rx_sw_if_index,
	      t->tx_sw_if_index);
  return s;
}

#ifndef CLIB_MARCH_VARIANT
l2_patch_main_t l2_patch_main;
#else
extern l2_patch_main_t l2_patch_main;
#endif

extern vlib_node_registration_t l2_patch_node;

#define foreach_l2_patch_error			\
_(PATCHED, "L2 patch packets")			\
_(DROPPED, "L2 patch misconfigured drops")

typedef enum
{
#define _(sym,str) L2_PATCH_ERROR_##sym,
  foreach_l2_patch_error
#undef _
    L2_PATCH_N_ERROR,
} l2_patch_error_t;

static char *l2_patch_error_strings[] = {
#define _(sym,string) string,
  foreach_l2_patch_error
#undef _
};

typedef enum
{
  L2_PATCH_NEXT_DROP,
  L2_PATCH_N_NEXT,
} l2_patch_next_t;

static_always_inline void
l2_patch_trace (vlib_main_t * vm, vlib_node_runtime_t * node,
		l2_patch_main_t * l2pm, vlib_buffer_t * b, u32 sw_if_index)
{
  l2_patch_trace_t *t;

  if ((b->flags & VLIB_BUFFER_IS_TRACED) == 0)
    return;

  t = vlib_add_trace (vm, node, b, sizeof (*t));
  t->rx_sw_if_index = sw_if_index;
  t->tx_sw_if_index = l2pm->tx_sw_if_index_by_rx_sw_if_index[sw_if_index];
}

static_always_inline void
l2_patch_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		 l2_patch_main_t * l2pm, vlib_buffer_t ** b, u16 * next,
		 u32 n_left, int do_trace)
{
  u32 sw_if_index[4];

  while (n_left >= 4)
    {
      /* Prefetch next iteration. */
      if (n_left >= 8)
	{
	  vlib_buffer_t **p = b + 4;
	  vlib_prefetch_buffer_header (p[0], LOAD);
	  vlib_prefetch_buffer_header (p[1], LOAD);
	  vlib_prefetch_buffer_header (p[2], LOAD);
	  vlib_prefetch_buffer_header (p[3], LOAD);
	}

      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
      sw_if_index[2] = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
      sw_if_index[3] = vnet_buffer (b[3])->sw_if_index[VLIB_RX];

      ASSERT (l2pm->tx_next_by_rx_sw_if_index[sw_if_index[0]] != ~0);
      ASSERT (l2pm->tx_sw_if_index_by_rx_sw_if_index[sw_if_index[0]] != ~0);
      ASSERT (l2pm->tx_next_by_rx_sw_if_index[sw_if_index[1]] != ~0);
      ASSERT (l2pm->tx_sw_if_index_by_rx_sw_if_index[sw_if_index[1]] != ~0);
      ASSERT (l2pm->tx_next_by_rx_sw_if_index[sw_if_index[2]] != ~0);
      ASSERT (l2pm->tx_sw_if_index_by_rx_sw_if_index[sw_if_index[2]] != ~0);
      ASSERT (l2pm->tx_next_by_rx_sw_if_index[sw_if_index[3]] != ~0);
      ASSERT (l2pm->tx_sw_if_index_by_rx_sw_if_index[sw_if_index[3]] != ~0);

      next[0] = l2pm->tx_next_by_rx_sw_if_index[sw_if_index[0]];
      next[1] = l2pm->tx_next_by_rx_sw_if_index[sw_if_index[1]];
      next[2] = l2pm->tx_next_by_rx_sw_if_index[sw_if_index[2]];
      next[3] = l2pm->tx_next_by_rx_sw_if_index[sw_if_index[3]];

      vnet_buffer (b[0])->sw_if_index[VLIB_TX] =
	l2pm->tx_sw_if_index_by_rx_sw_if_index[sw_if_index[0]];
      vnet_buffer (b[1])->sw_if_index[VLIB_TX] =
	l2pm->tx_sw_if_index_by_rx_sw_if_index[sw_if_index[1]];
      vnet_buffer (b[2])->sw_if_index[VLIB_TX] =
	l2pm->tx_sw_if_index_by_rx_sw_if_index[sw_if_index[2]];
      vnet_buffer (b[3])->sw_if_index[VLIB_TX] =
	l2pm->tx_sw_if_index_by_rx_sw_if_index[sw_if_index[3]];

      if (do_trace)
	{
	  l2_patch_trace (vm, node, l2pm, b[0], sw_if_index[0]);
	  l2_patch_trace (vm, node, l2pm, b[1], sw_if_index[1]);
	  l2_patch_trace (vm, node, l2pm, b[2], sw_if_index[2]);
	  l2_patch_trace (vm, node, l2pm, b[3], sw_if_index[3]);
	}

      /* next */
      next += 4;
      b += 4;
      n_left -= 4;
    }

  while (n_left)
    {
      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];

      ASSERT (l2pm->tx_next_by_rx_sw_if_index[sw_if_index[0]] != ~0);
      ASSERT (l2pm->tx_sw_if_index_by_rx_sw_if_index[sw_if_index[0]] != ~0);

      next[0] = l2pm->tx_next_by_rx_sw_if_index[sw_if_index[0]];

      vnet_buffer (b[0])->sw_if_index[VLIB_TX] =
	l2pm->tx_sw_if_index_by_rx_sw_if_index[sw_if_index[0]];

      if (do_trace)
	l2_patch_trace (vm, node, l2pm, b[0], sw_if_index[0]);

      /* next */
      next += 1;
      b += 1;
      n_left -= 1;
    }
}

VLIB_NODE_FN (l2_patch_node) (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
{
  u32 *from;
  l2_patch_main_t *l2pm = &l2_patch_main;
  vlib_node_t *n = vlib_get_node (vm, l2_patch_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t *em = &vm->error_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];

  from = vlib_frame_vector_args (frame);

  vlib_get_buffers (vm, from, bufs, frame->n_vectors);

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    l2_patch_inline (vm, node, l2pm, bufs, nexts, frame->n_vectors, 1);
  else
    l2_patch_inline (vm, node, l2pm, bufs, nexts, frame->n_vectors, 0);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  em->counters[node_counter_base_index + L2_PATCH_ERROR_PATCHED] +=
    frame->n_vectors;

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2_patch_node) = {
  .name = "l2-patch",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_patch_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2_patch_error_strings),
  .error_strings = l2_patch_error_strings,

  .n_next_nodes = L2_PATCH_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [L2_PATCH_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

extern int
vnet_l2_patch_add_del (u32 rx_sw_if_index, u32 tx_sw_if_index, int is_add);
#ifndef CLIB_MARCH_VARIANT
int
vnet_l2_patch_add_del (u32 rx_sw_if_index, u32 tx_sw_if_index, int is_add)
{
  l2_patch_main_t *l2pm = &l2_patch_main;
  vnet_hw_interface_t *rxhi, *txhi;
  u32 tx_next_index;

  /*
   * We assume that the API msg handler has used 2x VALIDATE_SW_IF_INDEX
   * macros...
   */

  rxhi = vnet_get_sup_hw_interface (l2pm->vnet_main, rx_sw_if_index);

  /* Make sure caller didn't pass a vlan subif, etc. */
  if (rxhi->sw_if_index != rx_sw_if_index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  txhi = vnet_get_sup_hw_interface (l2pm->vnet_main, tx_sw_if_index);
  if (txhi->sw_if_index != tx_sw_if_index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX_2;

  if (is_add)
    {
      tx_next_index = vlib_node_add_next (l2pm->vlib_main,
					  l2_patch_node.index,
					  txhi->output_node_index);

      vec_validate_init_empty (l2pm->tx_next_by_rx_sw_if_index,
			       rx_sw_if_index, ~0);

      l2pm->tx_next_by_rx_sw_if_index[rx_sw_if_index] = tx_next_index;
      vec_validate_init_empty (l2pm->tx_sw_if_index_by_rx_sw_if_index,
			       rx_sw_if_index, ~0);
      l2pm->tx_sw_if_index_by_rx_sw_if_index[rx_sw_if_index]
	= txhi->sw_if_index;

      ethernet_set_flags (l2pm->vnet_main, rxhi->hw_if_index,
			  ETHERNET_INTERFACE_FLAG_ACCEPT_ALL);

      vnet_feature_enable_disable ("device-input", "l2-patch",
				   rxhi->sw_if_index, 1, 0, 0);
    }
  else
    {
      ethernet_set_flags (l2pm->vnet_main, rxhi->hw_if_index,
			  /*ETHERNET_INTERFACE_FLAG_DEFAULT_L3 */ 0);

      vnet_feature_enable_disable ("device-input", "l2-patch",
				   rxhi->sw_if_index, 0, 0, 0);
      if (vec_len (l2pm->tx_next_by_rx_sw_if_index) > rx_sw_if_index)
	{
	  l2pm->tx_next_by_rx_sw_if_index[rx_sw_if_index] = ~0;
	  l2pm->tx_sw_if_index_by_rx_sw_if_index[rx_sw_if_index] = ~0;
	}
    }

  return 0;
}
#endif

static clib_error_t *
test_patch_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  l2_patch_main_t *l2pm = &l2_patch_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 rx_sw_if_index, tx_sw_if_index;
  int rv;
  int rx_set = 0;
  int tx_set = 0;
  int is_add = 1;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "rx %U", unformat_vnet_sw_interface,
		    l2pm->vnet_main, &rx_sw_if_index))
	rx_set = 1;
      else if (unformat (line_input, "tx %U", unformat_vnet_sw_interface,
			 l2pm->vnet_main, &tx_sw_if_index))
	tx_set = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	break;
    }

  if (rx_set == 0)
    {
      error = clib_error_return (0, "rx interface not set");
      goto done;
    }

  if (tx_set == 0)
    {
      error = clib_error_return (0, "tx interface not set");
      goto done;
    }

  rv = vnet_l2_patch_add_del (rx_sw_if_index, tx_sw_if_index, is_add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      error = clib_error_return (0, "rx interface not a physical port");
      goto done;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX_2:
      error = clib_error_return (0, "tx interface not a physical port");
      goto done;

    default:
      error = clib_error_return
	(0, "WARNING: vnet_l2_patch_add_del returned %d", rv);
      goto done;
    }


done:
  unformat_free (line_input);

  return error;
}

/*?
 * Create or delete a Layer 2 patch.
 *
 * @cliexpar
 * @cliexstart{test l2patch rx <intfc> tx <intfc> [del]}
 * @cliexend
 * @todo This is incomplete. This needs a detailed description and a
 * practical example.
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_patch_command, static) = {
    .path = "test l2patch",
    .short_help = "test l2patch rx <intfc> tx <intfc> [del]",
    .function = test_patch_command_fn,
};
/* *INDENT-ON* */

/** Display the contents of the l2patch table. */
static clib_error_t *
show_l2patch (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  l2_patch_main_t *l2pm = &l2_patch_main;
  u32 rx_sw_if_index;
  u32 no_entries = 1;

  ASSERT (vec_len (l2pm->tx_next_by_rx_sw_if_index) ==
	  vec_len (l2pm->tx_sw_if_index_by_rx_sw_if_index));

  for (rx_sw_if_index = 0;
       rx_sw_if_index < vec_len (l2pm->tx_sw_if_index_by_rx_sw_if_index);
       rx_sw_if_index++)
    {
      u32 tx_sw_if_index =
	l2pm->tx_sw_if_index_by_rx_sw_if_index[rx_sw_if_index];
      if (tx_sw_if_index != ~0)
	{
	  no_entries = 0;
	  vlib_cli_output (vm, "%26U -> %U",
			   format_vnet_sw_if_index_name,
			   l2pm->vnet_main, rx_sw_if_index,
			   format_vnet_sw_if_index_name,
			   l2pm->vnet_main, tx_sw_if_index);
	}
    }

  if (no_entries)
    vlib_cli_output (vm, "no l2patch entries");

  return 0;
}

/*?
 * Show Layer 2 patch entries.
 *
 * @cliexpar
 * @cliexstart{show l2patch}
 * @cliexend
 * @todo This is incomplete. This needs a detailed description and a
 * practical example.
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_l2patch_cli, static) = {
  .path = "show l2patch",
  .short_help = "Show l2 interface cross-connect entries",
  .function = show_l2patch,
};
/* *INDENT-ON* */

static clib_error_t *
l2_patch_init (vlib_main_t * vm)
{
  l2_patch_main_t *mp = &l2_patch_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main ();

  return 0;
}

VLIB_INIT_FUNCTION (l2_patch_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
