/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#define _GNU_SOURCE
#include <stdint.h>
#include <vnet/bonding/node.h>

bond_main_t bond_main;

#define foreach_bond_input_func_error      \
  _(NO_SLAVE, "no slave")

typedef enum
{
#define _(f,s) BOND_INPUT_FUNC_ERROR_##f,
  foreach_bond_input_func_error
#undef _
    BOND_INPUT_FUNC_N_ERROR,
} bond_input_func_error_t;

static char *bond_input_func_error_strings[] = {
#define _(n,s) s,
  foreach_bond_input_func_error
#undef _
};

static u8 *
format_bond_input_trace (u8 * s, va_list * va)
{
  return s;
}

static uword
bond_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
	       vlib_frame_t * frame)
{
  bond_main_t *bm = &bond_main;
  vnet_interface_output_runtime_t *rund = (void *) node->runtime_data;
  bond_if_t *bif;
  u32 bi0;
  vlib_buffer_t *b0;
  u32 next_index;
  u32 *from, *to_next, n_left_from, n_left_to_next;
  ethernet_header_t *eth;
  u32 next0 = 0;

  bif = pool_elt_at_index (bm->interfaces, rund->dev_instance);
  if (PREDICT_FALSE (vec_len (bif->slaves) < 1))
    {
      vlib_error_count (vm, node->node_index, BOND_INPUT_FUNC_ERROR_NO_SLAVE,
			frame->n_vectors);
      return frame->n_vectors;
    }

  /* Vector of buffer / pkt indices we're supposed to process */
  from = vlib_frame_vector_args (frame);

  /* Number of buffers / pkts */
  n_left_from = frame->n_vectors;

  /* Speculatively send the first buffer to the last disposition we used */
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      /* set up to enqueue to our disposition with index = next_index */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          eth = (ethernet_header_t *) vlib_buffer_get_current (b0);
	  // Let LACP packet pass through
	  if (eth->type != htons (ETHERNET_TYPE_SLOW_PROTOCOLS))
	    {
	      // Change the physical interface to bond interface
	      // TODO. Shouldn't have to modify the MAC. All slaves and master
	      // should have the same MAC.
	      memcpy (eth->dst_address, bif->hw_address, 6);
              vnet_buffer (b0)->sw_if_index[VLIB_RX] = bif->sw_if_index;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_buffer_free (vm, vlib_frame_args (frame), frame->n_vectors);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (bond_input_node) = {
  .function = bond_input_fn,
  .name = "bond-input",
  .vector_size = sizeof (u32),
  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_bond_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = BOND_INPUT_FUNC_N_ERROR,
  .error_strings = bond_input_func_error_strings,
};
/* *INDENT-ON* */

static clib_error_t *
bond_input_init (vlib_main_t * vm)
{
  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (bond_input_init);

VNET_FEATURE_INIT (bond_input, static) =
{
  .arc_name = "device-input",
  .node_name = "bond-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
