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
#include <vnet/ethernet/ethernet.h>
#include <vnet/bonding/node.h>
#include <vnet/bonding/lacp/node.h>

#define foreach_bond_tx_func_error      \
  _(NO_SLAVE, "no slave interface")

typedef enum
{
#define _(f,s) BOND_TX_FUNC_ERROR_##f,
  foreach_bond_tx_func_error
#undef _
    BOND_TX_FUNC_N_ERROR,
} bond_tx_func_error_t;

static char *bond_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_bond_tx_func_error
#undef _
};

static u8 *
format_bond_tx_trace (u8 * s, va_list * args)
{
  s = format (s, "Unimplemented...");

  return s;
}

u8 *
format_bond_interface_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  bond_main_t *bm = &bond_main;
  bond_if_t *bif = pool_elt_at_index (bm->interfaces, dev_instance);

  s = format (s, "bundle%lu/%lu", bif->group, bif->dev_instance);

  return s;
}

static clib_error_t *
bond_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  return 0;
}

#define foreach_bond_output_func_error      \
  _(NO_SLAVE, "no slave")

typedef enum
{
#define _(f,s) BOND_OUTPUT_FUNC_ERROR_##f,
  foreach_bond_output_func_error
#undef _
    BOND_OUTPUT_FUNC_N_ERROR,
} bond_output_func_error_t;

static char *bond_output_func_error_strings[] = {
#define _(n,s) s,
  foreach_bond_output_func_error
#undef _
};

static u8 *
format_bond_output_trace (u8 * s, va_list * va)
{
  return s;
}

static uword
bond_tx_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  clib_warning ("NOT IMPLEMENTED");
  return frame->n_vectors;
}

static uword
bond_output_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
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
  u16 hash, port;
  u32 sw_if_index;
  vnet_hw_interface_t *hw;
  vnet_main_t *vnm = vnet_get_main ();

  bif = pool_elt_at_index (bm->interfaces, rund->dev_instance);
  if (PREDICT_FALSE (vec_len (bif->slaves) < 1))
    {
      vlib_error_count (vm, node->node_index, BOND_OUTPUT_FUNC_ERROR_NO_SLAVE,
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
	  hash =
	    (*(u16 *) & eth->dst_address[0] ^
	     *(u16 *) & eth->src_address[0]) ^
	    (*(u16 *) & eth->dst_address[2] ^
	     *(u16 *) & eth->src_address[2]) ^
	    (*(u16 *) & eth->dst_address[4] ^ *(u16 *) & eth->src_address[4]);
	  hash ^= hash >> 8;
	  port = hash % vec_len (bif->slaves);
	  sw_if_index = *vec_elt_at_index (bif->slaves, port);
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index;
	  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
	  clib_memcpy (eth->src_address, hw->hw_address, 6);

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (bond_output_node) = {
  .function = bond_output_fn,
  .name = "bond-output",
  .vector_size = sizeof (u32),
  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_bond_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = BOND_OUTPUT_FUNC_N_ERROR,
  .error_strings = bond_output_func_error_strings,
};

VNET_FEATURE_INIT (bond_output, static) =
{
  .arc_name = "interface-output",
  .node_name = "bond-output",
  .runs_before = VNET_FEATURES ("interface-tx"),
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (bond_dev_class) = {
  .name = "bond",
  .tx_function = bond_tx_fn,
  .tx_function_n_errors = BOND_TX_FUNC_N_ERROR,
  .tx_function_error_strings = bond_tx_func_error_strings,
  .format_device_name = format_bond_interface_name,
  .admin_up_down_function = bond_interface_admin_up_down,
  .format_tx_trace = format_bond_tx_trace,
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH (bond_dev_class, bond_tx_fn)
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
