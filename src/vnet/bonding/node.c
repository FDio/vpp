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
#include <vnet/llc/llc.h>
#include <vnet/snap/snap.h>
#include <vnet/bonding/node.h>

bond_main_t bond_main;

#define foreach_bond_input_error \
  _(NONE, "no error")            \
  _(IF_DOWN, "interface down")   \
  _(NO_SLAVE, "no slave")        \
  _(NO_BOND, "no bundle interface")

typedef enum
{
#define _(f,s) BOND_INPUT_ERROR_##f,
  foreach_bond_input_error
#undef _
    BOND_INPUT_N_ERROR,
} bond_input_error_t;

static char *bond_input_error_strings[] = {
#define _(n,s) s,
  foreach_bond_input_error
#undef _
};

static u8 *
format_bond_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  bond_packet_trace_t *t = va_arg (*args, bond_packet_trace_t *);
  vnet_hw_interface_t *hw, *hw1;
  vnet_main_t *vnm = vnet_get_main ();

  hw = vnet_get_sup_hw_interface (vnm, t->sw_if_index);
  hw1 = vnet_get_sup_hw_interface (vnm, t->bond_sw_if_index);
  s = format (s, "src %U, dst %U, %s -> %s",
	      format_ethernet_address, t->ethernet.src_address,
	      format_ethernet_address, t->ethernet.dst_address,
	      hw->name, hw1->name);

  return s;
}

static_always_inline u8
packet_is_cdp (ethernet_header_t * eth)
{
  llc_header_t *llc;
  snap_header_t *snap;

  llc = (llc_header_t *) (eth + 1);
  snap = (snap_header_t *) (llc + 1);

  return ((eth->type == htons (ETHERNET_TYPE_CDP)) ||
	  ((llc->src_sap == 0xAA) && (llc->control == 0x03) &&
	   (snap->protocol == htons (0x2000)) &&
	   (snap->oui[0] == 0) && (snap->oui[1] == 0) &&
	   (snap->oui[2] == 0x0C)));
}

static uword
bond_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
	       vlib_frame_t * frame)
{
  bond_main_t *bm = &bond_main;
  bond_if_t *bif;
  u32 bi0;
  vlib_buffer_t *b0;
  u32 next_index;
  u32 *from, *to_next, n_left_from, n_left_to_next;
  ethernet_header_t *eth;
  u32 next0;
  bond_packet_trace_t *t0;
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 sw_if_index;
  slave_if_t *sif;
  uword *p;

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
	  next0 = 0;
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  vnet_feature_next (vnet_buffer (b0)->sw_if_index[VLIB_RX], &next0,
			     b0);

	  eth = (ethernet_header_t *) vlib_buffer_get_current (b0);

	  sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  // sw_if_index points to the physical interface
	  p = hash_get (bm->neighbor_by_sw_if_index, sw_if_index);
	  if (PREDICT_TRUE (p != 0))
	    {
	      sif = pool_elt_at_index (bm->neighbors, p[0]);
	      p = hash_get (bm->dev_instance_by_group_id, sif->group);
	      if (PREDICT_TRUE (p != 0))
		{
		  bif = pool_elt_at_index (bm->interfaces, p[0]);

		  if (PREDICT_TRUE (vec_len (bif->slaves) >= 1))
		    {
		      if (PREDICT_TRUE (bif->admin_up == 1))
			{
			  // Let some layer2 packets pass through.
			  // TODO what else besides LLDP, LACP, and CDP?
			  if ((eth->type !=
			       htons (ETHERNET_TYPE_SLOW_PROTOCOLS))
			      && !packet_is_cdp (eth)
			      && (eth->type !=
				  htons (ETHERNET_TYPE_802_1_LLDP)))
			    {
			      // Change the physical interface to bond interface
			      vnet_buffer (b0)->sw_if_index[VLIB_RX] =
				bif->sw_if_index;
			    }
			}
		      else
			{
			  vlib_error_count (vm, node->node_index,
					    BOND_INPUT_ERROR_IF_DOWN, 1);
			}
		    }
		  else
		    {
		      vlib_error_count (vm, node->node_index,
					BOND_INPUT_ERROR_NO_SLAVE, 1);
		    }
		}
	      else
		{
		  vlib_error_count (vm, node->node_index,
				    BOND_INPUT_ERROR_NO_BOND, 1);
		}
	    }
	  else
	    {
	      vlib_error_count (vm, node->node_index,
				BOND_INPUT_ERROR_NO_SLAVE, 1);
	    }

	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      vlib_trace_buffer (vm, node, next0, b0, 0 /* follow_chain */ );
	      vlib_set_trace_count (vm, node, --n_trace);
	      t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	      t0->ethernet = *eth;
	      t0->sw_if_index = sw_if_index;
	      t0->bond_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, bond_input_node.index,
			       BOND_INPUT_ERROR_NONE, frame->n_vectors);

  return frame->n_vectors;
}

static clib_error_t *
bond_input_init (vlib_main_t * vm)
{
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (bond_input_node) = {
  .function = bond_input_fn,
  .name = "bond-input",
  .vector_size = sizeof (u32),
  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_bond_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = BOND_INPUT_N_ERROR,
  .error_strings = bond_input_error_strings,
};

VLIB_INIT_FUNCTION (bond_input_init);

VNET_FEATURE_INIT (bond_input, static) =
{
  .arc_name = "device-input",
  .node_name = "bond-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
VLIB_NODE_FUNCTION_MULTIARCH (bond_input_node, bond_input_fn)
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
