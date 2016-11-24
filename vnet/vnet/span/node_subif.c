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
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>

#include <vnet/span/subif.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

vlib_node_registration_t subif_node;

/* packet trace format function */
u8 *
format_subif_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  subif_trace_t *t = va_arg (*args, subif_trace_t *);

  vnet_main_t *vnm = &vnet_main;
  s = format (s, "SUBBIF: %U",
         format_vnet_sw_if_index_name, vnm, t->sw_if_index);
  return s;
}

#define foreach_subif_error                      \
_(HITS, "SUBIF incomming packets processed")

typedef enum
{
#define _(sym,str) SUBIF_ERROR_##sym,
  foreach_subif_error
#undef _
    SUBIF_N_ERROR,
} subif_error_t;

static char *subif_error_strings[] = {
#define _(sym,string) string,
  foreach_subif_error
#undef _
};

// Parse the ethernet header to extract vlan tags and innermost ethertype
static_always_inline void
parse_eth_header (vlib_buffer_t * b0,
        u16 * type,
        u16 * orig_type,
        u16 * outer_id, u16 * inner_id, u32 * match_flags)
{
  ethernet_header_t *e0;

  e0 = (void *) (b0->data + b0->current_data);
  vnet_buffer (b0)->ethernet.start_of_ethernet_header = b0->current_data;
  vlib_buffer_advance (b0, sizeof (e0[0]));

  *type = clib_net_to_host_u16 (e0->type);

  // save for distinguishing between dot1q and dot1ad later
  *orig_type = *type;

  // default the tags to 0 (used if there is no corresponding tag)
  *outer_id = 0;
  *inner_id = 0;

  *match_flags = SUBINT_CONFIG_VALID | SUBINT_CONFIG_MATCH_0_TAG;

  // check for vlan encaps
  if (ethernet_frame_is_tagged (*type))
    {
      ethernet_vlan_header_t *h0;
      u16 tag;

      *match_flags = SUBINT_CONFIG_VALID | SUBINT_CONFIG_MATCH_1_TAG;
      h0 = (void *) (b0->data + b0->current_data);
      tag = clib_net_to_host_u16 (h0->priority_cfi_and_id);
      *outer_id = tag & 0xfff;
      *type = clib_net_to_host_u16 (h0->type);
      vlib_buffer_advance (b0, sizeof (h0[0]));

      if (*type == ETHERNET_TYPE_VLAN)
  {
    // Double tagged packet
    *match_flags = SUBINT_CONFIG_VALID | SUBINT_CONFIG_MATCH_2_TAG;
    h0 = (void *) (b0->data + b0->current_data);
    tag = clib_net_to_host_u16 (h0->priority_cfi_and_id);
    *inner_id = tag & 0xfff;
    *type = clib_net_to_host_u16 (h0->type);
    vlib_buffer_advance (b0, sizeof (h0[0]));

    if (*type == ETHERNET_TYPE_VLAN)
      {
        // More than double tagged packet
        *match_flags = SUBINT_CONFIG_VALID | SUBINT_CONFIG_MATCH_3_TAG;
      }
    vlib_buffer_advance (b0, -sizeof (h0[0]));
  }
      vlib_buffer_advance (b0, -sizeof (h0[0]));
    }

  vlib_buffer_advance (b0, -sizeof (e0[0]));
}

static uword
subif_node_fn (vlib_main_t * vm,
	      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
//  subif_main_t *sm = &subif_main;
  vnet_main_t *vnm = &vnet_main;
  ethernet_main_t *em = &ethernet_main;

  u32 n_left_from, *from, *to_next;
  u32 n_subif_packets = 0;
  u32 next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
  {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
         to_next, n_left_to_next);

/*
       // TODO : dual loop
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	}
*/
    while (n_left_from > 0 && n_left_to_next > 0)
    {
    u32 bi0;
    vlib_buffer_t * b0;
    u8 error0;
    u32 next0 = 0;
    ethernet_header_t *e0;

    u16 type0, orig_type0;
    u16 outer_id0, inner_id0;
    u32 match_flags0;
    u32 old_sw_if_index0, new_sw_if_index0;
    vnet_hw_interface_t *hi0;
    main_intf_t *main_intf0;
    vlan_intf_t *vlan_intf0;
    qinq_intf_t *qinq_intf0;
    u32 is_l20;

    /* speculatively enqueue b0 to the current next frame */
    bi0 = from[0];
    to_next[0] = bi0;
    from += 1;
    to_next += 1;
    n_left_from -= 1;
    n_left_to_next -= 1;

    b0 = vlib_get_buffer (vm, bi0);

    e0 = vlib_buffer_get_current (b0);
    type0 = clib_net_to_host_u16 (e0->type);

    parse_eth_header(b0,
      &type0,
      &orig_type0, &outer_id0, &inner_id0, &match_flags0);

    old_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

    eth_vlan_table_lookups (em,
          vnm,
          old_sw_if_index0,
          orig_type0,
          outer_id0,
          inner_id0,
          &hi0,
          &main_intf0, &vlan_intf0, &qinq_intf0);

    identify_subint (hi0,
         b0,
         match_flags0,
         main_intf0,
         vlan_intf0,
         qinq_intf0, &new_sw_if_index0, &error0, &is_l20);

    // replace vlib_rx index with subinterface index - will be used by span
    vnet_buffer (b0)->sw_if_index[VLIB_RX] = new_sw_if_index0;

    vnet_feature_next (old_sw_if_index0, &next0, b0);

    if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
      {
        subif_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
        t->sw_if_index = new_sw_if_index0;
      }

    n_subif_packets += 1;

    // verify speculative enqueue, maybe switch current next frame
    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
       to_next, n_left_to_next,
       bi0, next0);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

//  vnet_put_frame_to_sw_interface (vnm, last_mirror_sw_if_index, mirror_frame);
  vlib_node_increment_counter (vm, subif_node.index,
      SUBIF_ERROR_HITS, n_subif_packets);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (subif_node) = {
  .function = subif_node_fn,
  .name = "subif-input",
  .vector_size = sizeof (u32),
  .format_trace = format_subif_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(subif_error_strings),
  .error_strings = subif_error_strings,

  .n_next_nodes = 0,

  /* edit / add dispositions here */
  .next_nodes = {
    [0] = "error-drop",
  },
};

/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (subif_node, subif_node_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
