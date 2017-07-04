/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or pemplied.
 * See the License for the specific language governing permissions and
 * lpemitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/ppp/packet.h>
#include <pppoe/pppoe.h>

vlib_node_registration_t pppoe_tap_dispatch_node;

#define foreach_pppoe_tap_next        \
_(DROP, "error-drop")                  \
_(TUNTAP, "tuntap-tx" )                \
_(INTERFACE, "interface-output" )      \

typedef enum
{
#define _(s,n) PPPOE_TAP_NEXT_##s,
  foreach_pppoe_tap_next
#undef _
    PPPOE_TAP_N_NEXT,
} pppoe_tap_next_t;

typedef struct {
  u32 next_index;
  u32 sw_if_index;
  u32 tap_if_index;
  u32 error;
} pppoe_tap_trace_t;

static u8 * format_pppoe_tap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pppoe_tap_trace_t * t = va_arg (*args, pppoe_tap_trace_t *);

  if (t->sw_if_index != ~0)
    {
      s = format (s, "PPPoE dispatch from sw_if_index %d next %d error %d",
                  t->sw_if_index, t->next_index, t->error);
    }
  else
    {
      s = format (s, "PPPoE dispatch from tap_if_index %d next %d error %d",
                  t->tap_if_index, t->next_index, t->error);
    }
  return s;
}

static uword
pppoe_tap_dispatch (vlib_main_t * vm,
                    vlib_node_runtime_t * node,
                    vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  pppoe_main_t * pem = &pppoe_main;
  vnet_main_t * vnm = pem->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;
  u32 pkts_decapsulated = 0;
  u32 thread_index = vlib_get_thread_index();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
	  u32 next0;
          u32 error0;
	  u32 sw_if_index0, len0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          /* leaves current_data pointing at the pppoe header */
          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          error0 = 0;

          if(sw_if_index0 == pem->tap_if_index)
            {
              next0 = PPPOE_TAP_NEXT_INTERFACE;
              vnet_buffer(b0)->sw_if_index[VLIB_TX] = pem->sw_if_index;
              vlib_buffer_reset(b0);
              clib_memcpy (vlib_buffer_get_current (b0)+6, pem->ether_src_mac, 6);
            }
          else
            {
              next0 = PPPOE_TAP_NEXT_TUNTAP;
              vnet_buffer(b0)->sw_if_index[VLIB_TX] = pem->tap_if_index;
              vlib_buffer_reset(b0);
            }

	  len0 = vlib_buffer_length_in_chain (vm, b0);

          pkts_decapsulated ++;
          stats_n_packets += 1;
          stats_n_bytes += len0;

	  /* Batch stats increment on the same pppoe session so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (sw_if_index0 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_sw_if_index = sw_if_index0;
	    }

          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              pppoe_tap_trace_t *tr
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->sw_if_index = sw_if_index0;
              tr->tap_if_index = pem->tap_if_index;
            }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  /* Do we still need this now that session tx stats is kept? */
  vlib_node_increment_counter (vm, pppoe_input_node.index,
                               PPPOE_ERROR_DECAPSULATED,
                               pkts_decapsulated);

  /* Increment any remaining batch stats */
  if (stats_n_packets)
    {
      vlib_increment_combined_counter
	(im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
	 thread_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
      node->runtime_data[0] = stats_sw_if_index;
    }

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (pppoe_tap_dispatch_node) = {
  .function = pppoe_tap_dispatch,
  .name = "pppoe-tap-dispatch",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_next_nodes = PPPOE_TAP_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPPOE_TAP_NEXT_##s] = n,
    foreach_pppoe_tap_next
#undef _
  },

  .format_trace = format_pppoe_tap_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (pppoe_tap_dispatch_node, pppoe_tap_dispatch)

