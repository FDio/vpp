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

vlib_node_registration_t pppoe_cp_dispatch_node;

#define foreach_pppoe_cp_next        \
_(DROP, "error-drop")                  \
_(INTERFACE, "interface-output" )      \

typedef enum
{
#define _(s,n) PPPOE_CP_NEXT_##s,
  foreach_pppoe_cp_next
#undef _
    PPPOE_CP_N_NEXT,
} pppoe_cp_next_t;

typedef struct {
  u32 next_index;
  u32 sw_if_index;
  u32 cp_if_index;
  u8 pppoe_code;
  u16 ppp_proto;
  u32 error;
} pppoe_cp_trace_t;

static u8 * format_pppoe_cp_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pppoe_cp_trace_t * t = va_arg (*args, pppoe_cp_trace_t *);
  pppoe_main_t * pem = &pppoe_main;

  if (t->sw_if_index != pem->cp_if_index)
    {
      s = format (s, "PPPoE dispatch from sw_if_index %d next %d error %d \n"
	          "  pppoe_code 0x%x  ppp_proto 0x%x",
                  t->sw_if_index, t->next_index, t->error,
		  t->pppoe_code, t->ppp_proto);
    }
  else
    {
      s = format (s, "PPPoE dispatch from cp_if_index %d next %d error %d \n"
	          "  pppoe_code 0x%x  ppp_proto 0x%x",
                  t->cp_if_index, t->next_index, t->error,
		  t->pppoe_code, t->ppp_proto);
    }
  return s;
}

static uword
pppoe_cp_dispatch (vlib_main_t * vm,
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
  pppoe_entry_key_t cached_key;
  pppoe_entry_result_t cached_result;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  /* Clear the one-entry cache in case session table was updated */
  cached_key.raw = ~0;
  cached_result.raw = ~0;	/* warning be gone */

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
	  ethernet_header_t *h0;
	  pppoe_header_t * pppoe0;
	  pppoe_entry_key_t key0;
	  pppoe_entry_result_t result0;

	  u32 bucket0;
	  u32 next0;
          u32 error0 = 0;
	  u32 rx_sw_if_index0=~0, tx_sw_if_index0=~0, len0;
	  vnet_hw_interface_t *hi;
	  vnet_sw_interface_t *si;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          /* leaves current_data pointing at the pppoe header */
          pppoe0 = vlib_buffer_get_current (b0);
          rx_sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          if (PREDICT_FALSE (pppoe0->ver_type != PPPOE_VER_TYPE))
	    {
	      error0 = PPPOE_ERROR_BAD_VER_TYPE;
	      next0 = PPPOE_INPUT_NEXT_DROP;
	      goto trace00;
	    }

          vlib_buffer_reset(b0);
          h0 = vlib_buffer_get_current (b0);

          if(rx_sw_if_index0 == pem->cp_if_index)
            {
    	      pppoe_lookup_1 (&pem->link_table, &cached_key, &cached_result,
    			      h0->dst_address, 0,
    			      &key0, &bucket0, &result0);
    	      tx_sw_if_index0 = result0.fields.sw_if_index;

              if (PREDICT_FALSE (tx_sw_if_index0 == ~0))
    	        {
    	          error0 = PPPOE_ERROR_NO_SUCH_SESSION;
    	          next0 = PPPOE_INPUT_NEXT_DROP;
    	          goto trace00;
    	        }

              next0 = PPPOE_CP_NEXT_INTERFACE;
              vnet_buffer(b0)->sw_if_index[VLIB_TX] = tx_sw_if_index0;

              /* set src mac address */
              si = vnet_get_sw_interface(vnm, tx_sw_if_index0);
              hi = vnet_get_hw_interface (vnm, si->hw_if_index);
              clib_memcpy (vlib_buffer_get_current (b0)+6, hi->hw_address, 6);
            }
          else
            {
    	      pppoe_lookup_1 (&pem->link_table, &cached_key, &cached_result,
    			      h0->src_address, 0,
    			      &key0, &bucket0, &result0);
    	      tx_sw_if_index0 = result0.fields.sw_if_index;

              /* learn client session */
    	      pppoe_learn_process (&pem->link_table, rx_sw_if_index0,
				   &key0, &cached_key,
    			           &bucket0, &result0);

              next0 = PPPOE_CP_NEXT_INTERFACE;
              vnet_buffer(b0)->sw_if_index[VLIB_TX] = pem->cp_if_index;
            }

	  len0 = vlib_buffer_length_in_chain (vm, b0);

          pkts_decapsulated ++;
          stats_n_packets += 1;
          stats_n_bytes += len0;

	  /* Batch stats increment on the same pppoe session so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (rx_sw_if_index0 != stats_sw_if_index))
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
	      stats_sw_if_index = rx_sw_if_index0;
	    }
        
        trace00:  
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              pppoe_cp_trace_t *tr
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->sw_if_index = tx_sw_if_index0;
              tr->cp_if_index = pem->cp_if_index;
              tr->pppoe_code = pppoe0->code;
              tr->ppp_proto = clib_net_to_host_u16(pppoe0->ppp_proto);
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

VLIB_REGISTER_NODE (pppoe_cp_dispatch_node) = {
  .function = pppoe_cp_dispatch,
  .name = "pppoe-cp-dispatch",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_next_nodes = PPPOE_CP_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPPOE_CP_NEXT_##s] = n,
    foreach_pppoe_cp_next
#undef _
  },

  .format_trace = format_pppoe_cp_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (pppoe_cp_dispatch_node, pppoe_cp_dispatch)

