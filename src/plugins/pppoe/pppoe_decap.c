/*
 * decap.c: pppoe session decap packet processing
 *
 * Copyright (c) 2017 Intel and/or its affiliates.
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
#include <vnet/pg/pg.h>
#include <vnet/ppp/packet.h>
#include <pppoe/pppoe.h>

typedef struct {
  u32 next_index;
  u32 session_index;
  u32 session_id;
  u32 error;
} pppoe_rx_trace_t;

static u8 * format_pppoe_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pppoe_rx_trace_t * t = va_arg (*args, pppoe_rx_trace_t *);

  if (t->session_index != ~0)
    {
      s = format (s, "PPPoE decap from pppoe_session%d session_id %d next %d error %d",
                  t->session_index, t->session_id, t->next_index, t->error);
    }
  else
    {
      s = format (s, "PPPoE decap error - session for session_id %d does not exist",
		  t->session_id);
    }
  return s;
}

static uword
pppoe_input (vlib_main_t * vm,
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
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
	  u32 next0, next1;
	  ethernet_header_t *h0, *h1;
          pppoe_header_t * pppoe0, * pppoe1;
          u16 ppp_proto0 = 0, ppp_proto1 = 0;
          pppoe_session_t * t0, * t1;
          u32 error0, error1;
	  u32 sw_if_index0, sw_if_index1, len0, len1;
	  pppoe_entry_key_t key0, key1;
	  pppoe_entry_result_t result0, result1;
	  u32 bucket0, bucket1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
          error0 = 0;
          error1 = 0;

          /* leaves current_data pointing at the pppoe header */
          pppoe0 = vlib_buffer_get_current (b0);
          pppoe1 = vlib_buffer_get_current (b1);
          ppp_proto0 = clib_net_to_host_u16(pppoe0->ppp_proto);
          ppp_proto1 = clib_net_to_host_u16(pppoe1->ppp_proto);

          /* Manipulate packet 0 */
          if ((ppp_proto0 != PPP_PROTOCOL_ip4)
             && (ppp_proto0 != PPP_PROTOCOL_ip6))
            {
	      error0 = PPPOE_ERROR_CONTROL_PLANE;
	      next0 = PPPOE_INPUT_NEXT_CP_INPUT;
	      goto trace0;
            }

          /* get client mac */
          vlib_buffer_reset(b0);
          h0 = vlib_buffer_get_current (b0);

	  pppoe_lookup_1 (&pem->session_table, &cached_key, &cached_result,
			  h0->src_address, pppoe0->session_id,
			  &key0, &bucket0, &result0);
          if (PREDICT_FALSE (result0.fields.session_index == ~0))
	    {
	      error0 = PPPOE_ERROR_NO_SUCH_SESSION;
	      next0 = PPPOE_INPUT_NEXT_DROP;
	      goto trace0;
	    }

	  t0 = pool_elt_at_index (pem->sessions,
				  result0.fields.session_index);

	  /* Pop Eth and PPPPoE header */
	  vlib_buffer_advance(b0, sizeof(*h0)+sizeof(*pppoe0));

	  next0 = (ppp_proto0==PPP_PROTOCOL_ip4)?
		  PPPOE_INPUT_NEXT_IP4_INPUT
		  : PPPOE_INPUT_NEXT_IP6_INPUT;

          sw_if_index0 = t0->sw_if_index;
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

        trace0:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              pppoe_rx_trace_t *tr
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->session_index = result0.fields.session_index;
              tr->session_id = clib_net_to_host_u32(pppoe0->session_id);
            }


          /* Manipulate packet 1 */
          if ((ppp_proto1 != PPP_PROTOCOL_ip4)
             && (ppp_proto1 != PPP_PROTOCOL_ip6))
            {
	      error1 = PPPOE_ERROR_CONTROL_PLANE;
	      next1 = PPPOE_INPUT_NEXT_CP_INPUT;
	      goto trace1;
            }

          /* get client mac */
          vlib_buffer_reset(b1);
          h1 = vlib_buffer_get_current (b1);

	  pppoe_lookup_1 (&pem->session_table, &cached_key, &cached_result,
			  h1->src_address, pppoe1->session_id,
			  &key1, &bucket1, &result1);
          if (PREDICT_FALSE (result1.fields.session_index == ~0))
	    {
	      error1 = PPPOE_ERROR_NO_SUCH_SESSION;
	      next1 = PPPOE_INPUT_NEXT_DROP;
	      goto trace1;
	    }

	  t1 = pool_elt_at_index (pem->sessions,
				  result1.fields.session_index);

	  /* Pop Eth and PPPPoE header */
	  vlib_buffer_advance(b1, sizeof(*h1)+sizeof(*pppoe1));

	  next1 = (ppp_proto1==PPP_PROTOCOL_ip4)?
		  PPPOE_INPUT_NEXT_IP4_INPUT
		  : PPPOE_INPUT_NEXT_IP6_INPUT;

          sw_if_index1 = t1->sw_if_index;
          len1 = vlib_buffer_length_in_chain (vm, b1);

          pkts_decapsulated ++;
          stats_n_packets += 1;
          stats_n_bytes += len1;

	  /* Batch stats increment on the same pppoe session so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (sw_if_index1 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len1;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len1;
	      stats_sw_if_index = sw_if_index1;
	    }

        trace1:
          b1->error = error1 ? node->errors[error1] : 0;

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
              pppoe_rx_trace_t *tr
                = vlib_add_trace (vm, node, b1, sizeof (*tr));
              tr->next_index = next1;
              tr->error = error1;
              tr->session_index = result1.fields.session_index;
              tr->session_id = clib_net_to_host_u32(pppoe1->session_id);
            }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
	  u32 next0;
	  ethernet_header_t *h0;
          pppoe_header_t * pppoe0;
          u16 ppp_proto0 = 0;
          pppoe_session_t * t0;
          u32 error0;
	  u32 sw_if_index0, len0;
	  pppoe_entry_key_t key0;
	  pppoe_entry_result_t result0;
	  u32 bucket0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  error0 = 0;

          /* leaves current_data pointing at the pppoe header */
          pppoe0 = vlib_buffer_get_current (b0);
          ppp_proto0 = clib_net_to_host_u16(pppoe0->ppp_proto);

          if ((ppp_proto0 != PPP_PROTOCOL_ip4)
             && (ppp_proto0 != PPP_PROTOCOL_ip6))
            {
	      error0 = PPPOE_ERROR_CONTROL_PLANE;
	      next0 = PPPOE_INPUT_NEXT_CP_INPUT;
	      goto trace00;
            }

          /* get client mac */
          vlib_buffer_reset(b0);
          h0 = vlib_buffer_get_current (b0);

	  pppoe_lookup_1 (&pem->session_table, &cached_key, &cached_result,
			  h0->src_address, pppoe0->session_id,
			  &key0, &bucket0, &result0);
          if (PREDICT_FALSE (result0.fields.session_index == ~0))
	    {
	      error0 = PPPOE_ERROR_NO_SUCH_SESSION;
	      next0 = PPPOE_INPUT_NEXT_DROP;
	      goto trace00;
	    }

	  t0 = pool_elt_at_index (pem->sessions,
				  result0.fields.session_index);

	  /* Pop Eth and PPPPoE header */
	  vlib_buffer_advance(b0, sizeof(*h0)+sizeof(*pppoe0));

	  next0 = (ppp_proto0==PPP_PROTOCOL_ip4)?
		  PPPOE_INPUT_NEXT_IP4_INPUT
		  : PPPOE_INPUT_NEXT_IP6_INPUT;

	  sw_if_index0 = t0->sw_if_index;
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

        trace00:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              pppoe_rx_trace_t *tr
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->session_index = result0.fields.session_index;
              tr->session_id = clib_net_to_host_u16(pppoe0->session_id);
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

static char * pppoe_error_strings[] = {
#define pppoe_error(n,s) s,
#include <pppoe/pppoe_error.def>
#undef pppoe_error
#undef _
};

VLIB_REGISTER_NODE (pppoe_input_node) = {
  .function = pppoe_input,
  .name = "pppoe-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = PPPOE_N_ERROR,
  .error_strings = pppoe_error_strings,

  .n_next_nodes = PPPOE_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPPOE_INPUT_NEXT_##s] = n,
    foreach_pppoe_input_next
#undef _
  },

  .format_trace = format_pppoe_rx_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (pppoe_input_node, pppoe_input)


