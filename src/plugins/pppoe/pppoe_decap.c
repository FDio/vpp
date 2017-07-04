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
      s = format (s, "PPPOE decap from pppoe_session%d session_id %d next %d error %d",
                  t->session_index, t->session_id, t->next_index, t->error);
    }
  else
    {
      s = format (s, "PPPOE decap error - session for session_id %d does not exist",
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
  u32 last_session_index = ~0;
  pppoe4_session_key_t last_key4;
  pppoe6_session_key_t last_key6;
  u32 pkts_decapsulated = 0;
  u32 thread_index = vlib_get_thread_index();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;

  last_key4.client_ip = ~0;
  memset (&last_key6, 0xff, sizeof (last_key6));

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
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
	  u32 next0, next1;
          ip4_header_t * ip4_0, * ip4_1;
          ip6_header_t * ip6_0, * ip6_1;
          pppoe_header_t * pppoe0, * pppoe1;
          u16 ppp_proto0 = 0, ppp_proto1 = 0;
	  uword * p0, * p1;
          u32 session_index0, session_index1;
          pppoe_session_t * t0, * t1;
          pppoe4_session_key_t key4_0, key4_1;
          pppoe6_session_key_t key6_0, key6_1;
          u32 error0, error1;
	  u32 sw_if_index0, sw_if_index1, len0, len1;

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

          session_index0 = ~0;
          error0 = 0;

          session_index1 = ~0;
          error1 = 0;

          /* Manipulate packet 0 */
          /* leaves current_data pointing at the pppoe header */
          pppoe0 = vlib_buffer_get_current (b0);
          if (PREDICT_FALSE (pppoe0->ver_type != PPPOE_VER_TYPE))
	    {
	      error0 = PPPOE_ERROR_BAD_VER_TYPE;
	      next0 = PPPOE_INPUT_NEXT_DROP;
	      goto trace0;
	    }
          ppp_proto0 = clib_net_to_host_u16(pppoe0->ppp_proto);

          /* Pop PPPPoE header */
          vlib_buffer_advance(b0, sizeof(*pppoe0));

          if (ppp_proto0 == PPP_PROTOCOL_ip4) {
            ip4_0 = vlib_buffer_get_current (b0);
            key4_0.client_ip = ip4_0->src_address.as_u32;

 	    /* Make sure PPPOE session exist according to packet SIP.
 	     * SIP identify a PPPOE session */
            if (PREDICT_FALSE (key4_0.client_ip != last_key4.client_ip))
              {
                p0 = hash_get (pem->pppoe4_session_by_key, key4_0.client_ip);
                if (PREDICT_FALSE (p0 == NULL))
                  {
                    error0 = PPPOE_ERROR_NO_SUCH_SESSION;
                    next0 = PPPOE_INPUT_NEXT_DROP;
                    goto trace0;
                  }
                last_key4.client_ip = key4_0.client_ip;
                session_index0 = last_session_index = p0[0];
              }
            else
              session_index0 = last_session_index;
	    t0 = pool_elt_at_index (pem->sessions, session_index0);

	    /* Validate PPPOE session_id against packet session_id */
	    if (PREDICT_TRUE (pppoe0->session_id ==
		  clib_host_to_net_u16(t0->session_id)))
	      {
		next0 = PPPOE_INPUT_NEXT_IP4_INPUT;
		goto next0; /* valid packet */
	      }

	    error0 = PPPOE_ERROR_NO_SUCH_SESSION;
	    next0 = PPPOE_INPUT_NEXT_DROP;
	    goto trace0;

          } else /* !is_ip4 */ {
            ip6_0 = vlib_buffer_get_current (b0);
            key6_0.client_ip.as_u64[0] = ip6_0->src_address.as_u64[0];
            key6_0.client_ip.as_u64[1] = ip6_0->src_address.as_u64[1];

 	    /* Make sure PPPOE session exist according to packet SIP.
 	     * SIP identify a PPPOE session */
            if (PREDICT_FALSE (memcmp(&key6_0, &last_key6, sizeof(last_key6)) != 0))
              {
                p0 = hash_get_mem (pem->pppoe6_session_by_key, &key6_0);
                if (PREDICT_FALSE (p0 == NULL))
                  {
                    error0 = PPPOE_ERROR_NO_SUCH_SESSION;
                    next0 = PPPOE_INPUT_NEXT_DROP;
                    goto trace0;
                  }
                clib_memcpy (&last_key6, &key6_0, sizeof(key6_0));
                session_index0 = last_session_index = p0[0];
              }
            else
              session_index0 = last_session_index;
	    t0 = pool_elt_at_index (pem->sessions, session_index0);

	    /* Validate PPPOE session_id against packet session_id */
	    if (PREDICT_TRUE (pppoe0->session_id ==
		  clib_host_to_net_u16(t0->session_id)))
	      {
		next0 = PPPOE_INPUT_NEXT_IP6_INPUT;
		goto next0; /* valid packet */
	      }

	    error0 = PPPOE_ERROR_NO_SUCH_SESSION;
	    next0 = PPPOE_INPUT_NEXT_DROP;
	    goto trace0;
          }

	next0:
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
              tr->session_index = session_index0;
              tr->session_id = clib_net_to_host_u32(pppoe0->session_id);
            }


          /* Manipulate packet 1 */
          /* leaves current_data pointing at the pppoe header */
          pppoe1 = vlib_buffer_get_current (b1);
          if (PREDICT_FALSE (pppoe1->ver_type != PPPOE_VER_TYPE))
	    {
	      error1 = PPPOE_ERROR_BAD_VER_TYPE;
	      next1 = PPPOE_INPUT_NEXT_DROP;
	      goto trace1;
	    }
          ppp_proto1 = clib_net_to_host_u16(pppoe1->ppp_proto);

          /* Pop PPPPoE header */
          vlib_buffer_advance(b1, sizeof(*pppoe1));

          if (ppp_proto1 == PPP_PROTOCOL_ip4) {
            ip4_1 = vlib_buffer_get_current (b1);
            key4_1.client_ip = ip4_1->src_address.as_u32;

 	    /* Make sure PPPOE session exist according to packet SIP.
 	     * SIP identify a PPPOE session */
            if (PREDICT_FALSE (key4_1.client_ip != last_key4.client_ip))
              {
                p1 = hash_get (pem->pppoe4_session_by_key, key4_1.client_ip);
                if (PREDICT_FALSE (p1 == NULL))
                  {
                    error1 = PPPOE_ERROR_NO_SUCH_SESSION;
                    next1 = PPPOE_INPUT_NEXT_DROP;
                    goto trace1;
                  }
                last_key4.client_ip = key4_1.client_ip;
                session_index1 = last_session_index = p1[0];
              }
            else
              session_index1 = last_session_index;
	    t1 = pool_elt_at_index (pem->sessions, session_index1);

	    /* Validate PPPOE session_id against packet session_id */
	    if (PREDICT_TRUE (pppoe1->session_id ==
		  clib_host_to_net_u16(t1->session_id)))
	      {
		next1 = PPPOE_INPUT_NEXT_IP4_INPUT;
		goto next1; /* valid packet */
	      }

	    error1 = PPPOE_ERROR_NO_SUCH_SESSION;
	    next1 = PPPOE_INPUT_NEXT_DROP;
	    goto trace1;

          } else /* !is_ip4 */ {
            ip6_1 = vlib_buffer_get_current (b1);
            key6_1.client_ip.as_u64[0] = ip6_1->src_address.as_u64[0];
            key6_1.client_ip.as_u64[1] = ip6_1->src_address.as_u64[1];

 	    /* Make sure PPPOE session exist according to packet SIP.
 	     * SIP identify a PPPOE session */
            if (PREDICT_FALSE (memcmp(&key6_1, &last_key6, sizeof(last_key6)) != 0))
              {
                p1 = hash_get_mem (pem->pppoe6_session_by_key, &key6_1);
                if (PREDICT_FALSE (p1 == NULL))
                  {
                    error1 = PPPOE_ERROR_NO_SUCH_SESSION;
                    next1 = PPPOE_INPUT_NEXT_DROP;
                    goto trace1;
                  }
                clib_memcpy (&last_key6, &key6_1, sizeof(key6_1));
                session_index1 = last_session_index = p1[0];
              }
            else
              session_index1 = last_session_index;
	    t1 = pool_elt_at_index (pem->sessions, session_index1);

	    /* Validate PPPOE session_id against packet session_id */
	    if (PREDICT_TRUE (pppoe1->session_id ==
		  clib_host_to_net_u16(t1->session_id)))
	      {
		next1 = PPPOE_INPUT_NEXT_IP6_INPUT;
		goto next1; /* valid packet */
	      }

	    error1 = PPPOE_ERROR_NO_SUCH_SESSION;
	    next1 = PPPOE_INPUT_NEXT_DROP;
	    goto trace1;
          }

	next1:
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
              tr->session_index = session_index1;
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
          ip4_header_t * ip4_0;
          ip6_header_t * ip6_0;
          pppoe_header_t * pppoe0;
          u16 ppp_proto0 = 0;
	  uword * p0;
          u32 session_index0;
          pppoe_session_t * t0;
          pppoe4_session_key_t key4_0;
          pppoe6_session_key_t key6_0;
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
          pppoe0 = vlib_buffer_get_current (b0);
          session_index0 = ~0;
          error0 = 0;
          if (PREDICT_FALSE (pppoe0->ver_type != PPPOE_VER_TYPE))
	    {
	      error0 = PPPOE_ERROR_BAD_VER_TYPE;
	      next0 = PPPOE_INPUT_NEXT_DROP;
	      goto trace00;
	    }
          ppp_proto0 = clib_net_to_host_u16(pppoe0->ppp_proto);

          /* Pop PPPPoE header */
          vlib_buffer_advance(b0, sizeof(*pppoe0));

          if (ppp_proto0 == PPP_PROTOCOL_ip4) {
            ip4_0 = vlib_buffer_get_current (b0);
            key4_0.client_ip = ip4_0->src_address.as_u32;

 	    /* Make sure PPPOE session exist according to packet SIP.
 	     * SIP identify a PPPOE session */
            if (PREDICT_FALSE (key4_0.client_ip != last_key4.client_ip))
              {
                p0 = hash_get (pem->pppoe4_session_by_key, key4_0.client_ip);
                if (PREDICT_FALSE (p0 == NULL))
                  {
                    error0 = PPPOE_ERROR_NO_SUCH_SESSION;
                    next0 = PPPOE_INPUT_NEXT_DROP;
                    goto trace00;
                  }
                last_key4.client_ip = key4_0.client_ip;
                session_index0 = last_session_index = p0[0];
              }
            else
              session_index0 = last_session_index;
	    t0 = pool_elt_at_index (pem->sessions, session_index0);

	    /* Validate PPPOE session_id against packet session_id */
	    if (PREDICT_TRUE (pppoe0->session_id ==
		  clib_host_to_net_u16(t0->session_id)))
	      {
		next0 = PPPOE_INPUT_NEXT_IP4_INPUT;
		goto next00; /* valid packet */
	      }

	    error0 = PPPOE_ERROR_NO_SUCH_SESSION;
	    next0 = PPPOE_INPUT_NEXT_DROP;
	    goto trace00;

          } else /* !is_ip4 */ {
            ip6_0 = vlib_buffer_get_current (b0);
            key6_0.client_ip.as_u64[0] = ip6_0->src_address.as_u64[0];
            key6_0.client_ip.as_u64[1] = ip6_0->src_address.as_u64[1];

 	    /* Make sure PPPOE session exist according to packet SIP.
 	     * SIP identify a PPPOE session */
            if (PREDICT_FALSE (memcmp(&key6_0, &last_key6, sizeof(last_key6)) != 0))
              {
                p0 = hash_get_mem (pem->pppoe6_session_by_key, &key6_0);
                if (PREDICT_FALSE (p0 == NULL))
                  {
                    error0 = PPPOE_ERROR_NO_SUCH_SESSION;
                    next0 = PPPOE_INPUT_NEXT_DROP;
                    goto trace00;
                  }
                clib_memcpy (&last_key6, &key6_0, sizeof(key6_0));
                session_index0 = last_session_index = p0[0];
              }
            else
              session_index0 = last_session_index;
	    t0 = pool_elt_at_index (pem->sessions, session_index0);

	    /* Validate PPPOE session_id against packet session_id */
	    if (PREDICT_TRUE (pppoe0->session_id ==
		  clib_host_to_net_u16(t0->session_id)))
	      {
		next0 = PPPOE_INPUT_NEXT_IP6_INPUT;
		goto next00; /* valid packet */
	      }

	    error0 = PPPOE_ERROR_NO_SUCH_SESSION;
	    next0 = PPPOE_INPUT_NEXT_DROP;
	    goto trace00;
          }

	next00:
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
              tr->session_index = session_index0;
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

//temp  .format_buffer = format_pppoe_header,
  .format_trace = format_pppoe_rx_trace,
  // $$$$ .unformat_buffer = unformat_pppoe_header,
};

VLIB_NODE_FUNCTION_MULTIARCH (pppoe_input_node, pppoe_input)


