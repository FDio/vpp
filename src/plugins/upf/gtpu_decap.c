/*
 * decap.c: gtpu tunnel decap packet processing
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

#define _LGPL_SOURCE            /* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>          /* QSBR RCU flavor */

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <upf/upf.h>
#include <upf/upf_pfcp.h>

#if CLIB_DEBUG > 0
#define gtp_debug clib_warning
#else
#define gtp_debug(...)				\
  do { } while (0)
#endif

vlib_node_registration_t gtpu4_input_node;
vlib_node_registration_t gtpu6_input_node;

typedef enum
{
  GTPU_INPUT_NEXT_DROP,
  GTPU_INPUT_NEXT_IP4_CLASSIFY,
  GTPU_INPUT_NEXT_IP6_CLASSIFY,
  GTPU_INPUT_NEXT_ERROR_INDICATION,
  GTPU_INPUT_NEXT_ECHO_REQUEST,
  GTPU_INPUT_N_NEXT,
} gtpu_input_next_t;

typedef struct {
  u32 next_index;
  u32 session_index;
  u32 error;
  u32 teid;
} gtpu_rx_trace_t;

static u8 * format_gtpu_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gtpu_rx_trace_t * t = va_arg (*args, gtpu_rx_trace_t *);

  if (t->session_index != ~0)
    {
      s = format (s, "GTPU decap from gtpu_session%d teid 0x%08x next %d error %d",
		  t->session_index, t->teid, t->next_index, t->error);
    }
  else
    {
      s = format (s, "GTPU decap error - session for teid 0x%08x does not exist",
		  t->teid);
    }
  return s;
}

always_inline uword
gtpu_input (vlib_main_t * vm,
	     vlib_node_runtime_t * node,
	     vlib_frame_t * from_frame,
	     u8 is_ip4)
{
  u32 n_left_from, next_index, * from, * to_next;
  upf_main_t * gtm = &upf_main;
  vnet_main_t * vnm = gtm->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;
  u32 last_session_index = ~0;
  gtpu4_tunnel_key_t last_key4;
  clib_bihash_kv_24_8_t last_key6;
  u32 pkts_decapsulated = 0;
  u32 thread_index = vlib_get_thread_index();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;

  if (is_ip4)
    last_key4.as_u64 = ~0;
  else
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
	  gtpu_header_t * gtpu0, * gtpu1;
	  u32 gtpu_hdr_len0 = 0, gtpu_hdr_len1 =0 ;
	  u32 session_index0, session_index1;
	  upf_session_t * t0, * t1;
	  gtpu4_tunnel_key_t key4_0, key4_1;
	  u32 error0, error1;
	  u32 sw_if_index0, sw_if_index1, len0, len1;
	  u16 hdr_len0, hdr_len1;

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

	  /* udp leaves current_data pointing at the gtpu header */
	  gtpu0 = vlib_buffer_get_current (b0);
	  gtpu1 = vlib_buffer_get_current (b1);
	  hdr_len0 = is_ip4 ? sizeof(*ip4_0) : sizeof(*ip6_0);
	  hdr_len0 += sizeof(udp_header_t);
	  hdr_len1 = is_ip4 ? sizeof(*ip4_1) : sizeof(*ip6_1);
	  hdr_len1 += sizeof(udp_header_t);

	  if (is_ip4) {
	    vlib_buffer_advance
	      (b0, -(word)(sizeof(udp_header_t)+sizeof(ip4_header_t)));
	    vlib_buffer_advance
	      (b1, -(word)(sizeof(udp_header_t)+sizeof(ip4_header_t)));
	    ip4_0 = vlib_buffer_get_current (b0);
	    ip4_1 = vlib_buffer_get_current (b1);
	  } else {
	    vlib_buffer_advance
	      (b0, -(word)(sizeof(udp_header_t)+sizeof(ip6_header_t)));
	    vlib_buffer_advance
	      (b1, -(word)(sizeof(udp_header_t)+sizeof(ip6_header_t)));
	    ip6_0 = vlib_buffer_get_current (b0);
	    ip6_1 = vlib_buffer_get_current (b1);
	  }

	  session_index0 = ~0;
	  error0 = 0;

	  session_index1 = ~0;
	  error1 = 0;

	  if (PREDICT_FALSE ((gtpu0->ver_flags & GTPU_VER_MASK) != GTPU_V1_VER))
	    {
	      error0 = GTPU_ERROR_BAD_VER;
	      next0 = GTPU_INPUT_NEXT_DROP;
	      goto trace0;
	    }

	  if (PREDICT_FALSE (gtpu0->type != GTPU_TYPE_GTPU))
	    {
	      switch (gtpu0->type)
		{
		case GTPU_TYPE_ERROR_IND:
		  next0 = GTPU_INPUT_NEXT_ERROR_INDICATION;
		  break;

		case GTPU_TYPE_ECHO_REQUEST:
		  next0 = GTPU_INPUT_NEXT_ECHO_REQUEST;
		  break;

		case GTPU_TYPE_ECHO_RESPONSE:
		  // TODO next0 = GTPU_INPUT_NEXT_ECHO_RESPONSE;
		  next0 = GTPU_INPUT_NEXT_DROP;
		  break;

		default:
		  next0 = GTPU_INPUT_NEXT_DROP;
		  break;
		}

	      goto trace0;
	    }

	  /* Manipulate packet 0 */
	  if (is_ip4) {
	    key4_0.dst = ip4_0->dst_address.as_u32;
	    key4_0.teid = clib_net_to_host_u32(gtpu0->teid);

	    /* Make sure GTPU tunnel exist according to packet destination IP and teid
	     * destination identifies a GTP-U entity, and teid identifies a tunnel
	     * on a given GTP-U entity */
	   if (PREDICT_FALSE (key4_0.as_u64 != last_key4.as_u64))
	      {
		clib_bihash_kv_8_8_t kv, value;

		kv.key = key4_0.as_u64;

		if (PREDICT_FALSE (clib_bihash_search_8_8 (&gtm->v4_tunnel_by_key, &kv, &value)))
		  {
		    error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
		    next0 = GTPU_INPUT_NEXT_DROP;
		    goto trace0;
		  }
		last_key4.as_u64 = key4_0.as_u64;
		session_index0 = last_session_index = value.value;
	      }
	    else
	      session_index0 = last_session_index;
	    t0 = pool_elt_at_index (gtm->sessions, session_index0);

	    goto next0; /* valid packet */

	 } else /* !is_ip4 */ {
	    clib_bihash_kv_24_8_t kv, value;

	    kv.key[0] = ip6_0->dst_address.as_u64[0];
	    kv.key[1] = ip6_0->dst_address.as_u64[1];
	    kv.key[2] = clib_net_to_host_u32(gtpu0->teid);

	    /* Make sure GTPU tunnel exist according to packet destination IP and teid
	     * destination identifies a GTP-U entity, and teid identifies a tunnel
	     * on a given GTP-U entity */
	    if (PREDICT_FALSE (memcmp(&kv.key, &last_key6.key, sizeof(last_key6.key)) != 0))
	      {
		if (PREDICT_FALSE (clib_bihash_search_24_8 (&gtm->v6_tunnel_by_key, &kv, &value)))
		  {
		    error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
		    next0 = GTPU_INPUT_NEXT_DROP;
		    goto trace0;
		  }
		clib_memcpy (&last_key6.key, &kv.key, sizeof(kv.key));
		session_index0 = last_session_index = value.value;
	      }
	    else
	      session_index0 = last_session_index;
	    t0 = pool_elt_at_index (gtm->sessions, session_index0);

	    goto next0; /* valid packet */
	  }

	next0:
	  /* Manipulate gtpu header */
	  if (PREDICT_FALSE((gtpu0->ver_flags & GTPU_E_S_PN_BIT) != 0))
	    {
	      gtpu_hdr_len0 = sizeof(gtpu_header_t);

	      /* Manipulate Sequence Number and N-PDU Number */
	      /* TBD */

	      /* Manipulate Next Extension Header */
	      /* TBD */
	    }
	  else
	    {
	      gtpu_hdr_len0 = sizeof(gtpu_header_t) - 4;
	    }

	  hdr_len0 += gtpu_hdr_len0;
	  vnet_buffer (b0)->gtpu.data_offset = hdr_len0;
	  vnet_buffer (b0)->gtpu.teid = clib_net_to_host_u32(gtpu0->teid);
	  vnet_buffer (b0)->gtpu.session_index = session_index0;
	  vnet_buffer (b0)->gtpu.flags = is_ip4 ? BUFFER_GTP_UDP_IP4 : BUFFER_GTP_UDP_IP6;

	  /* inner IP header */
	  ip4_0 = vlib_buffer_get_current (b0) + hdr_len0;
	  next0 = ((ip4_0->ip_version_and_header_length & 0xF0) == 0x40) ?
	    GTPU_INPUT_NEXT_IP4_CLASSIFY : GTPU_INPUT_NEXT_IP6_CLASSIFY;

	   vnet_buffer (b0)->gtpu.src_intf =
		   gtm->intf_type_by_sw_if_index[vnet_buffer(b0)->sw_if_index[VLIB_RX]];

	  sw_if_index0 = t0->sw_if_index;
	  len0 = vlib_buffer_length_in_chain (vm, b0) - hdr_len0;

	  /* Set packet input sw_if_index to unicast GTPU tunnel for learning */
	  vnet_buffer(b0)->sw_if_index[VLIB_RX] = sw_if_index0;

	  pkts_decapsulated ++;
	  stats_n_packets += 1;
	  stats_n_bytes += len0;

	  /* Batch stats increment on the same gtpu tunnel so counter
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
	      gtpu_rx_trace_t *tr
		= vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->error = error0;
	      tr->session_index = session_index0;
	      tr->teid = clib_net_to_host_u32(gtpu0->teid);
	    }

	  if (PREDICT_FALSE ((gtpu1->ver_flags & GTPU_VER_MASK) != GTPU_V1_VER))
	    {
	      error1 = GTPU_ERROR_BAD_VER;
	      next1 = GTPU_INPUT_NEXT_DROP;
	      goto trace1;
	    }

	  if (PREDICT_FALSE (gtpu1->type != GTPU_TYPE_GTPU))
	    {
	      switch (gtpu1->type)
		{
		case GTPU_TYPE_ERROR_IND:
		  next1 = GTPU_INPUT_NEXT_ERROR_INDICATION;
		  break;

		case GTPU_TYPE_ECHO_REQUEST:
		  next1 = GTPU_INPUT_NEXT_ECHO_REQUEST;
		  break;

		case GTPU_TYPE_ECHO_RESPONSE:
		  // TODO next0 = GTPU_INPUT_NEXT_ECHO_RESPONSE;
		  next1 = GTPU_INPUT_NEXT_DROP;
		  break;

		default:
		  next1 = GTPU_INPUT_NEXT_DROP;
		  break;
		}

	      goto trace1;
	    }

	  /* Manipulate packet 1 */
	  if (is_ip4) {
	    key4_1.dst = ip4_1->dst_address.as_u32;
	    key4_1.teid = clib_net_to_host_u32(gtpu1->teid);

	    /* Make sure GTPU tunnel exist according to packet destination IP and teid
	     * destination identifies a GTP-U entity, and teid identifies a tunnel
	     * on a given GTP-U entity */
	    if (PREDICT_FALSE (key4_1.as_u64 != last_key4.as_u64))
	      {
		clib_bihash_kv_8_8_t kv, value;

		kv.key = key4_1.as_u64;

		if (PREDICT_FALSE (clib_bihash_search_8_8 (&gtm->v4_tunnel_by_key, &kv, &value)))
		  {
		    error1 = GTPU_ERROR_NO_SUCH_TUNNEL;
		    next1 = GTPU_INPUT_NEXT_DROP;
		    goto trace1;
		  }
		last_key4.as_u64 = key4_1.as_u64;
		session_index1 = last_session_index = value.value;
	      }
	    else
	      session_index1 = last_session_index;
	    t1 = pool_elt_at_index (gtm->sessions, session_index1);

	    goto next1; /* valid packet */

	 } else /* !is_ip4 */ {
	    clib_bihash_kv_24_8_t kv, value;

	    kv.key[0] = ip6_1->dst_address.as_u64[0];
	    kv.key[1] = ip6_1->dst_address.as_u64[1];
	    kv.key[2] = clib_net_to_host_u32(gtpu1->teid);

	    /* Make sure GTPU tunnel exist according to packet destination IP and teid
	     * destination identifies a GTP-U entity, and teid identifies a tunnel
	     * on a given GTP-U entity */
	    if (PREDICT_FALSE (memcmp(&kv.key, &last_key6.key, sizeof(last_key6.key)) != 0))
	      {
		if (PREDICT_FALSE (clib_bihash_search_24_8 (&gtm->v6_tunnel_by_key, &kv, &value)))
		  {
		    error1 = GTPU_ERROR_NO_SUCH_TUNNEL;
		    next1 = GTPU_INPUT_NEXT_DROP;
		    goto trace1;
		  }
		clib_memcpy (&last_key6.key, &kv.key, sizeof(kv.key));
		session_index1 = last_session_index = value.value;
	      }
	    else
	      session_index1 = last_session_index;
	    t1 = pool_elt_at_index (gtm->sessions, session_index1);

	    goto next1; /* valid packet */
	  }

	next1:
	  /* Manipulate gtpu header */
	  if (PREDICT_FALSE((gtpu1->ver_flags & GTPU_E_S_PN_BIT) != 0))
	    {
	      gtpu_hdr_len1 = sizeof(gtpu_header_t);

	      /* Manipulate Sequence Number and N-PDU Number */
	      /* TBD */

	      /* Manipulate Next Extension Header */
	      /* TBD */
	    }
	  else
	    {
	      gtpu_hdr_len1 = sizeof(gtpu_header_t) - 4;
	    }

	  hdr_len1 += gtpu_hdr_len1;
	  vnet_buffer (b1)->gtpu.data_offset = hdr_len1;
	  vnet_buffer (b1)->gtpu.teid = clib_net_to_host_u32(gtpu1->teid);
	  vnet_buffer (b1)->gtpu.session_index = session_index1;
	  vnet_buffer (b1)->gtpu.flags = is_ip4 ? BUFFER_GTP_UDP_IP4 : BUFFER_GTP_UDP_IP6;

	  /* inner IP header */
	  ip4_1 = vlib_buffer_get_current (b1) + hdr_len1;
	  next1 = ((ip4_1->ip_version_and_header_length & 0xF0) == 0x40) ?
	    GTPU_INPUT_NEXT_IP4_CLASSIFY : GTPU_INPUT_NEXT_IP6_CLASSIFY;

	  vnet_buffer (b1)->gtpu.src_intf =
		  gtm->intf_type_by_sw_if_index[vnet_buffer(b1)->sw_if_index[VLIB_RX]];

	  sw_if_index1 = t1->sw_if_index;
	  len1 = vlib_buffer_length_in_chain (vm, b1) - hdr_len1;

	  /* Set packet input sw_if_index to unicast GTPU tunnel for learning */
	  vnet_buffer(b1)->sw_if_index[VLIB_RX] = sw_if_index1;

	  pkts_decapsulated ++;
	  stats_n_packets += 1;
	  stats_n_bytes += len1;

	  /* Batch stats increment on the same gtpu tunnel so counter
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
	      gtpu_rx_trace_t *tr
		= vlib_add_trace (vm, node, b1, sizeof (*tr));
	      tr->next_index = next1;
	      tr->error = error1;
	      tr->session_index = session_index1;
	      tr->teid = clib_net_to_host_u32(gtpu1->teid);
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
	  gtpu_header_t * gtpu0;
	  u32 gtpu_hdr_len0 = 0;
	  u32 session_index0;
	  upf_session_t * t0;
	  gtpu4_tunnel_key_t key4_0;
	  u32 error0;
	  u32 sw_if_index0, len0;
	  u16 hdr_len0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* udp leaves current_data pointing at the gtpu header */
	  gtpu0 = vlib_buffer_get_current (b0);
	  hdr_len0 = is_ip4 ? sizeof(*ip4_0) : sizeof(*ip6_0);
	  hdr_len0 += sizeof(udp_header_t);

	  if (is_ip4) {
	    vlib_buffer_advance
	      (b0, -(word)(sizeof(udp_header_t)+sizeof(ip4_header_t)));
	    ip4_0 = vlib_buffer_get_current (b0);
	  } else {
	    vlib_buffer_advance
	      (b0, -(word)(sizeof(udp_header_t)+sizeof(ip6_header_t)));
	    ip6_0 = vlib_buffer_get_current (b0);
	  }

	  session_index0 = ~0;
	  error0 = 0;

	  if (PREDICT_FALSE ((gtpu0->ver_flags & GTPU_VER_MASK) != GTPU_V1_VER))
	    {
	      error0 = GTPU_ERROR_BAD_VER;
	      next0 = GTPU_INPUT_NEXT_DROP;
	      goto trace00;
	    }

	  if (PREDICT_FALSE (gtpu0->type != GTPU_TYPE_GTPU))
	    {
	      switch (gtpu0->type)
		{
		case GTPU_TYPE_ERROR_IND:
		  next0 = GTPU_INPUT_NEXT_ERROR_INDICATION;
		  break;

		case GTPU_TYPE_ECHO_REQUEST:
		  next0 = GTPU_INPUT_NEXT_ECHO_REQUEST;
		  break;

		case GTPU_TYPE_ECHO_RESPONSE:
		  // TODO next0 = GTPU_INPUT_NEXT_ECHO_RESPONSE;
		  next0 = GTPU_INPUT_NEXT_DROP;
		  break;

		default:
		  next0 = GTPU_INPUT_NEXT_DROP;
		  break;
		}

	      goto trace00;
	    }

	  if (is_ip4) {
	    key4_0.dst = ip4_0->dst_address.as_u32;
	    key4_0.teid = clib_net_to_host_u32(gtpu0->teid);

	    /* Make sure GTPU tunnel exist according to packet destination IP and teid
	     * destination identifies a GTP-U entity, and teid identifies a tunnel
	     * on a given GTP-U entity */
	    if (PREDICT_FALSE (key4_0.as_u64 != last_key4.as_u64))
	      {
		clib_bihash_kv_8_8_t kv, value;

		kv.key = key4_0.as_u64;

		if (PREDICT_FALSE (clib_bihash_search_8_8 (&gtm->v4_tunnel_by_key, &kv, &value)))
		  {
		    error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
		    next0 = GTPU_INPUT_NEXT_DROP;
		    goto trace00;
		  }
		last_key4.as_u64 = key4_0.as_u64;
		session_index0 = last_session_index = value.value;
	      }
	    else
	      session_index0 = last_session_index;
	    t0 = pool_elt_at_index (gtm->sessions, session_index0);

	    goto next00; /* valid packet */

	  } else /* !is_ip4 */ {
	    clib_bihash_kv_24_8_t kv, value;

	    kv.key[0] = ip6_0->dst_address.as_u64[0];
	    kv.key[1] = ip6_0->dst_address.as_u64[1];
	    kv.key[2] = clib_net_to_host_u32(gtpu0->teid);

	    /* Make sure GTPU tunnel exist according to packet destination IP and teid
	     * destination identifies a GTP-U entity, and teid identifies a tunnel
	     * on a given GTP-U entity */
	    if (PREDICT_FALSE (memcmp(&kv.key, &last_key6.key, sizeof(last_key6.key)) != 0))
	      {
		if (PREDICT_FALSE (clib_bihash_search_24_8 (&gtm->v6_tunnel_by_key, &kv, &value)))
		  {
		    error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
		    next0 = GTPU_INPUT_NEXT_DROP;
		    goto trace00;
		  }
		clib_memcpy (&last_key6.key, &kv.key, sizeof(kv.key));
		session_index0 = last_session_index = value.value;
	      }
	    else
	      session_index0 = last_session_index;
	    t0 = pool_elt_at_index (gtm->sessions, session_index0);

	    goto next00; /* valid packet */
	  }

	next00:
	  /* Manipulate gtpu header */
	  if (PREDICT_FALSE((gtpu0->ver_flags & GTPU_E_S_PN_BIT) != 0))
	    {
	      gtpu_hdr_len0 = sizeof(gtpu_header_t);

	      /* Manipulate Sequence Number and N-PDU Number */
	      /* TBD */

	      /* Manipulate Next Extension Header */
	      /* TBD */
	    }
	  else
	    {
	      gtpu_hdr_len0 = sizeof(gtpu_header_t) - 4;
	    }

	  hdr_len0 += gtpu_hdr_len0;
	  vnet_buffer (b0)->gtpu.data_offset = hdr_len0;
	  vnet_buffer (b0)->gtpu.teid = clib_net_to_host_u32(gtpu0->teid);
	  vnet_buffer (b0)->gtpu.session_index = session_index0;
	  vnet_buffer (b0)->gtpu.flags = (is_ip4) ? BUFFER_GTP_UDP_IP4 : BUFFER_GTP_UDP_IP6;

	  /* inner IP header */
	  ip4_0 = vlib_buffer_get_current (b0) + hdr_len0;
	  next0 = ((ip4_0->ip_version_and_header_length & 0xF0) == 0x40) ?
	    GTPU_INPUT_NEXT_IP4_CLASSIFY : GTPU_INPUT_NEXT_IP6_CLASSIFY;

	  vnet_buffer (b0)->gtpu.src_intf =
		  gtm->intf_type_by_sw_if_index[vnet_buffer(b0)->sw_if_index[VLIB_RX]];

	  sw_if_index0 = t0->sw_if_index;
	  len0 = vlib_buffer_length_in_chain (vm, b0) - hdr_len0;

	  /* Set packet input sw_if_index to unicast GTPU tunnel for learning */
	  vnet_buffer(b0)->sw_if_index[VLIB_RX] = sw_if_index0;

	  pkts_decapsulated ++;
	  stats_n_packets += 1;
	  stats_n_bytes += len0;

	  /* Batch stats increment on the same gtpu tunnel so counter
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
	      gtpu_rx_trace_t *tr
		= vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->error = error0;
	      tr->session_index = session_index0;
	      tr->teid = clib_net_to_host_u32(gtpu0->teid);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  /* Do we still need this now that tunnel tx stats is kept? */
  vlib_node_increment_counter (vm, is_ip4?
			       gtpu4_input_node.index:gtpu6_input_node.index,
			       GTPU_ERROR_DECAPSULATED,
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

static uword
gtpu4_input (vlib_main_t * vm,
	     vlib_node_runtime_t * node,
	     vlib_frame_t * from_frame)
{
	return gtpu_input(vm, node, from_frame, /* is_ip4 */ 1);
}

static uword
gtpu6_input (vlib_main_t * vm,
	     vlib_node_runtime_t * node,
	     vlib_frame_t * from_frame)
{
	return gtpu_input(vm, node, from_frame, /* is_ip4 */ 0);
}

static char * gtpu_error_strings[] = {
#define gtpu_error(n,s) s,
#include <upf/gtpu_error.def>
#undef gtpu_error
#undef _
};

VLIB_REGISTER_NODE (gtpu4_input_node) = {
  .function = gtpu4_input,
  .name = "gtpu4-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = GTPU_N_ERROR,
  .error_strings = gtpu_error_strings,

  .n_next_nodes = GTPU_INPUT_N_NEXT,
  .next_nodes = {
    [GTPU_INPUT_NEXT_DROP]             = "error-drop",
    [GTPU_INPUT_NEXT_IP4_CLASSIFY]     = "upf-ip4-classify",
    [GTPU_INPUT_NEXT_IP6_CLASSIFY]     = "upf-ip6-classify",
    [GTPU_INPUT_NEXT_ERROR_INDICATION] = "gtp-error-indication",
    [GTPU_INPUT_NEXT_ECHO_REQUEST]     = "upf-ip4-echo-request",
  },

//temp  .format_buffer = format_gtpu_header,
  .format_trace = format_gtpu_rx_trace,
  // $$$$ .unformat_buffer = unformat_gtpu_header,
};

VLIB_NODE_FUNCTION_MULTIARCH (gtpu4_input_node, gtpu4_input)

VLIB_REGISTER_NODE (gtpu6_input_node) = {
  .function = gtpu6_input,
  .name = "gtpu6-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = GTPU_N_ERROR,
  .error_strings = gtpu_error_strings,

  .n_next_nodes = GTPU_INPUT_N_NEXT,
  .next_nodes = {
    [GTPU_INPUT_NEXT_DROP]             = "error-drop",
    [GTPU_INPUT_NEXT_IP4_CLASSIFY]     = "upf-ip4-classify",
    [GTPU_INPUT_NEXT_IP6_CLASSIFY]     = "upf-ip6-classify",
    [GTPU_INPUT_NEXT_ERROR_INDICATION] = "gtp-error-indication",
    [GTPU_INPUT_NEXT_ECHO_REQUEST]     = "upf-ip6-echo-request",
  },

//temp  .format_buffer = format_gtpu_header,
  .format_trace = format_gtpu_rx_trace,
  // $$$$ .unformat_buffer = unformat_gtpu_header,
};

VLIB_NODE_FUNCTION_MULTIARCH (gtpu6_input_node, gtpu6_input)

typedef struct {
  u32 session_index;
  u32 error;
  gtp_error_ind_t indication;
} gtpu_error_ind_trace_t;

static u8 * format_gtpu_error_ind_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gtpu_error_ind_trace_t * t = va_arg (*args, gtpu_error_ind_trace_t *);

  if (t->session_index != ~0)
    {
      s = format (s, "GTPU Error Indication from %U, for gtpu_session%d teid 0x%08x error %d",
		  format_ip46_address, &t->indication.addr, IP46_TYPE_ANY,
		  t->session_index, t->indication.teid, t->error);
    }
  else
    {
      s = format (s, "GTPU decap error - session for teid 0x%08x does not exist",
		  t->indication.teid);
    }
  return s;
}

static void decode_error_indication_ext_hdr(vlib_buffer_t * b, u8 next_ext_type,
					    gtp_error_ind_t * error)
{
  u8 * start, * end, * p;

  start = p = vlib_buffer_get_current (b);
  end = vlib_buffer_get_tail (b);

  while (next_ext_type != 0 && p < end)
    {
      u16 length = (*p++ * 4) - 2;

      if (end - p < length)
	break;

      switch (next_ext_type)
	{
	case 0x40:		/* Recovery */
	  if (length < 2)
	    break;

	  error->port = clib_net_to_host_u16(*(u16 *)p);
	  break;

	default:
	  break;
	}
      p += length;
      next_ext_type = *p++;
    }

  vlib_buffer_advance (b, p - start);
  return;
}

static int decode_error_indication(vlib_buffer_t * b, gtp_error_ind_t * error)
{
  u8 * p = vlib_buffer_get_current (b);
  u8 * end = vlib_buffer_get_tail (b);
  u8 flag = 0;
  u16 length;
  while (p < end)
    {
      gtp_debug("IE: %d", *p);
      switch (*p++)
	{
	case 14:		/* Recovery */
	  gtp_debug("IE: Recovery");
	  p++;
	  break;

	case 16:		/* Tunnel Endpoint Identifier Data I */
	  gtp_debug("IE: TEID I, %d", end - p);
	  if ((flag & 1) | (end - p < 4))
	    return -1;
	  flag |= 1;
	  error->teid = clib_net_to_host_u32(*(u32 *)p);
	  gtp_debug("IE: TEID I, 0x%08x", error->teid);
	  p += 4;
	  break;

	case 133:		/* GTP-U Peer Address */
	  gtp_debug("IE: Peer, %d", end - p);
	  if ((flag & 2) | (end - p < 2))
	    return -1;
	  flag |= 2;
	  length = clib_net_to_host_u16(*(u16 *)p);
	  gtp_debug("IE: Peer Length, %d, %d", length, end - p);
	  p += 2;
	  if ((end - p) < length)
	    return -1;
	  if (length != 4 && length != 16)
	    return -1;
	  error->addr = to_ip46(length == 16, p);
	  gtp_debug("IE: Peer %U",  format_ip46_address, &error->addr, IP46_TYPE_ANY);
	  p += length;
	  break;

	default:
	  return -1;
	}
    }

  if (flag != 3)
    return -1;

  return 0;
}

static uword
process_error_indication (vlib_main_t * vm,
			  vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
  upf_main_t * gtm = &upf_main;
  u32 *buffers, *first_buffer;
  gtp_error_ind_t error;
  u32 n_errors_left;

  buffers = vlib_frame_args (frame);
  first_buffer = buffers;

  n_errors_left = frame->n_vectors;

  while (n_errors_left >= 1)
    {
      gtpu_header_t * gtpu;
      upf_session_t * t;
      vlib_buffer_t * b;
      u32 session_index = ~0;
      u32 bi, err;
      bi = buffers[0];

      buffers += 1;
      n_errors_left -= 1;

      b = vlib_get_buffer (vm, bi);
      gtpu = vlib_buffer_get_current (b);

      memset(&error, 0, sizeof(error));

      if (PREDICT_FALSE((gtpu->ver_flags & GTPU_E_S_PN_BIT) != 0))
	{
	  /* Pop gtpu header */
	  vlib_buffer_advance (b, sizeof(gtpu_header_t));

	  if ((gtpu->ver_flags & GTPU_E_BIT) != 0)
	    decode_error_indication_ext_hdr(b, gtpu->next_ext_type, &error);
	}
      else
	{
	  /* Pop gtpu header */
	  vlib_buffer_advance (b, sizeof(gtpu_header_t) - 4);
	}

      if (decode_error_indication(b, &error) != 0)
	{
	  err = GTPU_ERROR_NO_SUCH_TUNNEL;
	  goto trace;
	}

      if (ip46_address_is_ip4(&error.addr))
	{
	  clib_bihash_kv_8_8_t kv, value;
	  gtpu4_tunnel_key_t key4;

	  key4.dst = error.addr.ip4.as_u32;
	  key4.teid = error.teid;

	  kv.key = key4.as_u64;

	  if (PREDICT_FALSE (clib_bihash_search_8_8 (&gtm->v4_tunnel_by_key, &kv, &value)))
	    {
	      err = GTPU_ERROR_NO_SUCH_TUNNEL;
	      goto trace;
	    }
	  session_index = value.value;
	}
      else
	{
	  clib_bihash_kv_24_8_t kv, value;

	  kv.key[0] = error.addr.ip6.as_u64[0];
	  kv.key[1] = error.addr.ip6.as_u64[1];
	  kv.key[2] = error.teid;

	  if (PREDICT_FALSE (clib_bihash_search_24_8 (&gtm->v6_tunnel_by_key, &kv, &value)))
	    {
	      err = GTPU_ERROR_NO_SUCH_TUNNEL;
	      goto trace;
	    }
	  session_index = value.value;
	}

      t = pool_elt_at_index (gtm->sessions, session_index);

      upf_pfcp_error_report(t, &error);

    trace:
      if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  gtpu_error_ind_trace_t *tr =
	    vlib_add_trace (vm, node, b, sizeof (*tr));
	  tr->session_index = session_index;
	  tr->error = err;
	  tr->indication = error;
	}

      vlib_buffer_free (vm, first_buffer, frame->n_vectors);
      vlib_frame_free (vm, node, frame);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (gtp_error_ind_node) = {
  .function = process_error_indication,
  .name = "gtp-error-indication",
  .vector_size = sizeof (u32),
//  .format_buffer = format_ip4_header,
  .format_trace = format_gtpu_error_ind_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (gtp_error_ind_node,process_error_indication)


/****************************************************************************/

typedef enum
{
  GTPU_ECHO_REQ_NEXT_DROP,
  GTPU_ECHO_REQ_NEXT_REPLY,
  GTPU_ECHO_REQ_N_NEXT,
} gtpu_echo_req_next_t;

typedef struct {
  u8 packet_data[64];
} gtpu_echo_req_trace_t;

static u8 * format_gtpu_ip4_echo_req_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gtpu_echo_req_trace_t * t = va_arg (*args, gtpu_echo_req_trace_t *);

  return format (s, "%U", format_ip4_header, t->packet_data, sizeof (t->packet_data));
}

static uword
gtpu4_echo_request (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame)
{
  ip4_main_t *i4m = &ip4_main;
  uword n_packets = frame->n_vectors;
  u32 n_left_from, next_index, * from, * to_next;
  u16 *fragment_ids, *fid;
  u8 host_config_ttl = i4m->host_config.ttl;

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   sizeof (from[0]),
				   sizeof (gtpu_echo_req_trace_t));

  /* Get random fragment IDs for replies. */
  fid = fragment_ids = clib_random_buffer_get_data (&vm->random_buffer,
						    n_packets *
						    sizeof (fragment_ids[0]));

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 next0 = GTPU_ECHO_REQ_NEXT_REPLY;
	  u32 error0 = GTPU_ERROR_ECHO_RESPONSES_SENT;
	  ip4_header_t * ip0;
	  udp_header_t * udp0;
	  gtpu_header_t * gtpu0;
	  vlib_buffer_t * p0;
	  u32 bi0;
	  ip4_address_t tmp0;
	  u16 port0;
	  ip_csum_t sum0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  udp0 = ip4_next_header (ip0);

	  gtpu0 = (gtpu_header_t *)(udp0 + 1);
	  gtpu0->type = GTPU_TYPE_ECHO_RESPONSE;

	  vnet_buffer (p0)->sw_if_index[VLIB_RX] =
	    vnet_main.local_interface_sw_if_index;

	  /* Swap source and destination address. */
	  tmp0 = ip0->src_address;
	  ip0->src_address = ip0->dst_address;
	  ip0->dst_address = tmp0;

	  /* Update IP checksum. */
	  sum0 = ip0->checksum;

	  sum0 = ip_csum_update (sum0, ip0->ttl, host_config_ttl,
				 ip4_header_t, ttl);
	  ip0->ttl = host_config_ttl;

	  sum0 = ip_csum_update (sum0, ip0->fragment_id, fid[0],
				 ip4_header_t, fragment_id);
	  ip0->fragment_id = fid[0];
	  fid += 1;

	  ip0->checksum = ip_csum_fold (sum0);

	  ASSERT (ip0->checksum == ip4_header_checksum (ip0));

	  /* Swap source and destination port. */
	  port0 = udp0->src_port;
	  udp0->src_port = udp0->dst_port;
	  udp0->dst_port = port0;

	  /* UDP checksum. */
	  udp0->checksum = 0;
	  udp0->checksum = ip4_tcp_udp_compute_checksum (vm, p0, ip0);
	  if (udp0->checksum == 0)
	    udp0->checksum = 0xffff;

	  p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

	  vlib_error_count (vm, node->node_index, error0, 1);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static u8 * format_gtpu_ip6_echo_req_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gtpu_echo_req_trace_t * t = va_arg (*args, gtpu_echo_req_trace_t *);

  return format (s, "%U", format_ip6_header, t->packet_data, sizeof (t->packet_data));
}

static uword
gtpu6_echo_request (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame)
{
  ip6_main_t *i6m = &ip6_main;
  uword n_packets = frame->n_vectors;
  u32 n_left_from, next_index, * from, * to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   sizeof (from[0]),
				   sizeof (gtpu_echo_req_trace_t));

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 next0 = GTPU_ECHO_REQ_NEXT_REPLY;
	  u32 error0 = GTPU_ERROR_ECHO_RESPONSES_SENT;
	  ip6_header_t * ip0;
	  udp_header_t * udp0;
	  gtpu_header_t * gtpu0;
	  u32 fib_index0;
	  vlib_buffer_t * p0;
	  u32 bi0;
	  ip6_address_t tmp0;
	  u16 port0;
	  int bogus0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  udp0 = ip6_next_header (ip0);

	  gtpu0 = (gtpu_header_t *)(udp0 + 1);
	  gtpu0->type = GTPU_TYPE_ECHO_RESPONSE;

	  /* if the packet is link local, we'll bounce through the link-local
	   * table with the RX interface correctly set */
	  fib_index0 = vec_elt (i6m->fib_index_by_sw_if_index,
				vnet_buffer (p0)->sw_if_index[VLIB_RX]);
	  vnet_buffer (p0)->sw_if_index[VLIB_TX] = fib_index0;

	  /* Swap source and destination address. */
	  tmp0 = ip0->src_address;
	  ip0->src_address = ip0->dst_address;
	  ip0->dst_address = tmp0;

	  ip0->hop_limit = i6m->host_config.ttl;

	  /* Swap source and destination port. */
	  port0 = udp0->src_port;
	  udp0->src_port = udp0->dst_port;
	  udp0->dst_port = port0;

	  /* UDP checksum. */
	  udp0->checksum = 0;
	  udp0->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, p0, ip0, &bogus0);
	  if (udp0->checksum == 0)
	    udp0->checksum = 0xffff;

	  p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

	  vlib_error_count (vm, node->node_index, error0, 1);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (gtp_ip4_echo_req_node) = {
  .function = gtpu4_echo_request,
  .name = "upf-ip4-echo-request",
  .vector_size = sizeof (u32),
  .format_trace = format_gtpu_ip4_echo_req_trace,

  .n_errors = GTPU_N_ERROR,
  .error_strings = gtpu_error_strings,

  .n_next_nodes = GTPU_ECHO_REQ_N_NEXT,
  .next_nodes = {
    [GTPU_ECHO_REQ_NEXT_DROP] = "error-drop",
    [GTPU_ECHO_REQ_NEXT_REPLY] = "ip4-load-balance",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (gtp_ip4_echo_req_node,gtpu4_echo_request)

VLIB_REGISTER_NODE (gtp_ip6_echo_req_node) = {
  .function = gtpu6_echo_request,
  .name = "upf-ip6-echo-request",
  .vector_size = sizeof (u32),
  .format_trace = format_gtpu_ip6_echo_req_trace,

  .n_errors = GTPU_N_ERROR,
  .error_strings = gtpu_error_strings,

  .n_next_nodes = GTPU_ECHO_REQ_N_NEXT,
  .next_nodes = {
    [GTPU_ECHO_REQ_NEXT_DROP] = "error-drop",
    [GTPU_ECHO_REQ_NEXT_REPLY] = "ip6-lookup",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (gtp_ip6_echo_req_node,gtpu6_echo_request)



/****************************************************************************/

typedef enum {
  IP_GTPU_BYPASS_NEXT_DROP,
  IP_GTPU_BYPASS_NEXT_GTPU,
  IP_GTPU_BYPASS_N_NEXT,
} ip_vxan_bypass_next_t;

always_inline uword
ip_gtpu_bypass_inline (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			vlib_frame_t * frame,
			u32 is_ip4)
{
  //  upf_main_t * gtm = &upf_main;
  u32 * from, * to_next, n_left_from, n_left_to_next, next_index;
  vlib_node_runtime_t * error_node = vlib_node_get_runtime (vm, ip4_input_node.index);
#if VTEP_VALIDATION
  ip4_address_t addr4; /* last IPv4 address matching a local VTEP address */
  ip6_address_t addr6; /* last IPv6 address matching a local VTEP address */
#endif

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

#if VTEP_VALIDATION
  if (is_ip4) addr4.data_u32 = ~0;
  else ip6_address_set_zero (&addr6);
#endif

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t * b0, * b1;
	  ip4_header_t * ip40, * ip41;
	  ip6_header_t * ip60, * ip61;
	  udp_header_t * udp0, * udp1;
	  u32 bi0, ip_len0, udp_len0, flags0, next0;
	  u32 bi1, ip_len1, udp_len1, flags1, next1;
	  i32 len_diff0, len_diff1;
	  u8 error0, good_udp0, proto0;
	  u8 error1, good_udp1, proto1;

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

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  if (is_ip4)
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      ip41 = vlib_buffer_get_current (b1);
	    }
	  else
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      ip61 = vlib_buffer_get_current (b1);
	    }

	  /* Setup packet for next IP feature */
	  vnet_feature_next(&next0, b0);
	  vnet_feature_next(&next1, b1);

	  if (is_ip4)
	    {
	      /* Treat IP frag packets as "experimental" protocol for now
		 until support of IP frag reassembly is implemented */
	      proto0 = ip4_is_fragment(ip40) ? 0xfe : ip40->protocol;
	      proto1 = ip4_is_fragment(ip41) ? 0xfe : ip41->protocol;
	    }
	  else
	    {
	      proto0 = ip60->protocol;
	      proto1 = ip61->protocol;
	    }

	  /* Process packet 0 */
	  if (proto0 != IP_PROTOCOL_UDP)
	    goto exit0; /* not UDP packet */

	  if (is_ip4)
	    udp0 = ip4_next_header (ip40);
	  else
	    udp0 = ip6_next_header (ip60);

	  if (udp0->dst_port != clib_host_to_net_u16 (UDP_DST_PORT_GTPU))
	    goto exit0; /* not GTPU packet */

#if VTEP_VALIDATION
	  /* TODO: list of VTEPs as reported by User Plane IP Resource Information
	   *
	   * a CLI cmd to configure a interfaces as GTP enabled and
	   * mark it ia Core, Access, SGi is needed....
	   */

	  /* Validate DIP against VTEPs*/
	  if (is_ip4)
	    {
	      if (addr4.as_u32 != ip40->dst_address.as_u32)
		{
		  if (!hash_get (gtm->vtep4, ip40->dst_address.as_u32))
		      goto exit0; /* no local VTEP for GTPU packet */
		  addr4 = ip40->dst_address;
		}
	    }
	  else
	    {
	      if (!ip6_address_is_equal (&addr6, &ip60->dst_address))
		{
		  if (!hash_get_mem (gtm->vtep6, &ip60->dst_address))
		      goto exit0; /* no local VTEP for GTPU packet */
		  addr6 = ip60->dst_address;
		}
	    }
#endif

	  flags0 = b0->flags;
	  good_udp0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_udp0 |= udp0->checksum == 0;

	  /* Verify UDP length */
	  if (is_ip4)
	    ip_len0 = clib_net_to_host_u16 (ip40->length);
	  else
	    ip_len0 = clib_net_to_host_u16 (ip60->payload_length);
	  udp_len0 = clib_net_to_host_u16 (udp0->length);
	  len_diff0 = ip_len0 - udp_len0;

	  /* Verify UDP checksum */
	  if (PREDICT_FALSE (!good_udp0))
	    {
	      if ((flags0 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
		{
		  if (is_ip4)
		    flags0 = ip4_tcp_udp_validate_checksum (vm, b0);
		  else
		    flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, b0);
		  good_udp0 =
		    (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
		}
	    }

	  if (is_ip4)
	    {
	      error0 = good_udp0 ? 0 : IP4_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP4_ERROR_UDP_LENGTH;
	    }
	  else
	    {
	      error0 = good_udp0 ? 0 : IP6_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP6_ERROR_UDP_LENGTH;
	    }

	  next0 = error0 ?
	    IP_GTPU_BYPASS_NEXT_DROP : IP_GTPU_BYPASS_NEXT_GTPU;
	  b0->error = error0 ? error_node->errors[error0] : 0;

	  /* gtpu-input node expect current at GTPU header */
	  if (is_ip4)
	    vlib_buffer_advance (b0, sizeof(ip4_header_t)+sizeof(udp_header_t));
	  else
	    vlib_buffer_advance (b0, sizeof(ip6_header_t)+sizeof(udp_header_t));

	exit0:
	  /* Process packet 1 */
	  if (proto1 != IP_PROTOCOL_UDP)
	    goto exit1; /* not UDP packet */

	  if (is_ip4)
	    udp1 = ip4_next_header (ip41);
	  else
	    udp1 = ip6_next_header (ip61);

	  if (udp1->dst_port != clib_host_to_net_u16 (UDP_DST_PORT_GTPU))
	    goto exit1; /* not GTPU packet */

#if VTEP_VALIDATION
	  /* TODO: list of VTEPs as reported by User Plane IP Resource Information
	   *
	   * a CLI cmd to configure a interfaces as GTP enabled and
	   * mark it ia Core, Access, SGi is needed....
	   */

	  /* Validate DIP against VTEPs*/
	  if (is_ip4)
	    {
	      if (addr4.as_u32 != ip41->dst_address.as_u32)
		{
		  if (!hash_get (gtm->vtep4, ip41->dst_address.as_u32))
		      goto exit1; /* no local VTEP for GTPU packet */
		  addr4 = ip41->dst_address;
		}
	    }
	  else
	    {
	      if (!ip6_address_is_equal (&addr6, &ip61->dst_address))
		{
		  if (!hash_get_mem (gtm->vtep6, &ip61->dst_address))
		      goto exit1; /* no local VTEP for GTPU packet */
		  addr6 = ip61->dst_address;
		}
	    }
#endif

	  flags1 = b1->flags;
	  good_udp1 = (flags1 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_udp1 |= udp1->checksum == 0;

	  /* Verify UDP length */
	  if (is_ip4)
	    ip_len1 = clib_net_to_host_u16 (ip41->length);
	  else
	    ip_len1 = clib_net_to_host_u16 (ip61->payload_length);
	  udp_len1 = clib_net_to_host_u16 (udp1->length);
	  len_diff1 = ip_len1 - udp_len1;

	  /* Verify UDP checksum */
	  if (PREDICT_FALSE (!good_udp1))
	    {
	      if ((flags1 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
		{
		  if (is_ip4)
		    flags1 = ip4_tcp_udp_validate_checksum (vm, b1);
		  else
		    flags1 = ip6_tcp_udp_icmp_validate_checksum (vm, b1);
		  good_udp1 =
		    (flags1 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
		}
	    }

	  if (is_ip4)
	    {
	      error1 = good_udp1 ? 0 : IP4_ERROR_UDP_CHECKSUM;
	      error1 = (len_diff1 >= 0) ? error1 : IP4_ERROR_UDP_LENGTH;
	    }
	  else
	    {
	      error1 = good_udp1 ? 0 : IP6_ERROR_UDP_CHECKSUM;
	      error1 = (len_diff1 >= 0) ? error1 : IP6_ERROR_UDP_LENGTH;
	    }

	  next1 = error1 ?
	    IP_GTPU_BYPASS_NEXT_DROP : IP_GTPU_BYPASS_NEXT_GTPU;
	  b1->error = error1 ? error_node->errors[error1] : 0;

	  /* gtpu-input node expect current at GTPU header */
	  if (is_ip4)
	    vlib_buffer_advance (b1, sizeof(ip4_header_t)+sizeof(udp_header_t));
	  else
	    vlib_buffer_advance (b1, sizeof(ip6_header_t)+sizeof(udp_header_t));

	exit1:
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * b0;
	  ip4_header_t * ip40;
	  ip6_header_t * ip60;
	  udp_header_t * udp0;
	  u32 bi0, ip_len0, udp_len0, flags0, next0;
	  i32 len_diff0;
	  u8 error0, good_udp0, proto0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  if (is_ip4)
	    ip40 = vlib_buffer_get_current (b0);
	  else
	    ip60 = vlib_buffer_get_current (b0);

	  /* Setup packet for next IP feature */
	  vnet_feature_next(&next0, b0);

	  if (is_ip4)
	    /* Treat IP4 frag packets as "experimental" protocol for now
	       until support of IP frag reassembly is implemented */
	    proto0 = ip4_is_fragment(ip40) ? 0xfe : ip40->protocol;
	  else
	    proto0 = ip60->protocol;

	  if (proto0 != IP_PROTOCOL_UDP)
	    goto exit; /* not UDP packet */

	  if (is_ip4)
	    udp0 = ip4_next_header (ip40);
	  else
	    udp0 = ip6_next_header (ip60);

	  if (udp0->dst_port != clib_host_to_net_u16 (UDP_DST_PORT_GTPU))
	    goto exit; /* not GTPU packet */

#if VTEP_VALIDATION
	  /* TODO: list of VTEPs as reported by User Plane IP Resource Information
	   *
	   * a CLI cmd to configure a interfaces as GTP enabled and
	   * mark it ia Core, Access, SGi is needed....
	   */

	  /* Validate DIP against VTEPs*/
	  if (is_ip4)
	    {
	      if (addr4.as_u32 != ip40->dst_address.as_u32)
		{
		  if (!hash_get (gtm->vtep4, ip40->dst_address.as_u32))
		      goto exit; /* no local VTEP for GTPU packet */
		  addr4 = ip40->dst_address;
		}
	    }
	  else
	    {
	      if (!ip6_address_is_equal (&addr6, &ip60->dst_address))
		{
		  if (!hash_get_mem (gtm->vtep6, &ip60->dst_address))
		      goto exit; /* no local VTEP for GTPU packet */
		  addr6 = ip60->dst_address;
		}
	    }
#endif

	  flags0 = b0->flags;
	  good_udp0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_udp0 |= udp0->checksum == 0;

	  /* Verify UDP length */
	  if (is_ip4)
	    ip_len0 = clib_net_to_host_u16 (ip40->length);
	  else
	    ip_len0 = clib_net_to_host_u16 (ip60->payload_length);
	  udp_len0 = clib_net_to_host_u16 (udp0->length);
	  len_diff0 = ip_len0 - udp_len0;

	  /* Verify UDP checksum */
	  if (PREDICT_FALSE (!good_udp0))
	    {
	      if ((flags0 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
		{
		  if (is_ip4)
		    flags0 = ip4_tcp_udp_validate_checksum (vm, b0);
		  else
		    flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, b0);
		  good_udp0 =
		    (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
		}
	    }

	  if (is_ip4)
	    {
	      error0 = good_udp0 ? 0 : IP4_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP4_ERROR_UDP_LENGTH;
	    }
	  else
	    {
	      error0 = good_udp0 ? 0 : IP6_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP6_ERROR_UDP_LENGTH;
	    }

	  next0 = error0 ?
	    IP_GTPU_BYPASS_NEXT_DROP : IP_GTPU_BYPASS_NEXT_GTPU;
	  b0->error = error0 ? error_node->errors[error0] : 0;

	  /* gtpu-input node expect current at GTPU header */
	  if (is_ip4)
	    vlib_buffer_advance (b0, sizeof(ip4_header_t)+sizeof(udp_header_t));
	  else
	    vlib_buffer_advance (b0, sizeof(ip6_header_t)+sizeof(udp_header_t));

	exit:
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
ip4_gtpu_bypass (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  return ip_gtpu_bypass_inline (vm, node, frame, /* is_ip4 */ 1);
}

VLIB_REGISTER_NODE (ip4_gtpu_bypass_node) = {
  .function = ip4_gtpu_bypass,
  .name = "ip4-gtpu-bypass",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP_GTPU_BYPASS_N_NEXT,
  .next_nodes = {
    [IP_GTPU_BYPASS_NEXT_DROP] = "error-drop",
    [IP_GTPU_BYPASS_NEXT_GTPU] = "gtpu4-input",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_forward_next_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_gtpu_bypass_node,ip4_gtpu_bypass)

/* Dummy init function to get us linked in. */
clib_error_t * ip4_gtpu_bypass_init (vlib_main_t * vm)
{ return 0; }

VLIB_INIT_FUNCTION (ip4_gtpu_bypass_init);

static uword
ip6_gtpu_bypass (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  return ip_gtpu_bypass_inline (vm, node, frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (ip6_gtpu_bypass_node) = {
  .function = ip6_gtpu_bypass,
  .name = "ip6-gtpu-bypass",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP_GTPU_BYPASS_N_NEXT,
  .next_nodes = {
    [IP_GTPU_BYPASS_NEXT_DROP] = "error-drop",
    [IP_GTPU_BYPASS_NEXT_GTPU] = "gtpu6-input",
  },

  .format_buffer = format_ip6_header,
  .format_trace = format_ip6_forward_next_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_gtpu_bypass_node,ip6_gtpu_bypass)

/* Dummy init function to get us linked in. */
clib_error_t * ip6_gtpu_bypass_init (vlib_main_t * vm)
{ return 0; }

VLIB_INIT_FUNCTION (ip6_gtpu_bypass_init);
