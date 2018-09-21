/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief Deterministic/CGN NAT44 inside to outside network translation
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/ip4_fib.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>
#include <nat/nat.h>
#include <nat/nat_det.h>
#include <nat/nat_inlines.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 session_index;
} nat_det_in2out_trace_t;

typedef enum
{
  NAT_DET_IN2OUT_NEXT_LOOKUP,
  NAT_DET_IN2OUT_NEXT_DROP,
  NAT_DET_IN2OUT_NEXT_ICMP_ERROR,
  NAT_DET_IN2OUT_N_NEXT,
} nat_det_in2out_next_t;

#define foreach_nat_det_in2out_error                    \
_(UNSUPPORTED_PROTOCOL, "Unsupported protocol")         \
_(NO_TRANSLATION, "No translation")                     \
_(BAD_ICMP_TYPE, "unsupported ICMP type")               \
_(OUT_OF_PORTS, "Out of ports")                         \
_(IN2OUT_PACKETS, "Good in2out packets processed")

typedef enum
{
#define _(sym,str) NAT_DET_IN2OUT_ERROR_##sym,
  foreach_nat_det_in2out_error
#undef _
    NAT_DET_IN2OUT_N_ERROR,
} nat_det_in2out_error_t;

static char *nat_det_in2out_error_strings[] = {
#define _(sym,string) string,
  foreach_nat_det_in2out_error
#undef _
};

vlib_node_registration_t snat_det_in2out_node;

static u8 *
format_nat_det_in2out_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat_det_in2out_trace_t *t = va_arg (*args, nat_det_in2out_trace_t *);

  s = format (s, "NAT_DET_IN2OUT: sw_if_index %d, next index %d, session %d",
	      t->sw_if_index, t->next_index, t->session_index);

  return s;
}

/**
 * Get address and port values to be used for ICMP packet translation
 * and create session if needed
 *
 * @param[in,out] sm             NAT main
 * @param[in,out] node           NAT node runtime
 * @param[in] thread_index       thread index
 * @param[in,out] b0             buffer containing packet to be translated
 * @param[out] p_proto           protocol used for matching
 * @param[out] p_value           address and port after NAT translation
 * @param[out] p_dont_translate  if packet should not be translated
 * @param d                      optional parameter
 * @param e                      optional parameter
 */
u32
icmp_match_in2out_det (snat_main_t * sm, vlib_node_runtime_t * node,
		       u32 thread_index, vlib_buffer_t * b0,
		       ip4_header_t * ip0, u8 * p_proto,
		       snat_session_key_t * p_value,
		       u8 * p_dont_translate, void *d, void *e)
{
  icmp46_header_t *icmp0;
  u32 sw_if_index0;
  u32 rx_fib_index0;
  u8 protocol;
  snat_det_out_key_t key0;
  u8 dont_translate = 0;
  u32 next0 = ~0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;
  snat_det_map_t *dm0 = 0;
  ip4_address_t new_addr0;
  u16 lo_port0, i0;
  snat_det_session_t *ses0 = 0;
  ip4_address_t in_addr;
  u16 in_port;

  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  echo0 = (icmp_echo_header_t *) (icmp0 + 1);
  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
  rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

  if (!icmp_is_error_message (icmp0))
    {
      protocol = SNAT_PROTOCOL_ICMP;
      in_addr = ip0->src_address;
      in_port = echo0->identifier;
    }
  else
    {
      inner_ip0 = (ip4_header_t *) (echo0 + 1);
      l4_header = ip4_next_header (inner_ip0);
      protocol = ip_proto_to_snat_proto (inner_ip0->protocol);
      in_addr = inner_ip0->dst_address;
      switch (protocol)
	{
	case SNAT_PROTOCOL_ICMP:
	  inner_icmp0 = (icmp46_header_t *) l4_header;
	  inner_echo0 = (icmp_echo_header_t *) (inner_icmp0 + 1);
	  in_port = inner_echo0->identifier;
	  break;
	case SNAT_PROTOCOL_UDP:
	case SNAT_PROTOCOL_TCP:
	  in_port = ((tcp_udp_header_t *) l4_header)->dst_port;
	  break;
	default:
	  b0->error = node->errors[NAT_DET_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
	  next0 = NAT_DET_IN2OUT_NEXT_DROP;
	  goto out;
	}
    }

  dm0 = snat_det_map_by_user (sm, &in_addr);
  if (PREDICT_FALSE (!dm0))
    {
      nat_log_info ("no match for internal host %U",
		    format_ip4_address, &in_addr);
      if (PREDICT_FALSE (snat_not_translate_fast (sm, node, sw_if_index0, ip0,
						  IP_PROTOCOL_ICMP,
						  rx_fib_index0)))
	{
	  dont_translate = 1;
	  goto out;
	}
      next0 = NAT_DET_IN2OUT_NEXT_DROP;
      b0->error = node->errors[NAT_DET_IN2OUT_ERROR_NO_TRANSLATION];
      goto out;
    }

  snat_det_forward (dm0, &in_addr, &new_addr0, &lo_port0);

  key0.ext_host_addr = ip0->dst_address;
  key0.ext_host_port = 0;

  ses0 = snat_det_find_ses_by_in (dm0, &in_addr, in_port, key0);
  if (PREDICT_FALSE (!ses0))
    {
      if (PREDICT_FALSE (snat_not_translate_fast (sm, node, sw_if_index0, ip0,
						  IP_PROTOCOL_ICMP,
						  rx_fib_index0)))
	{
	  dont_translate = 1;
	  goto out;
	}
      if (icmp0->type != ICMP4_echo_request)
	{
	  b0->error = node->errors[NAT_DET_IN2OUT_ERROR_BAD_ICMP_TYPE];
	  next0 = NAT_DET_IN2OUT_NEXT_DROP;
	  goto out;
	}
      for (i0 = 0; i0 < dm0->ports_per_host; i0++)
	{
	  key0.out_port = clib_host_to_net_u16 (lo_port0 +
						((i0 +
						  clib_net_to_host_u16
						  (echo0->identifier)) %
						 dm0->ports_per_host));

	  if (snat_det_get_ses_by_out (dm0, &in_addr, key0.as_u64))
	    continue;

	  ses0 =
	    snat_det_ses_create (dm0, &in_addr, echo0->identifier, &key0);
	  break;
	}
      if (PREDICT_FALSE (!ses0))
	{
	  next0 = NAT_DET_IN2OUT_NEXT_DROP;
	  b0->error = node->errors[NAT_DET_IN2OUT_ERROR_OUT_OF_PORTS];
	  goto out;
	}
    }

  if (PREDICT_FALSE (icmp0->type != ICMP4_echo_request &&
		     !icmp_is_error_message (icmp0)))
    {
      b0->error = node->errors[NAT_DET_IN2OUT_ERROR_BAD_ICMP_TYPE];
      next0 = NAT_DET_IN2OUT_NEXT_DROP;
      goto out;
    }

  u32 now = (u32) vlib_time_now (sm->vlib_main);

  ses0->state = SNAT_SESSION_ICMP_ACTIVE;
  ses0->expire = now + sm->icmp_timeout;

out:
  *p_proto = protocol;
  if (ses0)
    {
      p_value->addr = new_addr0;
      p_value->fib_index = sm->outside_fib_index;
      p_value->port = ses0->out.out_port;
    }
  *p_dont_translate = dont_translate;
  if (d)
    *(snat_det_session_t **) d = ses0;
  if (e)
    *(snat_det_map_t **) e = dm0;
  return next0;
}

static uword
snat_det_in2out_node_fn (vlib_main_t * vm,
			 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  nat_det_in2out_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t *sm = &snat_main;
  u32 now = (u32) vlib_time_now (vm);
  u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  u32 sw_if_index0, sw_if_index1;
	  ip4_header_t *ip0, *ip1;
	  ip_csum_t sum0, sum1;
	  ip4_address_t new_addr0, old_addr0, new_addr1, old_addr1;
	  u16 old_port0, new_port0, lo_port0, i0;
	  u16 old_port1, new_port1, lo_port1, i1;
	  udp_header_t *udp0, *udp1;
	  tcp_header_t *tcp0, *tcp1;
	  u32 proto0, proto1;
	  snat_det_out_key_t key0, key1;
	  snat_det_map_t *dm0, *dm1;
	  snat_det_session_t *ses0 = 0, *ses1 = 0;
	  u32 rx_fib_index0, rx_fib_index1;
	  icmp46_header_t *icmp0, *icmp1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  next0 = NAT_DET_IN2OUT_NEXT_LOOKUP;
	  next1 = NAT_DET_IN2OUT_NEXT_LOOKUP;

	  ip0 = vlib_buffer_get_current (b0);
	  udp0 = ip4_next_header (ip0);
	  tcp0 = (tcp_header_t *) udp0;

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  if (PREDICT_FALSE (ip0->ttl == 1))
	    {
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	      icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
					   ICMP4_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      next0 = NAT_DET_IN2OUT_NEXT_ICMP_ERROR;
	      goto trace0;
	    }

	  proto0 = ip_proto_to_snat_proto (ip0->protocol);

	  if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
	    {
	      rx_fib_index0 =
		ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);
	      icmp0 = (icmp46_header_t *) udp0;

	      next0 = icmp_in2out (sm, b0, ip0, icmp0, sw_if_index0,
				   rx_fib_index0, node, next0, thread_index,
				   &ses0, &dm0);
	      goto trace0;
	    }

	  dm0 = snat_det_map_by_user (sm, &ip0->src_address);
	  if (PREDICT_FALSE (!dm0))
	    {
	      nat_log_info ("no match for internal host %U",
			    format_ip4_address, &ip0->src_address);
	      next0 = NAT_DET_IN2OUT_NEXT_DROP;
	      b0->error = node->errors[NAT_DET_IN2OUT_ERROR_NO_TRANSLATION];
	      goto trace0;
	    }

	  snat_det_forward (dm0, &ip0->src_address, &new_addr0, &lo_port0);

	  key0.ext_host_addr = ip0->dst_address;
	  key0.ext_host_port = tcp0->dst;

	  ses0 =
	    snat_det_find_ses_by_in (dm0, &ip0->src_address, tcp0->src, key0);
	  if (PREDICT_FALSE (!ses0))
	    {
	      for (i0 = 0; i0 < dm0->ports_per_host; i0++)
		{
		  key0.out_port = clib_host_to_net_u16 (lo_port0 +
							((i0 +
							  clib_net_to_host_u16
							  (tcp0->src)) %
							 dm0->
							 ports_per_host));

		  if (snat_det_get_ses_by_out
		      (dm0, &ip0->src_address, key0.as_u64))
		    continue;

		  ses0 =
		    snat_det_ses_create (dm0, &ip0->src_address, tcp0->src,
					 &key0);
		  break;
		}
	      if (PREDICT_FALSE (!ses0))
		{
		  /* too many sessions for user, send ICMP error packet */
		  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
		  icmp4_error_set_vnet_buffer (b0,
					       ICMP4_destination_unreachable,
					       ICMP4_destination_unreachable_destination_unreachable_host,
					       0);
		  next0 = NAT_DET_IN2OUT_NEXT_ICMP_ERROR;
		  goto trace0;
		}
	    }

	  new_port0 = ses0->out.out_port;

	  old_addr0.as_u32 = ip0->src_address.as_u32;
	  ip0->src_address.as_u32 = new_addr0.as_u32;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sm->outside_fib_index;

	  sum0 = ip0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
				 ip4_header_t,
				 src_address /* changed member */ );
	  ip0->checksum = ip_csum_fold (sum0);

	  if (PREDICT_TRUE (proto0 == SNAT_PROTOCOL_TCP))
	    {
	      if (tcp0->flags & TCP_FLAG_SYN)
		ses0->state = SNAT_SESSION_TCP_SYN_SENT;
	      else if (tcp0->flags & TCP_FLAG_ACK
		       && ses0->state == SNAT_SESSION_TCP_SYN_SENT)
		ses0->state = SNAT_SESSION_TCP_ESTABLISHED;
	      else if (tcp0->flags & TCP_FLAG_FIN
		       && ses0->state == SNAT_SESSION_TCP_ESTABLISHED)
		ses0->state = SNAT_SESSION_TCP_FIN_WAIT;
	      else if (tcp0->flags & TCP_FLAG_ACK
		       && ses0->state == SNAT_SESSION_TCP_FIN_WAIT)
		snat_det_ses_close (dm0, ses0);
	      else if (tcp0->flags & TCP_FLAG_FIN
		       && ses0->state == SNAT_SESSION_TCP_CLOSE_WAIT)
		ses0->state = SNAT_SESSION_TCP_LAST_ACK;
	      else if (tcp0->flags == 0
		       && ses0->state == SNAT_SESSION_UNKNOWN)
		ses0->state = SNAT_SESSION_TCP_ESTABLISHED;

	      old_port0 = tcp0->src;
	      tcp0->src = new_port0;

	      sum0 = tcp0->checksum;
	      sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
				     ip4_header_t,
				     dst_address /* changed member */ );
	      sum0 = ip_csum_update (sum0, old_port0, new_port0,
				     ip4_header_t /* cheat */ ,
				     length /* changed member */ );
	      mss_clamping (sm, tcp0, &sum0);
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	  else
	    {
	      ses0->state = SNAT_SESSION_UDP_ACTIVE;
	      old_port0 = udp0->src_port;
	      udp0->src_port = new_port0;
	      udp0->checksum = 0;
	    }

	  switch (ses0->state)
	    {
	    case SNAT_SESSION_UDP_ACTIVE:
	      ses0->expire = now + sm->udp_timeout;
	      break;
	    case SNAT_SESSION_TCP_SYN_SENT:
	    case SNAT_SESSION_TCP_FIN_WAIT:
	    case SNAT_SESSION_TCP_CLOSE_WAIT:
	    case SNAT_SESSION_TCP_LAST_ACK:
	      ses0->expire = now + sm->tcp_transitory_timeout;
	      break;
	    case SNAT_SESSION_TCP_ESTABLISHED:
	      ses0->expire = now + sm->tcp_established_timeout;
	      break;
	    }

	trace0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat_det_in2out_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->session_index = ~0;
	      if (ses0)
		t->session_index = ses0 - dm0->sessions;
	    }

	  pkts_processed += next0 != NAT_DET_IN2OUT_NEXT_DROP;

	  ip1 = vlib_buffer_get_current (b1);
	  udp1 = ip4_next_header (ip1);
	  tcp1 = (tcp_header_t *) udp1;

	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  if (PREDICT_FALSE (ip1->ttl == 1))
	    {
	      vnet_buffer (b1)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	      icmp4_error_set_vnet_buffer (b1, ICMP4_time_exceeded,
					   ICMP4_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      next1 = NAT_DET_IN2OUT_NEXT_ICMP_ERROR;
	      goto trace1;
	    }

	  proto1 = ip_proto_to_snat_proto (ip1->protocol);

	  if (PREDICT_FALSE (proto1 == SNAT_PROTOCOL_ICMP))
	    {
	      rx_fib_index1 =
		ip4_fib_table_get_index_for_sw_if_index (sw_if_index1);
	      icmp1 = (icmp46_header_t *) udp1;

	      next1 = icmp_in2out (sm, b1, ip1, icmp1, sw_if_index1,
				   rx_fib_index1, node, next1, thread_index,
				   &ses1, &dm1);
	      goto trace1;
	    }

	  dm1 = snat_det_map_by_user (sm, &ip1->src_address);
	  if (PREDICT_FALSE (!dm1))
	    {
	      nat_log_info ("no match for internal host %U",
			    format_ip4_address, &ip0->src_address);
	      next1 = NAT_DET_IN2OUT_NEXT_DROP;
	      b1->error = node->errors[NAT_DET_IN2OUT_ERROR_NO_TRANSLATION];
	      goto trace1;
	    }

	  snat_det_forward (dm1, &ip1->src_address, &new_addr1, &lo_port1);

	  key1.ext_host_addr = ip1->dst_address;
	  key1.ext_host_port = tcp1->dst;

	  ses1 =
	    snat_det_find_ses_by_in (dm1, &ip1->src_address, tcp1->src, key1);
	  if (PREDICT_FALSE (!ses1))
	    {
	      for (i1 = 0; i1 < dm1->ports_per_host; i1++)
		{
		  key1.out_port = clib_host_to_net_u16 (lo_port1 +
							((i1 +
							  clib_net_to_host_u16
							  (tcp1->src)) %
							 dm1->
							 ports_per_host));

		  if (snat_det_get_ses_by_out
		      (dm1, &ip1->src_address, key1.as_u64))
		    continue;

		  ses1 =
		    snat_det_ses_create (dm1, &ip1->src_address, tcp1->src,
					 &key1);
		  break;
		}
	      if (PREDICT_FALSE (!ses1))
		{
		  /* too many sessions for user, send ICMP error packet */
		  vnet_buffer (b1)->sw_if_index[VLIB_TX] = (u32) ~ 0;
		  icmp4_error_set_vnet_buffer (b1,
					       ICMP4_destination_unreachable,
					       ICMP4_destination_unreachable_destination_unreachable_host,
					       0);
		  next1 = NAT_DET_IN2OUT_NEXT_ICMP_ERROR;
		  goto trace1;
		}
	    }

	  new_port1 = ses1->out.out_port;

	  old_addr1.as_u32 = ip1->src_address.as_u32;
	  ip1->src_address.as_u32 = new_addr1.as_u32;
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = sm->outside_fib_index;

	  sum1 = ip1->checksum;
	  sum1 = ip_csum_update (sum1, old_addr1.as_u32, new_addr1.as_u32,
				 ip4_header_t,
				 src_address /* changed member */ );
	  ip1->checksum = ip_csum_fold (sum1);

	  if (PREDICT_TRUE (proto1 == SNAT_PROTOCOL_TCP))
	    {
	      if (tcp1->flags & TCP_FLAG_SYN)
		ses1->state = SNAT_SESSION_TCP_SYN_SENT;
	      else if (tcp1->flags & TCP_FLAG_ACK
		       && ses1->state == SNAT_SESSION_TCP_SYN_SENT)
		ses1->state = SNAT_SESSION_TCP_ESTABLISHED;
	      else if (tcp1->flags & TCP_FLAG_FIN
		       && ses1->state == SNAT_SESSION_TCP_ESTABLISHED)
		ses1->state = SNAT_SESSION_TCP_FIN_WAIT;
	      else if (tcp1->flags & TCP_FLAG_ACK
		       && ses1->state == SNAT_SESSION_TCP_FIN_WAIT)
		snat_det_ses_close (dm1, ses1);
	      else if (tcp1->flags & TCP_FLAG_FIN
		       && ses1->state == SNAT_SESSION_TCP_CLOSE_WAIT)
		ses1->state = SNAT_SESSION_TCP_LAST_ACK;
	      else if (tcp1->flags == 0
		       && ses1->state == SNAT_SESSION_UNKNOWN)
		ses1->state = SNAT_SESSION_TCP_ESTABLISHED;

	      old_port1 = tcp1->src;
	      tcp1->src = new_port1;

	      sum1 = tcp1->checksum;
	      sum1 = ip_csum_update (sum1, old_addr1.as_u32, new_addr1.as_u32,
				     ip4_header_t,
				     dst_address /* changed member */ );
	      sum1 = ip_csum_update (sum1, old_port1, new_port1,
				     ip4_header_t /* cheat */ ,
				     length /* changed member */ );
	      mss_clamping (sm, tcp1, &sum1);
	      tcp1->checksum = ip_csum_fold (sum1);
	    }
	  else
	    {
	      ses1->state = SNAT_SESSION_UDP_ACTIVE;
	      old_port1 = udp1->src_port;
	      udp1->src_port = new_port1;
	      udp1->checksum = 0;
	    }

	  switch (ses1->state)
	    {
	    case SNAT_SESSION_UDP_ACTIVE:
	      ses1->expire = now + sm->udp_timeout;
	      break;
	    case SNAT_SESSION_TCP_SYN_SENT:
	    case SNAT_SESSION_TCP_FIN_WAIT:
	    case SNAT_SESSION_TCP_CLOSE_WAIT:
	    case SNAT_SESSION_TCP_LAST_ACK:
	      ses1->expire = now + sm->tcp_transitory_timeout;
	      break;
	    case SNAT_SESSION_TCP_ESTABLISHED:
	      ses1->expire = now + sm->tcp_established_timeout;
	      break;
	    }

	trace1:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b1->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat_det_in2out_trace_t *t =
		vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->sw_if_index = sw_if_index1;
	      t->next_index = next1;
	      t->session_index = ~0;
	      if (ses1)
		t->session_index = ses1 - dm1->sessions;
	    }

	  pkts_processed += next1 != NAT_DET_IN2OUT_NEXT_DROP;

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 sw_if_index0;
	  ip4_header_t *ip0;
	  ip_csum_t sum0;
	  ip4_address_t new_addr0, old_addr0;
	  u16 old_port0, new_port0, lo_port0, i0;
	  udp_header_t *udp0;
	  tcp_header_t *tcp0;
	  u32 proto0;
	  snat_det_out_key_t key0;
	  snat_det_map_t *dm0;
	  snat_det_session_t *ses0 = 0;
	  u32 rx_fib_index0;
	  icmp46_header_t *icmp0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  next0 = NAT_DET_IN2OUT_NEXT_LOOKUP;

	  ip0 = vlib_buffer_get_current (b0);
	  udp0 = ip4_next_header (ip0);
	  tcp0 = (tcp_header_t *) udp0;

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  if (PREDICT_FALSE (ip0->ttl == 1))
	    {
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	      icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
					   ICMP4_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      next0 = NAT_DET_IN2OUT_NEXT_ICMP_ERROR;
	      goto trace00;
	    }

	  proto0 = ip_proto_to_snat_proto (ip0->protocol);

	  if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
	    {
	      rx_fib_index0 =
		ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);
	      icmp0 = (icmp46_header_t *) udp0;

	      next0 = icmp_in2out (sm, b0, ip0, icmp0, sw_if_index0,
				   rx_fib_index0, node, next0, thread_index,
				   &ses0, &dm0);
	      goto trace00;
	    }

	  dm0 = snat_det_map_by_user (sm, &ip0->src_address);
	  if (PREDICT_FALSE (!dm0))
	    {
	      nat_log_info ("no match for internal host %U",
			    format_ip4_address, &ip0->src_address);
	      next0 = NAT_DET_IN2OUT_NEXT_DROP;
	      b0->error = node->errors[NAT_DET_IN2OUT_ERROR_NO_TRANSLATION];
	      goto trace00;
	    }

	  snat_det_forward (dm0, &ip0->src_address, &new_addr0, &lo_port0);

	  key0.ext_host_addr = ip0->dst_address;
	  key0.ext_host_port = tcp0->dst;

	  ses0 =
	    snat_det_find_ses_by_in (dm0, &ip0->src_address, tcp0->src, key0);
	  if (PREDICT_FALSE (!ses0))
	    {
	      for (i0 = 0; i0 < dm0->ports_per_host; i0++)
		{
		  key0.out_port = clib_host_to_net_u16 (lo_port0 +
							((i0 +
							  clib_net_to_host_u16
							  (tcp0->src)) %
							 dm0->
							 ports_per_host));

		  if (snat_det_get_ses_by_out
		      (dm0, &ip0->src_address, key0.as_u64))
		    continue;

		  ses0 =
		    snat_det_ses_create (dm0, &ip0->src_address, tcp0->src,
					 &key0);
		  break;
		}
	      if (PREDICT_FALSE (!ses0))
		{
		  /* too many sessions for user, send ICMP error packet */
		  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
		  icmp4_error_set_vnet_buffer (b0,
					       ICMP4_destination_unreachable,
					       ICMP4_destination_unreachable_destination_unreachable_host,
					       0);
		  next0 = NAT_DET_IN2OUT_NEXT_ICMP_ERROR;
		  goto trace00;
		}
	    }

	  new_port0 = ses0->out.out_port;

	  old_addr0.as_u32 = ip0->src_address.as_u32;
	  ip0->src_address.as_u32 = new_addr0.as_u32;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sm->outside_fib_index;

	  sum0 = ip0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
				 ip4_header_t,
				 src_address /* changed member */ );
	  ip0->checksum = ip_csum_fold (sum0);

	  if (PREDICT_TRUE (proto0 == SNAT_PROTOCOL_TCP))
	    {
	      if (tcp0->flags & TCP_FLAG_SYN)
		ses0->state = SNAT_SESSION_TCP_SYN_SENT;
	      else if (tcp0->flags & TCP_FLAG_ACK
		       && ses0->state == SNAT_SESSION_TCP_SYN_SENT)
		ses0->state = SNAT_SESSION_TCP_ESTABLISHED;
	      else if (tcp0->flags & TCP_FLAG_FIN
		       && ses0->state == SNAT_SESSION_TCP_ESTABLISHED)
		ses0->state = SNAT_SESSION_TCP_FIN_WAIT;
	      else if (tcp0->flags & TCP_FLAG_ACK
		       && ses0->state == SNAT_SESSION_TCP_FIN_WAIT)
		snat_det_ses_close (dm0, ses0);
	      else if (tcp0->flags & TCP_FLAG_FIN
		       && ses0->state == SNAT_SESSION_TCP_CLOSE_WAIT)
		ses0->state = SNAT_SESSION_TCP_LAST_ACK;
	      else if (tcp0->flags == 0
		       && ses0->state == SNAT_SESSION_UNKNOWN)
		ses0->state = SNAT_SESSION_TCP_ESTABLISHED;

	      old_port0 = tcp0->src;
	      tcp0->src = new_port0;

	      sum0 = tcp0->checksum;
	      sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
				     ip4_header_t,
				     dst_address /* changed member */ );
	      sum0 = ip_csum_update (sum0, old_port0, new_port0,
				     ip4_header_t /* cheat */ ,
				     length /* changed member */ );
	      mss_clamping (sm, tcp0, &sum0);
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	  else
	    {
	      ses0->state = SNAT_SESSION_UDP_ACTIVE;
	      old_port0 = udp0->src_port;
	      udp0->src_port = new_port0;
	      udp0->checksum = 0;
	    }

	  switch (ses0->state)
	    {
	    case SNAT_SESSION_UDP_ACTIVE:
	      ses0->expire = now + sm->udp_timeout;
	      break;
	    case SNAT_SESSION_TCP_SYN_SENT:
	    case SNAT_SESSION_TCP_FIN_WAIT:
	    case SNAT_SESSION_TCP_CLOSE_WAIT:
	    case SNAT_SESSION_TCP_LAST_ACK:
	      ses0->expire = now + sm->tcp_transitory_timeout;
	      break;
	    case SNAT_SESSION_TCP_ESTABLISHED:
	      ses0->expire = now + sm->tcp_established_timeout;
	      break;
	    }

	trace00:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat_det_in2out_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->session_index = ~0;
	      if (ses0)
		t->session_index = ses0 - dm0->sessions;
	    }

	  pkts_processed += next0 != NAT_DET_IN2OUT_NEXT_DROP;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, snat_det_in2out_node.index,
			       NAT_DET_IN2OUT_ERROR_IN2OUT_PACKETS,
			       pkts_processed);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (snat_det_in2out_node) = {
  .function = snat_det_in2out_node_fn,
  .name = "nat44-det-in2out",
  .vector_size = sizeof (u32),
  .format_trace = format_nat_det_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat_det_in2out_error_strings),
  .error_strings = nat_det_in2out_error_strings,
  .n_next_nodes = NAT_DET_IN2OUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    [NAT_DET_IN2OUT_NEXT_DROP] = "error-drop",
    [NAT_DET_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [NAT_DET_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (snat_det_in2out_node, snat_det_in2out_node_fn);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
