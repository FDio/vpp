/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 * @brief Deterministic NAT (CGN) inside to outside translation
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/ip4_fib.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <nat/det44/det44.h>
#include <nat/det44/det44_inlines.h>

#include <nat/lib/lib.h>
#include <nat/lib/inlines.h>
#include <nat/lib/nat_inlines.h>

typedef enum
{
  DET44_IN2OUT_NEXT_LOOKUP,
  DET44_IN2OUT_NEXT_DROP,
  DET44_IN2OUT_NEXT_ICMP_ERROR,
  DET44_IN2OUT_N_NEXT,
} det44_in2out_next_t;

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 session_index;
} det44_in2out_trace_t;

#define foreach_det44_in2out_error                 \
_(UNSUPPORTED_PROTOCOL, "Unsupported protocol")    \
_(NO_TRANSLATION, "No translation")                \
_(BAD_ICMP_TYPE, "unsupported ICMP type")          \
_(OUT_OF_PORTS, "Out of ports")                    \
_(IN2OUT_PACKETS, "Good in2out packets processed")

typedef enum
{
#define _(sym,str) DET44_IN2OUT_ERROR_##sym,
  foreach_det44_in2out_error
#undef _
    DET44_IN2OUT_N_ERROR,
} det44_in2out_error_t;

static char *det44_in2out_error_strings[] = {
#define _(sym,string) string,
  foreach_det44_in2out_error
#undef _
};

static u8 *
format_det44_in2out_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  det44_in2out_trace_t *t = va_arg (*args, det44_in2out_trace_t *);

  s = format (s, "DET44_IN2OUT: sw_if_index %d, next index %d, session %d",
	      t->sw_if_index, t->next_index, t->session_index);

  return s;
}

#ifndef CLIB_MARCH_VARIANT
/**
 * Get address and port values to be used for ICMP packet translation
 * and create session if needed
 *
 * @param[in,out] node           NAT node runtime
 * @param[in] thread_index       thread index
 * @param[in,out] b0             buffer containing packet to be translated
 * @param[in,out] ip0            ip header
 * @param[out] p_proto           protocol used for matching
 * @param[out] p_value           address and port after NAT translation
 * @param[out] p_dont_translate  if packet should not be translated
 * @param d                      optional parameter
 * @param e                      optional parameter
 */
u32
icmp_match_in2out_det (vlib_node_runtime_t * node,
		       u32 thread_index, vlib_buffer_t * b0,
		       ip4_header_t * ip0, ip4_address_t * addr,
		       u16 * port, u32 * fib_index,
		       nat_protocol_t * proto, void *d, void *e,
		       u8 * dont_translate)
{
  det44_main_t *dm = &det44_main;
  vlib_main_t *vm = vlib_get_main ();
  icmp46_header_t *icmp0;
  u32 sw_if_index0;
  u32 rx_fib_index0;
  nat_protocol_t protocol;
  snat_det_out_key_t key0;
  u32 next0 = ~0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;
  snat_det_map_t *mp0 = 0;
  ip4_address_t new_addr0;
  u16 lo_port0, i0;
  snat_det_session_t *ses0 = 0;
  ip4_address_t in_addr;
  u16 in_port;
  *dont_translate = 0;

  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  echo0 = (icmp_echo_header_t *) (icmp0 + 1);
  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
  rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

  if (!icmp_type_is_error_message
      (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags))
    {
      protocol = NAT_PROTOCOL_ICMP;
      in_addr = ip0->src_address;
      in_port = vnet_buffer (b0)->ip.reass.l4_src_port;
    }
  else
    {
      /* if error message, then it's not fragmented and we can access it */
      inner_ip0 = (ip4_header_t *) (echo0 + 1);
      l4_header = ip4_next_header (inner_ip0);
      protocol = ip_proto_to_nat_proto (inner_ip0->protocol);
      in_addr = inner_ip0->dst_address;
      switch (protocol)
	{
	case NAT_PROTOCOL_ICMP:
	  inner_icmp0 = (icmp46_header_t *) l4_header;
	  inner_echo0 = (icmp_echo_header_t *) (inner_icmp0 + 1);
	  in_port = inner_echo0->identifier;
	  break;
	case NAT_PROTOCOL_UDP:
	case NAT_PROTOCOL_TCP:
	  in_port = ((tcp_udp_header_t *) l4_header)->dst_port;
	  break;
	default:
	  b0->error = node->errors[DET44_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
	  next0 = DET44_IN2OUT_NEXT_DROP;
	  goto out;
	}
    }

  mp0 = snat_det_map_by_user (&in_addr);
  if (PREDICT_FALSE (!mp0))
    {
      if (PREDICT_FALSE (det44_translate (node, sw_if_index0, ip0,
					  IP_PROTOCOL_ICMP, rx_fib_index0)))
	{
	  *dont_translate = 1;
	  goto out;
	}
      next0 = DET44_IN2OUT_NEXT_DROP;
      b0->error = node->errors[DET44_IN2OUT_ERROR_NO_TRANSLATION];
      goto out;
    }

  snat_det_forward (mp0, &in_addr, &new_addr0, &lo_port0);

  key0.ext_host_addr = ip0->dst_address;
  key0.ext_host_port = 0;

  ses0 = snat_det_find_ses_by_in (mp0, &in_addr, in_port, key0, ip0->protocol);
  if (PREDICT_FALSE (!ses0))
    {
      if (PREDICT_FALSE (det44_translate (node, sw_if_index0, ip0,
					  IP_PROTOCOL_ICMP, rx_fib_index0)))
	{
	  *dont_translate = 1;
	  goto out;
	}
      if (icmp0->type != ICMP4_echo_request)
	{
	  b0->error = node->errors[DET44_IN2OUT_ERROR_BAD_ICMP_TYPE];
	  next0 = DET44_IN2OUT_NEXT_DROP;
	  goto out;
	}
      for (i0 = 0; i0 < mp0->ports_per_host; i0++)
	{
	  key0.out_port = clib_host_to_net_u16 (lo_port0 +
						((i0 +
						  clib_net_to_host_u16
						  (echo0->identifier)) %
						 mp0->ports_per_host));

	  if (snat_det_get_ses_by_out (mp0, &in_addr, key0.as_u64,
				       ip0->protocol))
	    continue;

	  ses0 = snat_det_ses_create (thread_index, mp0, &in_addr,
				      echo0->identifier, &key0, ip0->protocol);
	  break;
	}
      if (PREDICT_FALSE (!ses0))
	{
	  next0 = DET44_IN2OUT_NEXT_DROP;
	  b0->error = node->errors[DET44_IN2OUT_ERROR_OUT_OF_PORTS];
	  goto out;
	}
    }

  if (PREDICT_FALSE
      (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags != ICMP4_echo_request
       && !icmp_type_is_error_message (vnet_buffer (b0)->ip.
				       reass.icmp_type_or_tcp_flags)))
    {
      b0->error = node->errors[DET44_IN2OUT_ERROR_BAD_ICMP_TYPE];
      next0 = DET44_IN2OUT_NEXT_DROP;
      goto out;
    }

  u32 now = (u32) vlib_time_now (vm);

  ses0->state = DET44_SESSION_ICMP_ACTIVE;
  ses0->expire = now + dm->timeouts.icmp;

out:
  *proto = protocol;
  if (ses0)
    {
      *addr = new_addr0;
      *fib_index = dm->outside_fib_index;
      *port = ses0->out.out_port;
    }
  if (d)
    *(snat_det_session_t **) d = ses0;
  if (e)
    *(snat_det_map_t **) e = mp0;
  return next0;
}
#endif

#ifndef CLIB_MARCH_VARIANT
u32
det44_icmp_in2out (vlib_buffer_t * b0,
		   ip4_header_t * ip0,
		   icmp46_header_t * icmp0,
		   u32 sw_if_index0,
		   u32 rx_fib_index0,
		   vlib_node_runtime_t * node,
		   u32 next0, u32 thread_index, void *d, void *e)
{
  vlib_main_t *vm = vlib_get_main ();
  u16 old_id0, new_id0, port, checksum0, old_checksum0, new_checksum0;
  u32 new_addr0, old_addr0, next0_tmp, fib_index;
  icmp_echo_header_t *echo0, *inner_echo0;
  icmp46_header_t *inner_icmp0;
  ip4_header_t *inner_ip0;
  ip4_address_t addr;
  void *l4_header;
  u8 dont_translate;
  ip_csum_t sum0;
  nat_protocol_t protocol;

  echo0 = (icmp_echo_header_t *) (icmp0 + 1);
  next0_tmp = icmp_match_in2out_det (node, thread_index, b0, ip0,
				     &addr, &port, &fib_index, &protocol,
				     d, e, &dont_translate);
  if (next0_tmp != ~0)
    next0 = next0_tmp;
  if (next0 == DET44_IN2OUT_NEXT_DROP || dont_translate)
    goto out;

  if (PREDICT_TRUE (!ip4_is_fragment (ip0)))
    {
      sum0 =
	ip_incremental_checksum_buffer (vm, b0,
					(u8 *) icmp0 -
					(u8 *) vlib_buffer_get_current (b0),
					ntohs (ip0->length) -
					ip4_header_bytes (ip0), 0);
      checksum0 = ~ip_csum_fold (sum0);
      if (PREDICT_FALSE (checksum0 != 0 && checksum0 != 0xffff))
	{
	  next0 = DET44_IN2OUT_NEXT_DROP;
	  goto out;
	}
    }

  old_addr0 = ip0->src_address.as_u32;
  new_addr0 = ip0->src_address.as_u32 = addr.as_u32;

  sum0 = ip0->checksum;
  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
			 src_address /* changed member */ );
  ip0->checksum = ip_csum_fold (sum0);

  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
    {
      if (icmp0->checksum == 0)
	icmp0->checksum = 0xffff;

      if (!icmp_type_is_error_message (icmp0->type))
	{
	  new_id0 = port;
	  if (PREDICT_FALSE (new_id0 != echo0->identifier))
	    {
	      old_id0 = echo0->identifier;
	      new_id0 = port;
	      echo0->identifier = new_id0;

	      sum0 = icmp0->checksum;
	      sum0 =
		ip_csum_update (sum0, old_id0, new_id0, icmp_echo_header_t,
				identifier);
	      icmp0->checksum = ip_csum_fold (sum0);
	    }
	}
      else
	{
	  inner_ip0 = (ip4_header_t *) (echo0 + 1);
	  l4_header = ip4_next_header (inner_ip0);

	  if (!ip4_header_checksum_is_valid (inner_ip0))
	    {
	      next0 = DET44_IN2OUT_NEXT_DROP;
	      goto out;
	    }

	  /* update inner destination IP address */
	  old_addr0 = inner_ip0->dst_address.as_u32;
	  inner_ip0->dst_address = addr;
	  new_addr0 = inner_ip0->dst_address.as_u32;
	  sum0 = icmp0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				 dst_address /* changed member */ );
	  icmp0->checksum = ip_csum_fold (sum0);

	  /* update inner IP header checksum */
	  old_checksum0 = inner_ip0->checksum;
	  sum0 = inner_ip0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				 dst_address /* changed member */ );
	  inner_ip0->checksum = ip_csum_fold (sum0);
	  new_checksum0 = inner_ip0->checksum;
	  sum0 = icmp0->checksum;
	  sum0 =
	    ip_csum_update (sum0, old_checksum0, new_checksum0, ip4_header_t,
			    checksum);
	  icmp0->checksum = ip_csum_fold (sum0);

	  switch (protocol)
	    {
	    case NAT_PROTOCOL_ICMP:
	      inner_icmp0 = (icmp46_header_t *) l4_header;
	      inner_echo0 = (icmp_echo_header_t *) (inner_icmp0 + 1);

	      old_id0 = inner_echo0->identifier;
	      new_id0 = port;
	      inner_echo0->identifier = new_id0;

	      sum0 = icmp0->checksum;
	      sum0 =
		ip_csum_update (sum0, old_id0, new_id0, icmp_echo_header_t,
				identifier);
	      icmp0->checksum = ip_csum_fold (sum0);
	      break;
	    case NAT_PROTOCOL_UDP:
	    case NAT_PROTOCOL_TCP:
	      old_id0 = ((tcp_udp_header_t *) l4_header)->dst_port;
	      new_id0 = port;
	      ((tcp_udp_header_t *) l4_header)->dst_port = new_id0;

	      sum0 = icmp0->checksum;
	      sum0 = ip_csum_update (sum0, old_id0, new_id0, tcp_udp_header_t,
				     dst_port);
	      icmp0->checksum = ip_csum_fold (sum0);
	      break;
	    default:
	      ASSERT (0);
	    }
	}
    }

  if (vnet_buffer (b0)->sw_if_index[VLIB_TX] == ~0)
    vnet_buffer (b0)->sw_if_index[VLIB_TX] = fib_index;
out:
  return next0;
}
#endif

VLIB_NODE_FN (det44_in2out_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  u32 n_left_from, *from;
  u32 pkts_processed = 0;
  det44_main_t *dm = &det44_main;
  u32 now = (u32) vlib_time_now (vm);
  u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  vlib_get_buffers (vm, from, b, n_left_from);

  while (n_left_from >= 2)
    {
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
      snat_det_map_t *mp0, *mp1;
      snat_det_session_t *ses0 = 0, *ses1 = 0;
      u32 rx_fib_index0, rx_fib_index1;
      icmp46_header_t *icmp0, *icmp1;

      b0 = *b;
      b++;
      b1 = *b;
      b++;

      /* Prefetch next iteration. */
      if (PREDICT_TRUE (n_left_from >= 4))
	{
	  vlib_buffer_t *p2, *p3;

	  p2 = *b;
	  p3 = *(b + 1);

	  vlib_prefetch_buffer_header (p2, LOAD);
	  vlib_prefetch_buffer_header (p3, LOAD);

	  clib_prefetch_load (p2->data);
	  clib_prefetch_load (p3->data);
	}

      next0 = DET44_IN2OUT_NEXT_LOOKUP;
      next1 = DET44_IN2OUT_NEXT_LOOKUP;

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
	  next0 = DET44_IN2OUT_NEXT_ICMP_ERROR;
	  goto trace0;
	}

      proto0 = ip_proto_to_nat_proto (ip0->protocol);

      if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
	{
	  rx_fib_index0 =
	    ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);
	  icmp0 = (icmp46_header_t *) udp0;

	  // TODO:
	  next0 = det44_icmp_in2out (b0, ip0, icmp0, sw_if_index0,
				     rx_fib_index0, node, next0,
				     thread_index, &ses0, &mp0);
	  goto trace0;
	}

      mp0 = snat_det_map_by_user (&ip0->src_address);
      if (PREDICT_FALSE (!mp0))
	{
	  det44_log_info ("no match for internal host %U",
			  format_ip4_address, &ip0->src_address);
	  next0 = DET44_IN2OUT_NEXT_DROP;
	  b0->error = node->errors[DET44_IN2OUT_ERROR_NO_TRANSLATION];
	  goto trace0;
	}

      snat_det_forward (mp0, &ip0->src_address, &new_addr0, &lo_port0);

      key0.ext_host_addr = ip0->dst_address;
      key0.ext_host_port = tcp0->dst;

      ses0 = snat_det_find_ses_by_in (mp0, &ip0->src_address, tcp0->src, key0,
				      ip0->protocol);
      if (PREDICT_FALSE (!ses0))
	{
	  // TODO: also ports per host need to be adjust per protocol
	  // TCP/UDP/OTHER
	  // TODO: do we have enough space now ?
	  for (i0 = 0; i0 < mp0->ports_per_host; i0++)
	    {
	      key0.out_port = clib_host_to_net_u16 (lo_port0 +
						    ((i0 +
						      clib_net_to_host_u16
						      (tcp0->src)) %
						     mp0->ports_per_host));

	      if (snat_det_get_ses_by_out (mp0, &ip0->src_address, key0.as_u64,
					   ip0->protocol))
		continue;

	      ses0 = snat_det_ses_create (thread_index, mp0, &ip0->src_address,
					  tcp0->src, &key0, ip0->protocol);
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
	      next0 = DET44_IN2OUT_NEXT_ICMP_ERROR;
	      goto trace0;
	    }
	}

      old_port0 = udp0->src_port;
      udp0->src_port = new_port0 = ses0->out.out_port;

      old_addr0.as_u32 = ip0->src_address.as_u32;
      ip0->src_address.as_u32 = new_addr0.as_u32;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = dm->outside_fib_index;

      sum0 = ip0->checksum;
      sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
			     ip4_header_t, src_address /* changed member */ );
      ip0->checksum = ip_csum_fold (sum0);

      if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	{
	  if (tcp0->flags & TCP_FLAG_SYN)
	    ses0->state = DET44_SESSION_TCP_SYN_SENT;
	  else if (tcp0->flags & TCP_FLAG_ACK
		   && ses0->state == DET44_SESSION_TCP_SYN_SENT)
	    ses0->state = DET44_SESSION_TCP_ESTABLISHED;
	  else if (tcp0->flags & TCP_FLAG_FIN
		   && ses0->state == DET44_SESSION_TCP_ESTABLISHED)
	    ses0->state = DET44_SESSION_TCP_FIN_WAIT;
	  else if (tcp0->flags & TCP_FLAG_ACK
		   && ses0->state == DET44_SESSION_TCP_FIN_WAIT)
	    snat_det_ses_close (mp0, ses0);
	  else if (tcp0->flags & TCP_FLAG_FIN
		   && ses0->state == DET44_SESSION_TCP_CLOSE_WAIT)
	    ses0->state = DET44_SESSION_TCP_LAST_ACK;
	  else if (tcp0->flags == 0 && ses0->state == DET44_SESSION_UNKNOWN)
	    ses0->state = DET44_SESSION_TCP_ESTABLISHED;

	  sum0 = tcp0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
				 ip4_header_t,
				 dst_address /* changed member */ );
	  sum0 = ip_csum_update (sum0, old_port0, new_port0,
				 ip4_header_t /* cheat */ ,
				 length /* changed member */ );
	  mss_clamping (dm->mss_clamping, tcp0, &sum0);
	  tcp0->checksum = ip_csum_fold (sum0);
	}
      else
	{
	  ses0->state = DET44_SESSION_UDP_ACTIVE;

	  if (PREDICT_FALSE (udp0->checksum))
	    {
	      sum0 = udp0->checksum;
	      sum0 =
		ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
				ip4_header_t,
				dst_address /* changed member */ );
	      sum0 =
		ip_csum_update (sum0, old_port0, new_port0,
				ip4_header_t /* cheat */ ,
				length /* changed member */ );
	      udp0->checksum = ip_csum_fold (sum0);
	    }
	}

      switch (ses0->state)
	{
	case DET44_SESSION_UDP_ACTIVE:
	  ses0->expire = now + dm->timeouts.udp;
	  break;
	case DET44_SESSION_TCP_SYN_SENT:
	case DET44_SESSION_TCP_FIN_WAIT:
	case DET44_SESSION_TCP_CLOSE_WAIT:
	case DET44_SESSION_TCP_LAST_ACK:
	  ses0->expire = now + dm->timeouts.tcp.transitory;
	  break;
	case DET44_SESSION_TCP_ESTABLISHED:
	  ses0->expire = now + dm->timeouts.tcp.established;
	  break;
	}

    trace0:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  det44_in2out_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->next_index = next0;
	  t->session_index = ~0;
	  if (ses0)
	    t->session_index = ses0 - mp0->sessions;
	}

      pkts_processed += next0 != DET44_IN2OUT_NEXT_DROP;

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
	  next1 = DET44_IN2OUT_NEXT_ICMP_ERROR;
	  goto trace1;
	}

      proto1 = ip_proto_to_nat_proto (ip1->protocol);

      if (PREDICT_FALSE (proto1 == NAT_PROTOCOL_ICMP))
	{
	  rx_fib_index1 =
	    ip4_fib_table_get_index_for_sw_if_index (sw_if_index1);
	  icmp1 = (icmp46_header_t *) udp1;

	  next1 = det44_icmp_in2out (b1, ip1, icmp1, sw_if_index1,
				     rx_fib_index1, node, next1,
				     thread_index, &ses1, &mp1);
	  goto trace1;
	}

      mp1 = snat_det_map_by_user (&ip1->src_address);
      if (PREDICT_FALSE (!mp1))
	{
	  det44_log_info ("no match for internal host %U",
			  format_ip4_address, &ip0->src_address);
	  next1 = DET44_IN2OUT_NEXT_DROP;
	  b1->error = node->errors[DET44_IN2OUT_ERROR_NO_TRANSLATION];
	  goto trace1;
	}

      snat_det_forward (mp1, &ip1->src_address, &new_addr1, &lo_port1);

      key1.ext_host_addr = ip1->dst_address;
      key1.ext_host_port = tcp1->dst;

      ses1 = snat_det_find_ses_by_in (mp1, &ip1->src_address, tcp1->src, key1,
				      ip1->protocol);
      if (PREDICT_FALSE (!ses1))
	{
	  for (i1 = 0; i1 < mp1->ports_per_host; i1++)
	    {
	      key1.out_port = clib_host_to_net_u16 (lo_port1 +
						    ((i1 +
						      clib_net_to_host_u16
						      (tcp1->src)) %
						     mp1->ports_per_host));

	      if (snat_det_get_ses_by_out (mp1, &ip1->src_address, key1.as_u64,
					   ip1->protocol))
		continue;

	      ses1 = snat_det_ses_create (thread_index, mp1, &ip1->src_address,
					  tcp1->src, &key1, ip1->protocol);
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
	      next1 = DET44_IN2OUT_NEXT_ICMP_ERROR;
	      goto trace1;
	    }
	}

      old_port1 = udp1->src_port;
      udp1->src_port = new_port1 = ses1->out.out_port;

      old_addr1.as_u32 = ip1->src_address.as_u32;
      ip1->src_address.as_u32 = new_addr1.as_u32;
      vnet_buffer (b1)->sw_if_index[VLIB_TX] = dm->outside_fib_index;

      sum1 = ip1->checksum;
      sum1 = ip_csum_update (sum1, old_addr1.as_u32, new_addr1.as_u32,
			     ip4_header_t, src_address /* changed member */ );
      ip1->checksum = ip_csum_fold (sum1);

      if (PREDICT_TRUE (proto1 == NAT_PROTOCOL_TCP))
	{
	  if (tcp1->flags & TCP_FLAG_SYN)
	    ses1->state = DET44_SESSION_TCP_SYN_SENT;
	  else if (tcp1->flags & TCP_FLAG_ACK
		   && ses1->state == DET44_SESSION_TCP_SYN_SENT)
	    ses1->state = DET44_SESSION_TCP_ESTABLISHED;
	  else if (tcp1->flags & TCP_FLAG_FIN
		   && ses1->state == DET44_SESSION_TCP_ESTABLISHED)
	    ses1->state = DET44_SESSION_TCP_FIN_WAIT;
	  else if (tcp1->flags & TCP_FLAG_ACK
		   && ses1->state == DET44_SESSION_TCP_FIN_WAIT)
	    snat_det_ses_close (mp1, ses1);
	  else if (tcp1->flags & TCP_FLAG_FIN
		   && ses1->state == DET44_SESSION_TCP_CLOSE_WAIT)
	    ses1->state = DET44_SESSION_TCP_LAST_ACK;
	  else if (tcp1->flags == 0 && ses1->state == DET44_SESSION_UNKNOWN)
	    ses1->state = DET44_SESSION_TCP_ESTABLISHED;

	  sum1 = tcp1->checksum;
	  sum1 = ip_csum_update (sum1, old_addr1.as_u32, new_addr1.as_u32,
				 ip4_header_t,
				 dst_address /* changed member */ );
	  sum1 = ip_csum_update (sum1, old_port1, new_port1,
				 ip4_header_t /* cheat */ ,
				 length /* changed member */ );
	  mss_clamping (dm->mss_clamping, tcp1, &sum1);
	  tcp1->checksum = ip_csum_fold (sum1);
	}
      else
	{
	  ses1->state = DET44_SESSION_UDP_ACTIVE;

	  if (PREDICT_FALSE (udp1->checksum))
	    {
	      sum1 = udp1->checksum;
	      sum1 =
		ip_csum_update (sum1, old_addr1.as_u32, new_addr1.as_u32,
				ip4_header_t,
				dst_address /* changed member */ );
	      sum1 =
		ip_csum_update (sum1, old_port1, new_port1,
				ip4_header_t /* cheat */ ,
				length /* changed member */ );
	      udp1->checksum = ip_csum_fold (sum1);
	    }
	}

      switch (ses1->state)
	{
	case DET44_SESSION_UDP_ACTIVE:
	  ses1->expire = now + dm->timeouts.udp;
	  break;
	case DET44_SESSION_TCP_SYN_SENT:
	case DET44_SESSION_TCP_FIN_WAIT:
	case DET44_SESSION_TCP_CLOSE_WAIT:
	case DET44_SESSION_TCP_LAST_ACK:
	  ses1->expire = now + dm->timeouts.tcp.transitory;
	  break;
	case DET44_SESSION_TCP_ESTABLISHED:
	  ses1->expire = now + dm->timeouts.tcp.established;
	  break;
	}

    trace1:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b1->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  det44_in2out_trace_t *t =
	    vlib_add_trace (vm, node, b1, sizeof (*t));
	  t->sw_if_index = sw_if_index1;
	  t->next_index = next1;
	  t->session_index = ~0;
	  if (ses1)
	    t->session_index = ses1 - mp1->sessions;
	}

      pkts_processed += next1 != DET44_IN2OUT_NEXT_DROP;

      n_left_from -= 2;
      next[0] = next0;
      next[1] = next1;
      next += 2;
    }

  while (n_left_from > 0)
    {
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
      snat_det_map_t *mp0;
      snat_det_session_t *ses0 = 0;
      u32 rx_fib_index0;
      icmp46_header_t *icmp0;

      b0 = *b;
      b++;
      next0 = DET44_IN2OUT_NEXT_LOOKUP;

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
	  next0 = DET44_IN2OUT_NEXT_ICMP_ERROR;
	  goto trace00;
	}

      proto0 = ip_proto_to_nat_proto (ip0->protocol);

      if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
	{
	  rx_fib_index0 =
	    ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);
	  icmp0 = (icmp46_header_t *) udp0;

	  next0 = det44_icmp_in2out (b0, ip0, icmp0, sw_if_index0,
				     rx_fib_index0, node, next0,
				     thread_index, &ses0, &mp0);
	  goto trace00;
	}

      mp0 = snat_det_map_by_user (&ip0->src_address);
      if (PREDICT_FALSE (!mp0))
	{
	  det44_log_info ("no match for internal host %U",
			  format_ip4_address, &ip0->src_address);
	  next0 = DET44_IN2OUT_NEXT_DROP;
	  b0->error = node->errors[DET44_IN2OUT_ERROR_NO_TRANSLATION];
	  goto trace00;
	}

      snat_det_forward (mp0, &ip0->src_address, &new_addr0, &lo_port0);

      key0.ext_host_addr = ip0->dst_address;
      key0.ext_host_port = tcp0->dst;

      ses0 = snat_det_find_ses_by_in (mp0, &ip0->src_address, tcp0->src, key0,
				      ip0->protocol);
      if (PREDICT_FALSE (!ses0))
	{
	  for (i0 = 0; i0 < mp0->ports_per_host; i0++)
	    {
	      key0.out_port = clib_host_to_net_u16 (lo_port0 +
						    ((i0 +
						      clib_net_to_host_u16
						      (tcp0->src)) %
						     mp0->ports_per_host));

	      if (snat_det_get_ses_by_out (mp0, &ip0->src_address, key0.as_u64,
					   ip0->protocol))
		continue;

	      ses0 = snat_det_ses_create (thread_index, mp0, &ip0->src_address,
					  tcp0->src, &key0, ip0->protocol);
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
	      next0 = DET44_IN2OUT_NEXT_ICMP_ERROR;
	      goto trace00;
	    }
	}

      old_port0 = udp0->src_port;
      udp0->src_port = new_port0 = ses0->out.out_port;

      old_addr0.as_u32 = ip0->src_address.as_u32;
      ip0->src_address.as_u32 = new_addr0.as_u32;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = dm->outside_fib_index;

      sum0 = ip0->checksum;
      sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
			     ip4_header_t, src_address /* changed member */ );
      ip0->checksum = ip_csum_fold (sum0);

      if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	{
	  if (tcp0->flags & TCP_FLAG_SYN)
	    ses0->state = DET44_SESSION_TCP_SYN_SENT;
	  else if (tcp0->flags & TCP_FLAG_ACK
		   && ses0->state == DET44_SESSION_TCP_SYN_SENT)
	    ses0->state = DET44_SESSION_TCP_ESTABLISHED;
	  else if (tcp0->flags & TCP_FLAG_FIN
		   && ses0->state == DET44_SESSION_TCP_ESTABLISHED)
	    ses0->state = DET44_SESSION_TCP_FIN_WAIT;
	  else if (tcp0->flags & TCP_FLAG_ACK
		   && ses0->state == DET44_SESSION_TCP_FIN_WAIT)
	    snat_det_ses_close (mp0, ses0);
	  else if (tcp0->flags & TCP_FLAG_FIN
		   && ses0->state == DET44_SESSION_TCP_CLOSE_WAIT)
	    ses0->state = DET44_SESSION_TCP_LAST_ACK;
	  else if (tcp0->flags == 0 && ses0->state == DET44_SESSION_UNKNOWN)
	    ses0->state = DET44_SESSION_TCP_ESTABLISHED;

	  sum0 = tcp0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
				 ip4_header_t,
				 dst_address /* changed member */ );
	  sum0 = ip_csum_update (sum0, old_port0, new_port0,
				 ip4_header_t /* cheat */ ,
				 length /* changed member */ );
	  mss_clamping (dm->mss_clamping, tcp0, &sum0);
	  tcp0->checksum = ip_csum_fold (sum0);
	}
      else
	{
	  ses0->state = DET44_SESSION_UDP_ACTIVE;

	  if (PREDICT_FALSE (udp0->checksum))
	    {
	      sum0 = udp0->checksum;
	      sum0 =
		ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
				ip4_header_t,
				dst_address /* changed member */ );
	      sum0 =
		ip_csum_update (sum0, old_port0, new_port0,
				ip4_header_t /* cheat */ ,
				length /* changed member */ );
	      udp0->checksum = ip_csum_fold (sum0);
	    }
	}

      switch (ses0->state)
	{
	case DET44_SESSION_UDP_ACTIVE:
	  ses0->expire = now + dm->timeouts.udp;
	  break;
	case DET44_SESSION_TCP_SYN_SENT:
	case DET44_SESSION_TCP_FIN_WAIT:
	case DET44_SESSION_TCP_CLOSE_WAIT:
	case DET44_SESSION_TCP_LAST_ACK:
	  ses0->expire = now + dm->timeouts.tcp.transitory;
	  break;
	case DET44_SESSION_TCP_ESTABLISHED:
	  ses0->expire = now + dm->timeouts.tcp.established;
	  break;
	}

    trace00:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  det44_in2out_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->next_index = next0;
	  t->session_index = ~0;
	  if (ses0)
	    t->session_index = ses0 - mp0->sessions;
	}

      pkts_processed += next0 != DET44_IN2OUT_NEXT_DROP;

      n_left_from--;
      next[0] = next0;
      next++;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) nexts,
			       frame->n_vectors);

  vlib_node_increment_counter (vm, dm->in2out_node_index,
			       DET44_IN2OUT_ERROR_IN2OUT_PACKETS,
			       pkts_processed);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (det44_in2out_node) = {
  .name = "det44-in2out",
  .vector_size = sizeof (u32),
  .format_trace = format_det44_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(det44_in2out_error_strings),
  .error_strings = det44_in2out_error_strings,
  .runtime_data_bytes = sizeof (det44_runtime_t),
  .n_next_nodes = DET44_IN2OUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    [DET44_IN2OUT_NEXT_DROP] = "error-drop",
    [DET44_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [DET44_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
