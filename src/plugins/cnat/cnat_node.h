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

#ifndef __CNAT_NODE_H__
#define __CNAT_NODE_H__

#include <vlibmemory/api.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/load_balance_map.h>

#include <cnat/cnat_session.h>
#include <cnat/cnat_client.h>
#include <cnat/cnat_inline.h>
#include <cnat/cnat_translation.h>

#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

typedef void (*cnat_node_sub_t) (vlib_main_t *vm, vlib_node_runtime_t *node,
				 vlib_buffer_t *b, u16 *next,
				 ip_address_family_t af, f64 now, u8 do_trace);

typedef enum cnat_node_vip_next_t_
{
  CNAT_NODE_VIP_NEXT_DROP,
  CNAT_NODE_VIP_NEXT_LOOKUP,
  CNAT_NODE_VIP_N_NEXT,
} cnat_node_vip_next_t;

typedef struct cnat_trace_element_t_
{
  cnat_timestamp_rewrite_t rw;
  cnat_translation_t tr;
  u32 sw_if_index[VLIB_N_RX_TX];
  u32 snat_policy_result;
  u32 generic_flow_id;
  u32 flow_state;
  u8 flags;
} cnat_trace_element_t;

typedef enum cnat_trace_element_flag_t_
{
  CNAT_TRACE_SESSION_FOUND = (1 << 0),
  CNAT_TRACE_SESSION_CREATED = (1 << 1),
  CNAT_TRACE_TRANSLATION_FOUND = (1 << 2),
  CNAT_TRACE_REWRITE_FOUND = (1 << 3)
} cnat_trace_element_flag_t;

static_always_inline void
cnat_add_trace (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const cnat_timestamp_rewrite_t *rw,
		const cnat_translation_t *ct)
{
  cnat_trace_element_t *t;
  if (!(b->flags & VLIB_BUFFER_IS_TRACED))
    return;

  t = vlib_add_trace (vm, node, b, sizeof (*t));
  t->sw_if_index[VLIB_RX] = vnet_buffer (b)->sw_if_index[VLIB_RX];
  t->sw_if_index[VLIB_TX] = vnet_buffer (b)->sw_if_index[VLIB_TX];

  t->generic_flow_id = vnet_buffer (b)->session.generic_flow_id;
  t->flow_state = vnet_buffer (b)->session.state;

  t->flags = 0;
  if (ct)
    {
      clib_memcpy (&t->tr, ct, sizeof (cnat_translation_t));
      t->flags |= CNAT_TRACE_TRANSLATION_FOUND;
    }

  if (rw)
    {
      clib_memcpy (&t->rw, rw, sizeof (cnat_timestamp_rewrite_t));
      t->flags |= CNAT_TRACE_REWRITE_FOUND;
    }
}

static u8 *
format_cnat_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cnat_trace_element_t *t = va_arg (*args, cnat_trace_element_t *);
  u32 indent = format_get_indent (s);
  vnet_main_t *vnm = vnet_get_main ();

  if (t->flow_state == CNAT_LOOKUP_IS_ERR)
    s = format (s, "session lookup error");
  else if (t->flow_state == CNAT_LOOKUP_IS_RETURN)
    s = format (s, "return session");
  else if (t->flow_state == CNAT_LOOKUP_IS_NEW)
    s = format (s, "new session");
  else if (t->flow_state == CNAT_LOOKUP_IS_OK)
    s = format (s, "session found");
  else
    s = format (s, "weird flow_state %d", t->flow_state);

  s = format (s, "\n%Uin:%U out:%U ", format_white_space, indent,
	      format_vnet_sw_if_index_name, vnm, t->sw_if_index[VLIB_RX],
	      format_vnet_sw_if_index_name, vnm, t->sw_if_index[VLIB_TX]);

  if (t->flags & CNAT_TRACE_REWRITE_FOUND)
    s = format (s, "\n%U%U", format_white_space, indent, format_cnat_rewrite,
		&t->rw, 1);

  if (t->flags & CNAT_TRACE_TRANSLATION_FOUND)
    s = format (s, "\n%Utranslation: %U", format_white_space, indent,
		format_cnat_translation, &t->tr, 0);

  return s;
}

static_always_inline u8
icmp_type_is_error_message (u8 icmp_type)
{
  switch (icmp_type)
    {
    case ICMP4_destination_unreachable:
    case ICMP4_time_exceeded:
    case ICMP4_parameter_problem:
    case ICMP4_source_quench:
    case ICMP4_redirect:
    case ICMP4_alternate_host_address:
      return 1;
    }
  return 0;
}

static_always_inline u8
icmp_type_is_echo (u8 icmp_type)
{
  switch (icmp_type)
    {
    case ICMP4_echo_request:
    case ICMP4_echo_reply:
      return 1;
    }
  return 0;
}

static_always_inline u8
icmp6_type_is_echo (u8 icmp_type)
{
  switch (icmp_type)
    {
    case ICMP6_echo_request:
    case ICMP6_echo_reply:
      return 1;
    }
  return 0;
}

static_always_inline u8
icmp6_type_is_error_message (u8 icmp_type)
{
  switch (icmp_type)
    {
    case ICMP6_destination_unreachable:
    case ICMP6_time_exceeded:
    case ICMP6_parameter_problem:
      return 1;
    }
  return 0;
}

static_always_inline u8
cmp_ip6_address (const ip6_address_t * a1, const ip6_address_t * a2)
{
  return ((a1->as_u64[0] == a2->as_u64[0])
	  && (a1->as_u64[1] == a2->as_u64[1]));
}

/**
 * Inline translation functions
 */

static_always_inline void
cnat_ip4_translate_l4 (ip4_header_t *ip4, udp_header_t *udp, ip_csum_t *sum,
		       ip4_address_t new_addr[VLIB_N_DIR],
		       u16 new_port[VLIB_N_DIR], u32 oflags)
{
  u16 old_port[VLIB_N_DIR];
  old_port[VLIB_TX] = udp->dst_port;
  old_port[VLIB_RX] = udp->src_port;

  udp->dst_port = new_port[VLIB_TX];
  udp->src_port = new_port[VLIB_RX];

  /* Completely offloaded checksum */
  if (oflags &
      (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM | VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
    return;

  *sum = ip_csum_update (*sum, ip4->dst_address.as_u32,
			 new_addr[VLIB_TX].as_u32, ip4_header_t, dst_address);
  *sum = ip_csum_update (*sum, ip4->src_address.as_u32,
			 new_addr[VLIB_RX].as_u32, ip4_header_t, src_address);

  *sum =
    ip_csum_update (*sum, old_port[VLIB_TX], new_port[VLIB_TX],
		    ip4_header_t /* cheat */, length /* changed member */);
  *sum =
    ip_csum_update (*sum, old_port[VLIB_RX], new_port[VLIB_RX],
		    ip4_header_t /* cheat */, length /* changed member */);
}

static_always_inline void
cnat_ip4_translate_l3 (ip4_header_t *ip4, ip4_address_t new_addr[VLIB_N_DIR],
		       u32 oflags)
{
  ip4_address_t old_addr[VLIB_N_DIR];
  ip_csum_t sum;
  old_addr[VLIB_TX] = ip4->dst_address;
  old_addr[VLIB_RX] = ip4->src_address;

  ip4->dst_address = new_addr[VLIB_TX];
  ip4->src_address = new_addr[VLIB_RX];

  if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
    return;

  sum = ip4->checksum;
  sum = ip_csum_update (sum, old_addr[VLIB_TX].as_u32,
			new_addr[VLIB_TX].as_u32, ip4_header_t, dst_address);
  sum = ip_csum_update (sum, old_addr[VLIB_RX].as_u32,
			new_addr[VLIB_RX].as_u32, ip4_header_t, src_address);
  ip4->checksum = ip_csum_fold (sum);
}

static_always_inline void
cnat_tcp_update_session_lifetime (tcp_header_t *tcp, u16 *lifetime)
{
  cnat_main_t *cm = &cnat_main;
  if (PREDICT_FALSE (tcp_fin (tcp)))
    *lifetime = CNAT_DEFAULT_TCP_RST_TIMEOUT;

  if (PREDICT_FALSE (tcp_rst (tcp)))
    *lifetime = CNAT_DEFAULT_TCP_RST_TIMEOUT;

  if (PREDICT_FALSE (tcp_syn (tcp) && tcp_ack (tcp)))
    *lifetime = cm->tcp_max_age;
}

static_always_inline void
cnat_translation_icmp4_echo (ip4_header_t *ip4, icmp46_header_t *icmp,
			     ip4_address_t new_addr[VLIB_N_DIR],
			     u16 new_port[VLIB_N_DIR], u32 oflags)
{
  ip_csum_t sum;
  u16 old_port;
  cnat_echo_header_t *echo = (cnat_echo_header_t *) (icmp + 1);

  cnat_ip4_translate_l3 (ip4, new_addr, oflags);
  old_port = echo->identifier;
  echo->identifier = new_port[VLIB_RX];

  sum = icmp->checksum;
  sum = ip_csum_update (sum, old_port, new_port[VLIB_RX],
			ip4_header_t /* cheat */ ,
			length /* changed member */ );

  icmp->checksum = ip_csum_fold (sum);
}

static_always_inline void
cnat_translation_icmp4_error (ip4_header_t *outer_ip4, icmp46_header_t *icmp,
			      ip4_address_t outer_new_addr[VLIB_N_DIR],
			      u16 outer_new_port[VLIB_N_DIR], u32 oflags)
{
  ip4_address_t new_addr[VLIB_N_DIR];
  ip4_address_t old_addr[VLIB_N_DIR];
  u16 new_port[VLIB_N_DIR];
  u16 old_port[VLIB_N_DIR];
  ip_csum_t sum, old_ip_sum, inner_l4_sum, inner_l4_old_sum;

  ip4_header_t *ip4 = (ip4_header_t *) (icmp + 2);
  udp_header_t *udp = (udp_header_t *) (ip4 + 1);
  tcp_header_t *tcp = (tcp_header_t *) udp;

  /* Swap inner ports */
  new_addr[VLIB_TX] = outer_new_addr[VLIB_RX];
  new_addr[VLIB_RX] = outer_new_addr[VLIB_TX];
  new_port[VLIB_TX] = outer_new_port[VLIB_RX];
  new_port[VLIB_RX] = outer_new_port[VLIB_TX];

  old_addr[VLIB_TX] = ip4->dst_address;
  old_addr[VLIB_RX] = ip4->src_address;
  old_port[VLIB_RX] = udp->src_port;
  old_port[VLIB_TX] = udp->dst_port;

  sum = icmp->checksum;
  old_ip_sum = ip4->checksum;

  /* translate outer ip only if src_addr was translated */
  if (outer_ip4->src_address.as_u32 != ip4->dst_address.as_u32)
    outer_new_addr[VLIB_RX] = outer_ip4->src_address;
  cnat_ip4_translate_l3 (outer_ip4, outer_new_addr, oflags);

  if (ip4->protocol == IP_PROTOCOL_TCP)
    {
      inner_l4_old_sum = inner_l4_sum = tcp->checksum;
      cnat_ip4_translate_l4 (ip4, udp, &inner_l4_sum, new_addr, new_port,
			     0 /* flags */);
      tcp->checksum = ip_csum_fold (inner_l4_sum);
    }
  else if (ip4->protocol == IP_PROTOCOL_UDP)
    {
      inner_l4_old_sum = inner_l4_sum = udp->checksum;
      cnat_ip4_translate_l4 (ip4, udp, &inner_l4_sum, new_addr, new_port,
			     0 /* flags */);
      udp->checksum = ip_csum_fold (inner_l4_sum);
    }
  else
    return;

  /* UDP/TCP checksum changed */
  sum = ip_csum_update (sum, inner_l4_old_sum, inner_l4_sum,
			ip4_header_t, checksum);

  /* UDP/TCP Ports changed */
  if (old_port[VLIB_TX] && new_port[VLIB_TX])
    sum = ip_csum_update (sum, old_port[VLIB_TX], new_port[VLIB_TX],
			  ip4_header_t /* cheat */ ,
			  length /* changed member */ );

  if (old_port[VLIB_RX] && new_port[VLIB_RX])
    sum = ip_csum_update (sum, old_port[VLIB_RX], new_port[VLIB_RX],
			  ip4_header_t /* cheat */ ,
			  length /* changed member */ );

  cnat_ip4_translate_l3 (ip4, new_addr, 0 /* oflags */);
  ip_csum_t new_ip_sum = ip4->checksum;
  /* IP checksum changed */
  sum = ip_csum_update (sum, old_ip_sum, new_ip_sum, ip4_header_t, checksum);

  /* IP src/dst addr changed */
  sum = ip_csum_update (sum, old_addr[VLIB_TX].as_u32,
			new_addr[VLIB_TX].as_u32, ip4_header_t, dst_address);

  sum = ip_csum_update (sum, old_addr[VLIB_RX].as_u32,
			new_addr[VLIB_RX].as_u32, ip4_header_t, src_address);

  icmp->checksum = ip_csum_fold (sum);
}

static_always_inline void
cnat_translation_ip4 (const cnat_5tuple_t *tuple, ip4_header_t *ip4,
		      udp_header_t *udp, u16 *lifetime, u32 oflags)
{
  tcp_header_t *tcp = (tcp_header_t *) udp;
  ip4_address_t new_addr[VLIB_N_DIR];
  u16 new_port[VLIB_N_DIR];

  new_addr[VLIB_TX] = tuple->ip[VLIB_TX].ip4;
  new_addr[VLIB_RX] = tuple->ip[VLIB_RX].ip4;
  new_port[VLIB_TX] = tuple->port[VLIB_TX];
  new_port[VLIB_RX] = tuple->port[VLIB_RX];

  if (ip4->protocol == IP_PROTOCOL_TCP)
    {
      ip_csum_t sum = tcp->checksum;
      cnat_ip4_translate_l4 (ip4, udp, &sum, new_addr, new_port, oflags);
      tcp->checksum = ip_csum_fold (sum);
      cnat_ip4_translate_l3 (ip4, new_addr, oflags);
      cnat_tcp_update_session_lifetime (tcp, lifetime);
    }
  else if (ip4->protocol == IP_PROTOCOL_UDP)
    {
      ip_csum_t sum = udp->checksum;
      cnat_ip4_translate_l4 (ip4, udp, &sum, new_addr, new_port, oflags);
      udp->checksum = ip_csum_fold (sum);
      cnat_ip4_translate_l3 (ip4, new_addr, oflags);
    }
  else if (ip4->protocol == IP_PROTOCOL_ICMP)
    {
      icmp46_header_t *icmp = (icmp46_header_t *) udp;
      if (icmp_type_is_error_message (icmp->type))
	cnat_translation_icmp4_error (ip4, icmp, new_addr, new_port, oflags);
      else if (icmp_type_is_echo (icmp->type))
	cnat_translation_icmp4_echo (ip4, icmp, new_addr, new_port, oflags);
    }
}

static_always_inline void
cnat_ip6_translate_l3 (ip6_header_t * ip6, ip6_address_t new_addr[VLIB_N_DIR])
{
  ip6_address_copy (&ip6->dst_address, &new_addr[VLIB_TX]);
  ip6_address_copy (&ip6->src_address, &new_addr[VLIB_RX]);
}

static_always_inline void
cnat_ip6_translate_l4 (ip6_header_t *ip6, udp_header_t *udp, ip_csum_t *sum,
		       ip6_address_t new_addr[VLIB_N_DIR],
		       u16 new_port[VLIB_N_DIR], u32 oflags)
{
  u16 old_port[VLIB_N_DIR];
  old_port[VLIB_TX] = udp->dst_port;
  old_port[VLIB_RX] = udp->src_port;

  udp->dst_port = new_port[VLIB_TX];
  udp->src_port = new_port[VLIB_RX];

  /* Completely offloaded checksum */
  if (oflags &
      (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM | VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
    return;

  *sum = ip_csum_add_even (*sum, new_addr[VLIB_TX].as_u64[0]);
  *sum = ip_csum_add_even (*sum, new_addr[VLIB_TX].as_u64[1]);
  *sum = ip_csum_sub_even (*sum, ip6->dst_address.as_u64[0]);
  *sum = ip_csum_sub_even (*sum, ip6->dst_address.as_u64[1]);

  *sum = ip_csum_add_even (*sum, new_addr[VLIB_RX].as_u64[0]);
  *sum = ip_csum_add_even (*sum, new_addr[VLIB_RX].as_u64[1]);
  *sum = ip_csum_sub_even (*sum, ip6->src_address.as_u64[0]);
  *sum = ip_csum_sub_even (*sum, ip6->src_address.as_u64[1]);

  *sum =
    ip_csum_update (*sum, old_port[VLIB_TX], new_port[VLIB_TX],
		    ip4_header_t /* cheat */, length /* changed member */);

  *sum =
    ip_csum_update (*sum, old_port[VLIB_RX], new_port[VLIB_RX],
		    ip4_header_t /* cheat */, length /* changed member */);
}

static_always_inline void
cnat_translation_icmp6_echo (ip6_header_t * ip6, icmp46_header_t * icmp,
			     ip6_address_t new_addr[VLIB_N_DIR],
			     u16 new_port[VLIB_N_DIR])
{
  cnat_echo_header_t *echo = (cnat_echo_header_t *) (icmp + 1);
  ip6_address_t old_addr[VLIB_N_DIR];
  ip_csum_t sum;
  u16 old_port;
  old_port = echo->identifier;
  ip6_address_copy (&old_addr[VLIB_TX], &ip6->dst_address);
  ip6_address_copy (&old_addr[VLIB_RX], &ip6->src_address);

  sum = icmp->checksum;

  cnat_ip6_translate_l3 (ip6, new_addr);

  sum = ip_csum_add_even (sum, new_addr[VLIB_TX].as_u64[0]);
  sum = ip_csum_add_even (sum, new_addr[VLIB_TX].as_u64[1]);
  sum = ip_csum_sub_even (sum, old_addr[VLIB_TX].as_u64[0]);
  sum = ip_csum_sub_even (sum, old_addr[VLIB_TX].as_u64[1]);

  sum = ip_csum_add_even (sum, new_addr[VLIB_RX].as_u64[0]);
  sum = ip_csum_add_even (sum, new_addr[VLIB_RX].as_u64[1]);
  sum = ip_csum_sub_even (sum, old_addr[VLIB_RX].as_u64[0]);
  sum = ip_csum_sub_even (sum, old_addr[VLIB_RX].as_u64[1]);

  echo->identifier = new_port[VLIB_RX];
  sum = ip_csum_update (sum, old_port, new_port[VLIB_RX],
			ip4_header_t /* cheat */ ,
			length /* changed member */ );

  icmp->checksum = ip_csum_fold (sum);
}

static_always_inline void
cnat_translation_icmp6_error (ip6_header_t *outer_ip6, icmp46_header_t *icmp,
			      ip6_address_t outer_new_addr[VLIB_N_DIR],
			      u16 outer_new_port[VLIB_N_DIR])
{
  ip6_address_t new_addr[VLIB_N_DIR];
  ip6_address_t old_addr[VLIB_N_DIR];
  ip6_address_t outer_old_addr[VLIB_N_DIR];
  u16 new_port[VLIB_N_DIR];
  u16 old_port[VLIB_N_DIR];
  ip_csum_t sum, inner_l4_sum, inner_l4_old_sum;

  if (!icmp6_type_is_error_message (icmp->type))
    return;

  ip6_header_t *ip6 = (ip6_header_t *) (icmp + 2);
  udp_header_t *udp = (udp_header_t *) (ip6 + 1);
  tcp_header_t *tcp = (tcp_header_t *) udp;

  /* Swap inner ports */
  ip6_address_copy (&new_addr[VLIB_RX], &outer_new_addr[VLIB_TX]);
  ip6_address_copy (&new_addr[VLIB_TX], &outer_new_addr[VLIB_RX]);
  new_port[VLIB_TX] = outer_new_port[VLIB_RX];
  new_port[VLIB_RX] = outer_new_port[VLIB_TX];

  ip6_address_copy (&old_addr[VLIB_TX], &ip6->dst_address);
  ip6_address_copy (&old_addr[VLIB_RX], &ip6->src_address);
  old_port[VLIB_RX] = udp->src_port;
  old_port[VLIB_TX] = udp->dst_port;

  sum = icmp->checksum;
  /* Translate outer ip */
  ip6_address_copy (&outer_old_addr[VLIB_TX], &outer_ip6->dst_address);
  ip6_address_copy (&outer_old_addr[VLIB_RX], &outer_ip6->src_address);

  /* translate only if src_addr was translated */
  if (!cmp_ip6_address (&outer_ip6->src_address, &ip6->dst_address))
    ip6_address_copy (&outer_new_addr[VLIB_RX], &outer_ip6->src_address);
  cnat_ip6_translate_l3 (outer_ip6, outer_new_addr);

  sum = ip_csum_add_even (sum, outer_new_addr[VLIB_TX].as_u64[0]);
  sum = ip_csum_add_even (sum, outer_new_addr[VLIB_TX].as_u64[1]);
  sum = ip_csum_sub_even (sum, outer_old_addr[VLIB_TX].as_u64[0]);
  sum = ip_csum_sub_even (sum, outer_old_addr[VLIB_TX].as_u64[1]);

  sum = ip_csum_add_even (sum, outer_new_addr[VLIB_RX].as_u64[0]);
  sum = ip_csum_add_even (sum, outer_new_addr[VLIB_RX].as_u64[1]);
  sum = ip_csum_sub_even (sum, outer_old_addr[VLIB_RX].as_u64[0]);
  sum = ip_csum_sub_even (sum, outer_old_addr[VLIB_RX].as_u64[1]);

  /* Translate inner TCP / UDP */
  if (ip6->protocol == IP_PROTOCOL_TCP)
    {
      inner_l4_old_sum = inner_l4_sum = tcp->checksum;
      cnat_ip6_translate_l4 (ip6, udp, &inner_l4_sum, new_addr, new_port,
			     0 /* oflags */);
      tcp->checksum = ip_csum_fold (inner_l4_sum);
    }
  else if (ip6->protocol == IP_PROTOCOL_UDP)
    {
      inner_l4_old_sum = inner_l4_sum = udp->checksum;
      cnat_ip6_translate_l4 (ip6, udp, &inner_l4_sum, new_addr, new_port,
			     0 /* oflags */);
      udp->checksum = ip_csum_fold (inner_l4_sum);
    }
  else
    return;

  /* UDP/TCP checksum changed */
  sum = ip_csum_update (sum, inner_l4_old_sum, inner_l4_sum,
			ip4_header_t /* cheat */ ,
			checksum);

  /* UDP/TCP Ports changed */
  sum = ip_csum_update (sum, old_port[VLIB_TX], new_port[VLIB_TX],
			ip4_header_t /* cheat */, length /* changed member */);

  sum = ip_csum_update (sum, old_port[VLIB_RX], new_port[VLIB_RX],
			ip4_header_t /* cheat */, length /* changed member */);

  cnat_ip6_translate_l3 (ip6, new_addr);
  /* IP src/dst addr changed */
  sum = ip_csum_add_even (sum, new_addr[VLIB_TX].as_u64[0]);
  sum = ip_csum_add_even (sum, new_addr[VLIB_TX].as_u64[1]);
  sum = ip_csum_sub_even (sum, old_addr[VLIB_TX].as_u64[0]);
  sum = ip_csum_sub_even (sum, old_addr[VLIB_TX].as_u64[1]);

  sum = ip_csum_add_even (sum, new_addr[VLIB_RX].as_u64[0]);
  sum = ip_csum_add_even (sum, new_addr[VLIB_RX].as_u64[1]);
  sum = ip_csum_sub_even (sum, old_addr[VLIB_RX].as_u64[0]);
  sum = ip_csum_sub_even (sum, old_addr[VLIB_RX].as_u64[1]);

  icmp->checksum = ip_csum_fold (sum);
}

static_always_inline void
cnat_translation_ip6 (const cnat_5tuple_t *tuple, ip6_header_t *ip6,
		      udp_header_t *udp, u16 *lifetime, u32 oflags)
{
  tcp_header_t *tcp = (tcp_header_t *) udp;
  ip6_address_t new_addr[VLIB_N_DIR];
  u16 new_port[VLIB_N_DIR];

  ip6_address_copy (&new_addr[VLIB_TX], &tuple->ip[VLIB_TX].ip6);
  ip6_address_copy (&new_addr[VLIB_RX], &tuple->ip[VLIB_RX].ip6);
  new_port[VLIB_TX] = tuple->port[VLIB_TX];
  new_port[VLIB_RX] = tuple->port[VLIB_RX];

  if (ip6->protocol == IP_PROTOCOL_TCP)
    {
      ip_csum_t sum = tcp->checksum;
      cnat_ip6_translate_l4 (ip6, udp, &sum, new_addr, new_port, oflags);
      tcp->checksum = ip_csum_fold (sum);
      cnat_ip6_translate_l3 (ip6, new_addr);
      cnat_tcp_update_session_lifetime (tcp, lifetime);
    }
  else if (ip6->protocol == IP_PROTOCOL_UDP)
    {
      ip_csum_t sum = udp->checksum;
      cnat_ip6_translate_l4 (ip6, udp, &sum, new_addr, new_port, oflags);
      udp->checksum = ip_csum_fold (sum);
      cnat_ip6_translate_l3 (ip6, new_addr);
    }
  else if (ip6->protocol == IP_PROTOCOL_ICMP6)
    {
      icmp46_header_t *icmp = (icmp46_header_t *) udp;
      if (icmp6_type_is_error_message (icmp->type))
	cnat_translation_icmp6_error (ip6, icmp, new_addr, new_port);
      else if (icmp6_type_is_echo (icmp->type))
	cnat_translation_icmp6_echo (ip6, icmp, new_addr, new_port);
    }
}

static_always_inline void
cnat_make_buffer_5tuple (vlib_buffer_t *b, ip_address_family_t af,
			 cnat_5tuple_t *tup, u32 iph_offset, u8 swap)
{
  udp_header_t *udp;
  clib_memset (tup, 0, sizeof (*tup));
  if (AF_IP4 == af)
    {
      ip4_header_t *ip4;
      ip4 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b) + iph_offset);

      if (PREDICT_FALSE (ip4->protocol == IP_PROTOCOL_ICMP))
	{
	  icmp46_header_t *icmp = (icmp46_header_t *) (ip4 + 1);
	  if (icmp_type_is_error_message (icmp->type))
	    {
	      ip4 = (ip4_header_t *) (icmp + 2);	/* Use inner packet */
	      udp = (udp_header_t *) (ip4 + 1);
	      /* Swap dst & src for search as ICMP payload is reversed */
	      ip46_address_set_ip4 (&tup->ip[VLIB_RX ^ swap],
				    &ip4->dst_address);
	      ip46_address_set_ip4 (&tup->ip[VLIB_TX ^ swap],
				    &ip4->src_address);
	      tup->iproto = ip4->protocol;
	      tup->port[VLIB_TX ^ swap] = udp->src_port;
	      tup->port[VLIB_RX ^ swap] = udp->dst_port;
	    }
	  else if (icmp_type_is_echo (icmp->type))
	    {
	      cnat_echo_header_t *echo = (cnat_echo_header_t *) (icmp + 1);
	      ip46_address_set_ip4 (&tup->ip[VLIB_TX ^ swap],
				    &ip4->dst_address);
	      ip46_address_set_ip4 (&tup->ip[VLIB_RX ^ swap],
				    &ip4->src_address);
	      tup->iproto = ip4->protocol;
	      tup->port[VLIB_TX ^ swap] = echo->identifier;
	      tup->port[VLIB_RX ^ swap] = echo->identifier;
	    }
	}
      else if (ip4->protocol == IP_PROTOCOL_UDP ||
	       ip4->protocol == IP_PROTOCOL_TCP)
	{
	  udp = (udp_header_t *) (ip4 + 1);
	  ip46_address_set_ip4 (&tup->ip[VLIB_TX ^ swap], &ip4->dst_address);
	  ip46_address_set_ip4 (&tup->ip[VLIB_RX ^ swap], &ip4->src_address);
	  tup->iproto = ip4->protocol;
	  tup->port[VLIB_RX ^ swap] = udp->src_port;
	  tup->port[VLIB_TX ^ swap] = udp->dst_port;
	}
    }
  else
    {
      ip6_header_t *ip6;
      ip6 = (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b) + iph_offset);
      if (PREDICT_FALSE (ip6->protocol == IP_PROTOCOL_ICMP6))
	{
	  icmp46_header_t *icmp = (icmp46_header_t *) (ip6 + 1);
	  if (icmp6_type_is_error_message (icmp->type))
	    {
	      ip6 = (ip6_header_t *) (icmp + 2);	/* Use inner packet */
	      udp = (udp_header_t *) (ip6 + 1);
	      /* Swap dst & src for search as ICMP payload is reversed */
	      ip46_address_set_ip6 (&tup->ip[VLIB_RX ^ swap],
				    &ip6->dst_address);
	      ip46_address_set_ip6 (&tup->ip[VLIB_TX ^ swap],
				    &ip6->src_address);
	      tup->iproto = ip6->protocol;
	      tup->port[VLIB_TX ^ swap] = udp->src_port;
	      tup->port[VLIB_RX ^ swap] = udp->dst_port;
	    }
	  else if (icmp6_type_is_echo (icmp->type))
	    {
	      cnat_echo_header_t *echo = (cnat_echo_header_t *) (icmp + 1);
	      ip46_address_set_ip6 (&tup->ip[VLIB_TX ^ swap],
				    &ip6->dst_address);
	      ip46_address_set_ip6 (&tup->ip[VLIB_RX ^ swap],
				    &ip6->src_address);
	      tup->iproto = ip6->protocol;
	      tup->port[VLIB_TX ^ swap] = echo->identifier;
	      tup->port[VLIB_RX ^ swap] = echo->identifier;
	    }
	}
      else if (ip6->protocol == IP_PROTOCOL_UDP ||
	       ip6->protocol == IP_PROTOCOL_TCP)
	{
	  udp = (udp_header_t *) (ip6 + 1);
	  ip46_address_set_ip6 (&tup->ip[VLIB_TX ^ swap], &ip6->dst_address);
	  ip46_address_set_ip6 (&tup->ip[VLIB_RX ^ swap], &ip6->src_address);
	  tup->port[VLIB_RX ^ swap] = udp->src_port;
	  tup->port[VLIB_TX ^ swap] = udp->dst_port;
	  tup->iproto = ip6->protocol;
	}
    }
}

static_always_inline void
cnat_session_make_key (vlib_buffer_t *b, ip_address_family_t af,
		       cnat_bihash_kv_t *bkey, u32 iph_offset, u8 swap)
{
  cnat_session_t *session = (cnat_session_t *) bkey;
  session->key.cs_af = af;
  session->key.__cs_pad = 0;

  cnat_make_buffer_5tuple (b, af, &session->key.cs_5tuple, iph_offset, swap);
}

static_always_inline cnat_ep_trk_t *
cnat_load_balance (const cnat_translation_t *ct, ip_address_family_t af,
		   ip4_header_t *ip4, ip6_header_t *ip6, u32 *dpoi_index)
{
  cnat_main_t *cm = &cnat_main;
  const load_balance_t *lb0;
  const dpo_id_t *dpo0;
  u32 hash_c0, bucket0;

  lb0 = load_balance_get (ct->ct_lb.dpoi_index);
  if (PREDICT_FALSE (!lb0->lb_n_buckets))
    return (NULL);

  /* session table miss */
  hash_c0 = (AF_IP4 == af ? ip4_compute_flow_hash (ip4, lb0->lb_hash_config) :
			    ip6_compute_flow_hash (ip6, lb0->lb_hash_config));

  if (PREDICT_FALSE (ct->lb_type == CNAT_LB_MAGLEV))
    bucket0 = ct->lb_maglev[hash_c0 % cm->maglev_len];
  else
    bucket0 = hash_c0 % lb0->lb_n_buckets;

  dpo0 = load_balance_get_fwd_bucket (lb0, bucket0);

  *dpoi_index = dpo0->dpoi_index;

  return &ct->ct_active_paths[bucket0];
}

/**
 * Create NAT sessions
 * rsession_location is the location the (return) session will be
 * matched at
 */

static_always_inline void
cnat_rsession_create_client (cnat_timestamp_rewrite_t *rw,
			     ip_address_family_t af)
{
  cnat_client_t *cc;

  /* is this the first time we've seen this source address */
  cc = (AF_IP4 == af ? cnat_client_ip4_find (&rw->tuple.ip[VLIB_RX].ip4) :
		       cnat_client_ip6_find (&rw->tuple.ip[VLIB_RX].ip6));

  if (cc)
    {
      /* Refcount reverse session */
      cnat_client_cnt_session (cc);
      return;
    }

  /* New client */

  cnat_client_learn_args_t cl_args;
  uword *p;
  u32 refcnt;

  cl_args.addr.version = af;
  ip46_address_copy (&cl_args.addr.ip, &rw->tuple.ip[VLIB_RX]);

  /* Throttle */
  clib_spinlock_lock (&cnat_client_db.throttle_lock);

  p = hash_get_mem (cnat_client_db.throttle_mem, &cl_args.addr);
  if (p)
    {
      refcnt = p[0] + 1;
      hash_set_mem (cnat_client_db.throttle_mem, &cl_args.addr, refcnt);
    }
  else
    hash_set_mem_alloc (&cnat_client_db.throttle_mem, &cl_args.addr, 0);

  clib_spinlock_unlock (&cnat_client_db.throttle_lock);

  /* fire client create to the main thread */
  if (!p)
    vl_api_rpc_call_main_thread (cnat_client_learn, (u8 *) &cl_args,
				 sizeof (cl_args));
}

static_always_inline void
cnat_rsession_create (cnat_timestamp_rewrite_t *rw, ip_address_family_t af,
		      cnat_session_flag_t rsession_flags, ip_protocol_t iproto,
		      u32 flow_id)
{
  cnat_bihash_kv_t rkey;
  cnat_session_t *rsession = (cnat_session_t *) &rkey;
  cnat_bihash_kv_t rvalue;
  int rv;

  /* create the reverse flow key */
  ip46_address_copy (&rsession->key.cs_5tuple.ip[VLIB_RX],
		     &rw->tuple.ip[VLIB_TX]);
  ip46_address_copy (&rsession->key.cs_5tuple.ip[VLIB_TX],
		     &rw->tuple.ip[VLIB_RX]);
  rsession->key.cs_5tuple.iproto = iproto;
  rsession->key.__cs_pad = 0;
  rsession->key.cs_af = af;

  rsession->key.cs_5tuple.port[VLIB_RX] = rw->tuple.port[VLIB_TX];
  rsession->key.cs_5tuple.port[VLIB_TX] = rw->tuple.port[VLIB_RX];

  /* First search for existing reverse session */
  rv = cnat_bihash_search_i2 (&cnat_session_db, &rkey, &rvalue);
  if (!rv)
    {
      /* Reverse session already exists
         cleanup before creating for refcnts */
      cnat_session_t *found_rsession = (cnat_session_t *) & rvalue;
      cnat_session_free (found_rsession);
    }

  rsession->value.cs_session_index = flow_id;
  rsession->value.cs_flags = rsession_flags | CNAT_SESSION_IS_RETURN;

  cnat_bihash_add_del (&cnat_session_db, &rkey, 1);
}

static_always_inline void
cnat_set_rw_next_node (vlib_buffer_t *b, const cnat_timestamp_rewrite_t *rw,
		       u16 *next0)
{
  if (rw)
    {
      *next0 =
	rw->cts_dpoi_next_node == (u32) ~0 ? *next0 : rw->cts_dpoi_next_node;
      vnet_buffer (b)->ip.adj_index[VLIB_TX] =
	rw->cts_lbi == (u32) ~0 ? vnet_buffer (b)->ip.adj_index[VLIB_TX] :
				  rw->cts_lbi;
    }
}

static_always_inline void
cnat_translation (vlib_buffer_t *b, ip_address_family_t af,
		  const cnat_timestamp_rewrite_t *rw, u16 *lifetime,
		  u32 iph_offset)
{
  ip4_header_t *ip4 = NULL;
  ip6_header_t *ip6 = NULL;
  udp_header_t *udp0;

  if (PREDICT_FALSE (!rw))
    return;

  if (AF_IP4 == af)
    {
      ip4 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b) + iph_offset);
      udp0 = (udp_header_t *) (ip4 + 1);
      cnat_translation_ip4 (&rw->tuple, ip4, udp0, lifetime,
			    vnet_buffer (b)->oflags);
    }
  else
    {
      ip6 = (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b) + iph_offset);
      udp0 = (udp_header_t *) (ip6 + 1);
      cnat_translation_ip6 (&rw->tuple, ip6, udp0, lifetime,
			    vnet_buffer (b)->oflags);
    }
}

always_inline uword
cnat_lookup_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, ip_address_family_t af, u8 do_trace,
		    cnat_node_sub_t cnat_sub, u8 is_feature)
{
  u32 n_left, *from;
  f64 now = vlib_time_now (vm);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left);
  cnat_bihash_kv_t bkey[4], bvalue[4];
  u64 hash[4];
  int rv[4];

  /* Kickstart our state */
  if (n_left >= 4)
    {
      cnat_session_make_key (b[3], af, &bkey[3], 0, 0);
      cnat_session_make_key (b[2], af, &bkey[2], 0, 0);
      cnat_session_make_key (b[1], af, &bkey[1], 0, 0);
      cnat_session_make_key (b[0], af, &bkey[0], 0, 0);

      hash[3] = cnat_bihash_hash (&bkey[3]);
      hash[2] = cnat_bihash_hash (&bkey[2]);
      hash[1] = cnat_bihash_hash (&bkey[1]);
      hash[0] = cnat_bihash_hash (&bkey[0]);

      if (is_feature)
	{
	  vnet_feature_next_u16 (&next[3], b[3]);
	  vnet_feature_next_u16 (&next[2], b[2]);
	  vnet_feature_next_u16 (&next[1], b[1]);
	  vnet_feature_next_u16 (&next[0], b[0]);
	}
    }

  if (n_left >= 8 && is_feature)
    {
      vnet_feature_next_u16 (&next[7], b[7]);
      vnet_feature_next_u16 (&next[6], b[6]);
      vnet_feature_next_u16 (&next[5], b[5]);
      vnet_feature_next_u16 (&next[4], b[4]);
    }

  while (n_left >= 4)
    {

      rv[3] = cnat_bihash_search_i2_hash (&cnat_session_db, hash[3], &bkey[3],
					  &bvalue[3]);
      cnat_lookup_create_or_return (b[3], rv[3], &bkey[3], &bvalue[3], now);
      rv[2] = cnat_bihash_search_i2_hash (&cnat_session_db, hash[2], &bkey[2],
					  &bvalue[2]);
      cnat_lookup_create_or_return (b[2], rv[2], &bkey[2], &bvalue[2], now);
      rv[1] = cnat_bihash_search_i2_hash (&cnat_session_db, hash[1], &bkey[1],
					  &bvalue[1]);
      cnat_lookup_create_or_return (b[1], rv[1], &bkey[1], &bvalue[1], now);
      rv[0] = cnat_bihash_search_i2_hash (&cnat_session_db, hash[0], &bkey[0],
					  &bvalue[0]);
      cnat_lookup_create_or_return (b[0], rv[0], &bkey[0], &bvalue[0], now);

      if (cnat_sub != NULL)
	{
	  cnat_sub (vm, node, b[3], &next[3], af, now, do_trace);
	  cnat_sub (vm, node, b[2], &next[2], af, now, do_trace);
	  cnat_sub (vm, node, b[1], &next[1], af, now, do_trace);
	  cnat_sub (vm, node, b[0], &next[0], af, now, do_trace);
	}

      if (n_left >= 8)
	{
	  cnat_session_make_key (b[7], af, &bkey[3], 0, 0);
	  cnat_session_make_key (b[6], af, &bkey[2], 0, 0);
	  cnat_session_make_key (b[5], af, &bkey[1], 0, 0);
	  cnat_session_make_key (b[4], af, &bkey[0], 0, 0);

	  hash[3] = cnat_bihash_hash (&bkey[3]);
	  hash[2] = cnat_bihash_hash (&bkey[2]);
	  hash[1] = cnat_bihash_hash (&bkey[1]);
	  hash[0] = cnat_bihash_hash (&bkey[0]);

	  cnat_bihash_prefetch_bucket (&cnat_session_db, hash[3]);
	  cnat_bihash_prefetch_bucket (&cnat_session_db, hash[2]);
	  cnat_bihash_prefetch_bucket (&cnat_session_db, hash[1]);
	  cnat_bihash_prefetch_bucket (&cnat_session_db, hash[0]);
	}

      if (n_left >= 12)
	{
	  if (is_feature)
	    {
	      vnet_feature_next_u16 (&next[11], b[11]);
	      vnet_feature_next_u16 (&next[10], b[10]);
	      vnet_feature_next_u16 (&next[9], b[9]);
	      vnet_feature_next_u16 (&next[8], b[8]);
	    }

	  vlib_prefetch_buffer_data (b[11], LOAD);
	  vlib_prefetch_buffer_data (b[10], LOAD);
	  vlib_prefetch_buffer_data (b[9], LOAD);
	  vlib_prefetch_buffer_data (b[8], LOAD);
	}

      if (n_left >= 16)
	{
	  vlib_prefetch_buffer_header (b[15], LOAD);
	  vlib_prefetch_buffer_header (b[14], LOAD);
	  vlib_prefetch_buffer_header (b[13], LOAD);
	  vlib_prefetch_buffer_header (b[12], LOAD);
	}

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      if (is_feature)
	vnet_feature_next_u16 (&next[0], b[0]);

      cnat_session_make_key (b[0], af, &bkey[0], 0, 0);
      rv[0] = cnat_bihash_search_i2 (&cnat_session_db, &bkey[0], &bvalue[0]);
      cnat_lookup_create_or_return (b[0], rv[0], &bkey[0], &bvalue[0], now);

      if (cnat_sub != NULL)
	cnat_sub (vm, node, b[0], &next[0], af, now, do_trace);

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
