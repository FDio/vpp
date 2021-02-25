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
#include <vnet/ip/ip_psh_cksum.h>

#include <cnat/cnat_session.h>
#include <cnat/cnat_client.h>
#include <cnat/cnat_inline.h>
#include <cnat/cnat_translation.h>

#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

typedef uword (*cnat_node_sub_t) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_buffer_t * b,
				  cnat_node_ctx_t * ctx, int rv,
				  cnat_session_t * session);

typedef struct cnat_trace_element_t_
{
  cnat_session_t session;
  cnat_translation_t tr;
  u32 sw_if_index[VLIB_N_RX_TX];
  u32 snat_policy_result;
  u8 flags;
} cnat_trace_element_t;

typedef enum cnat_trace_element_flag_t_
{
  CNAT_TRACE_SESSION_FOUND = (1 << 0),
  CNAT_TRACE_SESSION_CREATED = (1 << 1),
  CNAT_TRACE_TRANSLATION_FOUND = (1 << 2),
  CNAT_TRACE_NO_NAT = (1 << 3),
} cnat_trace_element_flag_t;

static_always_inline void
cnat_add_trace (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		cnat_session_t *session, const cnat_translation_t *ct,
		u8 flags)
{
  cnat_trace_element_t *t;
  if (NULL != ct)
    flags |= CNAT_TRACE_TRANSLATION_FOUND;

  t = vlib_add_trace (vm, node, b, sizeof (*t));
  t->sw_if_index[VLIB_RX] = vnet_buffer (b)->sw_if_index[VLIB_RX];
  t->sw_if_index[VLIB_TX] = vnet_buffer (b)->sw_if_index[VLIB_TX];

  if (flags & (CNAT_TRACE_SESSION_FOUND | CNAT_TRACE_SESSION_CREATED))
    clib_memcpy (&t->session, session, sizeof (t->session));
  if (flags & CNAT_TRACE_TRANSLATION_FOUND)
    clib_memcpy (&t->tr, ct, sizeof (cnat_translation_t));
  t->flags = flags;
}

static u8 *
format_cnat_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cnat_trace_element_t *t = va_arg (*args, cnat_trace_element_t *);
  u32 indent = format_get_indent (s);
  vnet_main_t *vnm = vnet_get_main ();

  if (t->flags & CNAT_TRACE_SESSION_CREATED)
    s = format (s, "created session");
  else if (t->flags & CNAT_TRACE_SESSION_FOUND)
    s = format (s, "found session");
  else
    s = format (s, "session not found");

  if (t->flags & (CNAT_TRACE_NO_NAT))
    s = format (s, " [policy:skip]");

  s = format (s, "\n%Uin:%U out:%U ", format_white_space, indent,
	      format_vnet_sw_if_index_name, vnm, t->sw_if_index[VLIB_RX],
	      format_vnet_sw_if_index_name, vnm, t->sw_if_index[VLIB_TX]);

  if (t->flags & (CNAT_TRACE_SESSION_CREATED | CNAT_TRACE_SESSION_FOUND))
    s = format (s, "\n%U%U", format_white_space, indent, format_cnat_session,
		&t->session, 1);

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

static_always_inline u16
ip4_pseudo_header_cksum2 (ip4_header_t *ip4, ip4_address_t address[VLIB_N_DIR])
{
  ip4_psh_t psh = { 0 };
  psh.src = address[VLIB_RX];
  psh.dst = address[VLIB_TX];
  psh.proto = ip4->protocol;
  psh.l4len = clib_host_to_net_u16 (clib_net_to_host_u16 (ip4->length) -
				    sizeof (ip4_header_t));
  return ~(clib_ip_csum ((u8 *) &psh, sizeof (ip4_psh_t)));
}

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

  if (oflags &
      (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM | VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
    {
      *sum = ip4_pseudo_header_cksum2 (ip4, new_addr);
      return;
    }

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
cnat_ip4_translate_sctp (ip4_header_t *ip4, sctp_header_t *sctp,
			 u16 new_port[VLIB_N_DIR])
{
  /* Fastpath no checksum */
  if (PREDICT_TRUE (0 == sctp->checksum))
    {
      sctp->dst_port = new_port[VLIB_TX];
      sctp->src_port = new_port[VLIB_RX];
      return;
    }

  if (new_port[VLIB_TX])
    sctp->dst_port = new_port[VLIB_TX];
  if (new_port[VLIB_RX])
    sctp->src_port = new_port[VLIB_RX];

  sctp->checksum = 0;
  sctp->checksum = clib_host_to_little_u32 (~clib_crc32c_with_init (
    (u8 *) sctp, ntohs (ip4->length) - sizeof (ip4_header_t),
    ~0 /* init value */));
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

  // We always compute the IP checksum even if oflags &
  // VNET_BUFFER_OFFLOAD_F_IP_CKSUM is set as this is relatively inexpensive
  // and will allow avoiding issues in driver that do not behave properly
  // downstream.
  sum = ip4->checksum;
  sum = ip_csum_update (sum, old_addr[VLIB_TX].as_u32,
			new_addr[VLIB_TX].as_u32, ip4_header_t, dst_address);
  sum = ip_csum_update (sum, old_addr[VLIB_RX].as_u32,
			new_addr[VLIB_RX].as_u32, ip4_header_t, src_address);
  ip4->checksum = ip_csum_fold (sum);
}

static_always_inline void
cnat_tcp_update_session_lifetime (tcp_header_t * tcp, u32 index)
{
  cnat_main_t *cm = &cnat_main;
  if (PREDICT_FALSE (tcp_fin (tcp)))
    cnat_timestamp_set_lifetime (index, CNAT_DEFAULT_TCP_RST_TIMEOUT);

  if (PREDICT_FALSE (tcp_rst (tcp)))
    cnat_timestamp_set_lifetime (index, CNAT_DEFAULT_TCP_RST_TIMEOUT);

  if (PREDICT_FALSE (tcp_syn (tcp) && tcp_ack (tcp)))
    cnat_timestamp_set_lifetime (index, cm->tcp_max_age);
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
			      u16 outer_new_port[VLIB_N_DIR], u8 snat_outer_ip,
			      u32 oflags)
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

  /* translate outer ip. */
  if (!snat_outer_ip)
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
cnat_translation_ip4 (const cnat_session_t *session, ip4_header_t *ip4,
		      udp_header_t *udp, u32 oflags)
{
  tcp_header_t *tcp = (tcp_header_t *) udp;
  ip4_address_t new_addr[VLIB_N_DIR];
  u16 new_port[VLIB_N_DIR];

  new_addr[VLIB_TX] = session->value.cs_ip[VLIB_TX].ip4;
  new_addr[VLIB_RX] = session->value.cs_ip[VLIB_RX].ip4;
  new_port[VLIB_TX] = session->value.cs_port[VLIB_TX];
  new_port[VLIB_RX] = session->value.cs_port[VLIB_RX];

  if (ip4->protocol == IP_PROTOCOL_TCP)
    {
      ip_csum_t sum = tcp->checksum;
      cnat_ip4_translate_l4 (ip4, udp, &sum, new_addr, new_port, oflags);
      tcp->checksum = ip_csum_fold (sum);
      cnat_ip4_translate_l3 (ip4, new_addr, oflags);
      cnat_tcp_update_session_lifetime (tcp, session->value.cs_ts_index);
    }
  else if (ip4->protocol == IP_PROTOCOL_UDP)
    {
      ip_csum_t sum = udp->checksum;
      cnat_ip4_translate_l4 (ip4, udp, &sum, new_addr, new_port, oflags);
      udp->checksum = ip_csum_fold (sum);
      cnat_ip4_translate_l3 (ip4, new_addr, oflags);
    }
  else if (ip4->protocol == IP_PROTOCOL_SCTP)
    {
      sctp_header_t *sctp = (sctp_header_t *) udp;
      cnat_ip4_translate_sctp (ip4, sctp, new_port);
      cnat_ip4_translate_l3 (ip4, new_addr, oflags);
    }
  else if (ip4->protocol == IP_PROTOCOL_ICMP)
    {
      icmp46_header_t *icmp = (icmp46_header_t *) udp;
      if (icmp_type_is_error_message (icmp->type))
	{
	  /* SNAT only if src_addr was translated */
	  u8 snat_outer_ip =
	    (ip4->src_address.as_u32 ==
	     session->key.cs_ip[VLIB_RX].ip4.as_u32);
	  cnat_translation_icmp4_error (ip4, icmp, new_addr, new_port,
					snat_outer_ip, oflags);
	}
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

static_always_inline u16
ip6_pseudo_header_cksum2 (ip6_header_t *ip6, ip6_address_t address[VLIB_N_DIR])
{
  ip6_psh_t psh = { 0 };
  psh.src = address[VLIB_RX];
  psh.dst = address[VLIB_TX];
  psh.l4len = ip6->payload_length;
  psh.proto = clib_host_to_net_u32 ((u32) ip6->protocol);
  return ~(clib_ip_csum ((u8 *) &psh, sizeof (ip6_psh_t)));
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

  if (oflags &
      (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM | VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
    {
      *sum = ip6_pseudo_header_cksum2 (ip6, new_addr);
      return;
    }

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
cnat_translation_icmp6_error (ip6_header_t * outer_ip6,
			      icmp46_header_t * icmp,
			      ip6_address_t outer_new_addr[VLIB_N_DIR],
			      u16 outer_new_port[VLIB_N_DIR],
			      u8 snat_outer_ip)
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
  if (!snat_outer_ip)
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
cnat_translation_ip6 (const cnat_session_t *session, ip6_header_t *ip6,
		      udp_header_t *udp, u32 oflags)
{
  tcp_header_t *tcp = (tcp_header_t *) udp;
  ip6_address_t new_addr[VLIB_N_DIR];
  u16 new_port[VLIB_N_DIR];

  ip6_address_copy (&new_addr[VLIB_TX], &session->value.cs_ip[VLIB_TX].ip6);
  ip6_address_copy (&new_addr[VLIB_RX], &session->value.cs_ip[VLIB_RX].ip6);
  new_port[VLIB_TX] = session->value.cs_port[VLIB_TX];
  new_port[VLIB_RX] = session->value.cs_port[VLIB_RX];

  if (ip6->protocol == IP_PROTOCOL_TCP)
    {
      ip_csum_t sum = tcp->checksum;
      cnat_ip6_translate_l4 (ip6, udp, &sum, new_addr, new_port, oflags);
      tcp->checksum = ip_csum_fold (sum);
      cnat_ip6_translate_l3 (ip6, new_addr);
      cnat_tcp_update_session_lifetime (tcp, session->value.cs_ts_index);
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
	{
	  /* SNAT only if src_addr was translated */
	  u8 snat_outer_ip = cmp_ip6_address (&ip6->src_address,
					      &session->key.
					      cs_ip[VLIB_RX].ip6);
	  cnat_translation_icmp6_error (ip6, icmp, new_addr, new_port,
					snat_outer_ip);
	}
      else if (icmp6_type_is_echo (icmp->type))
	cnat_translation_icmp6_echo (ip6, icmp, new_addr, new_port);
    }
}

static_always_inline void
cnat_session_make_key (vlib_buffer_t *b, ip_address_family_t af,
		       cnat_session_location_t cs_loc, cnat_bihash_kv_t *bkey)
{
  udp_header_t *udp;
  cnat_session_t *session = (cnat_session_t *) bkey;
  u32 iph_offset = 0;
  session->key.cs_af = af;

  session->key.cs_loc = cs_loc;
  session->key.__cs_pad = 0;
  if (cs_loc == CNAT_LOCATION_OUTPUT)
    /* rewind buffer */
    iph_offset = vnet_buffer (b)->ip.save_rewrite_length;

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
	      ip46_address_set_ip4 (&session->key.cs_ip[VLIB_RX],
				    &ip4->dst_address);
	      ip46_address_set_ip4 (&session->key.cs_ip[VLIB_TX],
				    &ip4->src_address);
	      session->key.cs_proto = ip4->protocol;
	      session->key.cs_port[VLIB_TX] = udp->src_port;
	      session->key.cs_port[VLIB_RX] = udp->dst_port;
	    }
	  else if (icmp_type_is_echo (icmp->type))
	    {
	      cnat_echo_header_t *echo = (cnat_echo_header_t *) (icmp + 1);
	      ip46_address_set_ip4 (&session->key.cs_ip[VLIB_TX],
				    &ip4->dst_address);
	      ip46_address_set_ip4 (&session->key.cs_ip[VLIB_RX],
				    &ip4->src_address);
	      session->key.cs_proto = ip4->protocol;
	      session->key.cs_port[VLIB_TX] = echo->identifier;
	      session->key.cs_port[VLIB_RX] = echo->identifier;
	    }
	  else
	    goto error;
	}
      else if (ip4->protocol == IP_PROTOCOL_UDP ||
	       ip4->protocol == IP_PROTOCOL_TCP)
	{
	  udp = (udp_header_t *) (ip4 + 1);
	  ip46_address_set_ip4 (&session->key.cs_ip[VLIB_TX],
				&ip4->dst_address);
	  ip46_address_set_ip4 (&session->key.cs_ip[VLIB_RX],
				&ip4->src_address);
	  session->key.cs_proto = ip4->protocol;
	  session->key.cs_port[VLIB_RX] = udp->src_port;
	  session->key.cs_port[VLIB_TX] = udp->dst_port;
	}
      else if (ip4->protocol == IP_PROTOCOL_SCTP)
	{
	  sctp_header_t *sctp;
	  sctp = (sctp_header_t *) (ip4 + 1);
	  ip46_address_set_ip4 (&session->key.cs_ip[VLIB_TX],
				&ip4->dst_address);
	  ip46_address_set_ip4 (&session->key.cs_ip[VLIB_RX],
				&ip4->src_address);
	  session->key.cs_proto = ip4->protocol;
	  session->key.cs_port[VLIB_RX] = sctp->src_port;
	  session->key.cs_port[VLIB_TX] = sctp->dst_port;
	}
      else
	goto error;
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
	      ip46_address_set_ip6 (&session->key.cs_ip[VLIB_RX],
				    &ip6->dst_address);
	      ip46_address_set_ip6 (&session->key.cs_ip[VLIB_TX],
				    &ip6->src_address);
	      session->key.cs_proto = ip6->protocol;
	      session->key.cs_port[VLIB_TX] = udp->src_port;
	      session->key.cs_port[VLIB_RX] = udp->dst_port;
	    }
	  else if (icmp6_type_is_echo (icmp->type))
	    {
	      cnat_echo_header_t *echo = (cnat_echo_header_t *) (icmp + 1);
	      ip46_address_set_ip6 (&session->key.cs_ip[VLIB_TX],
				    &ip6->dst_address);
	      ip46_address_set_ip6 (&session->key.cs_ip[VLIB_RX],
				    &ip6->src_address);
	      session->key.cs_proto = ip6->protocol;
	      session->key.cs_port[VLIB_TX] = echo->identifier;
	      session->key.cs_port[VLIB_RX] = echo->identifier;
	    }
	  else
	    goto error;
	}
      else if (ip6->protocol == IP_PROTOCOL_UDP ||
	       ip6->protocol == IP_PROTOCOL_TCP)
	{
	  udp = (udp_header_t *) (ip6 + 1);
	  ip46_address_set_ip6 (&session->key.cs_ip[VLIB_TX],
				&ip6->dst_address);
	  ip46_address_set_ip6 (&session->key.cs_ip[VLIB_RX],
				&ip6->src_address);
	  session->key.cs_port[VLIB_RX] = udp->src_port;
	  session->key.cs_port[VLIB_TX] = udp->dst_port;
	  session->key.cs_proto = ip6->protocol;
	}
      else
	goto error;
    }
  return;

error:
  /* Ensure we dont find anything */
  session->key.cs_proto = 0;
  return;
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
cnat_session_create (cnat_session_t *session, cnat_node_ctx_t *ctx,
		     cnat_session_location_t rsession_location,
		     u8 rsession_flags)
{
  cnat_client_t *cc;
  cnat_bihash_kv_t rkey;
  cnat_session_t *rsession = (cnat_session_t *) & rkey;
  cnat_bihash_kv_t *bkey = (cnat_bihash_kv_t *) session;
  int rv, n_retries = 0;
  static u32 sport_seed = 0;

  session->value.cs_ts_index = cnat_timestamp_new (ctx->now);

  /* First create the return session */
  ip46_address_copy (&rsession->key.cs_ip[VLIB_RX],
		     &session->value.cs_ip[VLIB_TX]);
  ip46_address_copy (&rsession->key.cs_ip[VLIB_TX],
		     &session->value.cs_ip[VLIB_RX]);
  rsession->key.cs_proto = session->key.cs_proto;
  rsession->key.cs_loc = rsession_location;
  rsession->key.__cs_pad = 0;
  rsession->key.cs_af = ctx->af;
  rsession->key.cs_port[VLIB_RX] = session->value.cs_port[VLIB_TX];
  rsession->key.cs_port[VLIB_TX] = session->value.cs_port[VLIB_RX];

  ip46_address_copy (&rsession->value.cs_ip[VLIB_RX],
		     &session->key.cs_ip[VLIB_TX]);
  ip46_address_copy (&rsession->value.cs_ip[VLIB_TX],
		     &session->key.cs_ip[VLIB_RX]);
  rsession->value.cs_ts_index = session->value.cs_ts_index;
  rsession->value.cs_lbi = INDEX_INVALID;
  rsession->value.flags = rsession_flags | CNAT_SESSION_IS_RETURN;
  rsession->value.cs_port[VLIB_TX] = session->key.cs_port[VLIB_RX];
  rsession->value.cs_port[VLIB_RX] = session->key.cs_port[VLIB_TX];

retry_add_ression:
  rv = cnat_bihash_add_del (&cnat_session_db, &rkey,
			    2 /* add but don't overwrite */);
  if (rv)
    {
      if (!(rsession_flags & CNAT_SESSION_RETRY_SNAT))
	return;

      /* return session add failed pick an new random src port */
      rsession->value.cs_port[VLIB_TX] = session->key.cs_port[VLIB_RX] =
	random_u32 (&sport_seed);
      if (n_retries++ < 100)
	goto retry_add_ression;
      else
	{
	  clib_warning ("Could not find a free port after 100 tries");
	  /* translate this packet, but don't create state */
	  return;
	}
    }

  cnat_bihash_add_del (&cnat_session_db, bkey, 1 /* add */);

  if (!(rsession_flags & CNAT_SESSION_FLAG_NO_CLIENT))
    {
      /* is this the first time we've seen this source address */
      cc = (AF_IP4 == ctx->af ?
	      cnat_client_ip4_find (&session->value.cs_ip[VLIB_RX].ip4) :
	      cnat_client_ip6_find (&session->value.cs_ip[VLIB_RX].ip6));

      if (NULL == cc)
	{
	  ip_address_t addr;
	  uword *p;
	  u32 refcnt;

	  addr.version = ctx->af;
	  ip46_address_copy (&addr.ip, &session->value.cs_ip[VLIB_RX]);

	  /* Throttle */
	  clib_spinlock_lock (&cnat_client_db.throttle_lock);

	  p = hash_get_mem (cnat_client_db.throttle_mem, &addr);
	  if (p)
	    {
	      refcnt = p[0] + 1;
	      hash_set_mem (cnat_client_db.throttle_mem, &addr, refcnt);
	    }
	  else
	    hash_set_mem_alloc (&cnat_client_db.throttle_mem, &addr, 0);

	  clib_spinlock_unlock (&cnat_client_db.throttle_lock);

	  /* fire client create to the main thread */
	  if (!p)
	    vl_api_rpc_call_main_thread (cnat_client_learn, (u8 *) &addr,
					 sizeof (addr));
	}
      else
	{
	  /* Refcount reverse session */
	  cnat_client_cnt_session (cc);
	}
    }

}

always_inline uword
cnat_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vlib_frame_t *frame, cnat_node_sub_t cnat_sub,
		  ip_address_family_t af, cnat_session_location_t cs_loc,
		  u8 do_trace)
{
  u32 n_left, *from, thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  f64 now;

  thread_index = vm->thread_index;
  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left);
  now = vlib_time_now (vm);
  cnat_session_t *session[4];
  cnat_bihash_kv_t bkey[4], bvalue[4];
  u64 hash[4];
  int rv[4];

  cnat_node_ctx_t ctx = { now, thread_index, af, do_trace };

  if (n_left >= 8)
    {
      /* Kickstart our state */
      cnat_session_make_key (b[3], af, cs_loc, &bkey[3]);
      cnat_session_make_key (b[2], af, cs_loc, &bkey[2]);
      cnat_session_make_key (b[1], af, cs_loc, &bkey[1]);
      cnat_session_make_key (b[0], af, cs_loc, &bkey[0]);

      hash[3] = cnat_bihash_hash (&bkey[3]);
      hash[2] = cnat_bihash_hash (&bkey[2]);
      hash[1] = cnat_bihash_hash (&bkey[1]);
      hash[0] = cnat_bihash_hash (&bkey[0]);
    }

  while (n_left >= 8)
    {
      if (n_left >= 12)
	{
	  vlib_prefetch_buffer_header (b[11], LOAD);
	  vlib_prefetch_buffer_header (b[10], LOAD);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	  vlib_prefetch_buffer_header (b[8], LOAD);
	}

      rv[3] = cnat_bihash_search_i2_hash (&cnat_session_db, hash[3], &bkey[3],
					  &bvalue[3]);
      session[3] = (cnat_session_t *) (rv[3] ? &bkey[3] : &bvalue[3]);
      next[3] = cnat_sub (vm, node, b[3], &ctx, rv[3], session[3]);

      rv[2] = cnat_bihash_search_i2_hash (&cnat_session_db, hash[2], &bkey[2],
					  &bvalue[2]);
      session[2] = (cnat_session_t *) (rv[2] ? &bkey[2] : &bvalue[2]);
      next[2] = cnat_sub (vm, node, b[2], &ctx, rv[2], session[2]);

      rv[1] = cnat_bihash_search_i2_hash (&cnat_session_db, hash[1], &bkey[1],
					  &bvalue[1]);
      session[1] = (cnat_session_t *) (rv[1] ? &bkey[1] : &bvalue[1]);
      next[1] = cnat_sub (vm, node, b[1], &ctx, rv[1], session[1]);

      rv[0] = cnat_bihash_search_i2_hash (&cnat_session_db, hash[0], &bkey[0],
					  &bvalue[0]);
      session[0] = (cnat_session_t *) (rv[0] ? &bkey[0] : &bvalue[0]);
      next[0] = cnat_sub (vm, node, b[0], &ctx, rv[0], session[0]);

      cnat_session_make_key (b[7], af, cs_loc, &bkey[3]);
      cnat_session_make_key (b[6], af, cs_loc, &bkey[2]);
      cnat_session_make_key (b[5], af, cs_loc, &bkey[1]);
      cnat_session_make_key (b[4], af, cs_loc, &bkey[0]);

      hash[3] = cnat_bihash_hash (&bkey[3]);
      hash[2] = cnat_bihash_hash (&bkey[2]);
      hash[1] = cnat_bihash_hash (&bkey[1]);
      hash[0] = cnat_bihash_hash (&bkey[0]);

      cnat_bihash_prefetch_bucket (&cnat_session_db, hash[3]);
      cnat_bihash_prefetch_bucket (&cnat_session_db, hash[2]);
      cnat_bihash_prefetch_bucket (&cnat_session_db, hash[1]);
      cnat_bihash_prefetch_bucket (&cnat_session_db, hash[0]);

      cnat_bihash_prefetch_data (&cnat_session_db, hash[3]);
      cnat_bihash_prefetch_data (&cnat_session_db, hash[2]);
      cnat_bihash_prefetch_data (&cnat_session_db, hash[1]);
      cnat_bihash_prefetch_data (&cnat_session_db, hash[0]);

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      cnat_session_make_key (b[0], af, cs_loc, &bkey[0]);
      rv[0] = cnat_bihash_search_i2 (&cnat_session_db, &bkey[0], &bvalue[0]);

      session[0] = (cnat_session_t *) (rv[0] ? &bkey[0] : &bvalue[0]);
      next[0] = cnat_sub (vm, node, b[0], &ctx, rv[0], session[0]);

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
