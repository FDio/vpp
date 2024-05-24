/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

/* how many time to retry when trying to allocate a source port? In the worst
 * case, we have a single source ip (or everything collide on the same src
 * ip). Then, if our port space 1024-65535 is full at 50%, we have a 50%
 * chance of collision when randomly choosing a src port.
 * Retrying 8 times mean we have 1/2^8 ~ 0.4% chance of failure (aka
 * overwriting an existing session, breaking it) */
#define CNAT_PORT_MAX_RETRIES 8

extern u8 *format_cnat_trace (u8 *s, va_list *args);

typedef void (*cnat_node_sub_t) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
				 u16 *next, ip_address_family_t af, f64 now, u8 do_trace);

typedef enum cnat_node_vip_next_t_
{
  CNAT_NODE_VIP_NEXT_DROP,
  CNAT_NODE_VIP_NEXT_LOOKUP,
  CNAT_NODE_VIP_N_NEXT,
} cnat_node_vip_next_t;

typedef struct cnat_trace_element_t_
{
  cnat_timestamp_rewrite_t rw;
  cnat_timestamp_t ts;
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
  CNAT_TRACE_REWRITE_FOUND = (1 << 3)
} cnat_trace_element_flag_t;

static_always_inline void
cnat_add_trace (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const cnat_timestamp_t *ts, const cnat_timestamp_rewrite_t *rw)
{
  cnat_trace_element_t *t;

  if (!(b->flags & VLIB_BUFFER_IS_TRACED))
    return;

  t = vlib_add_trace (vm, node, b, sizeof (*t));
  t->sw_if_index[VLIB_RX] = vnet_buffer (b)->sw_if_index[VLIB_RX];
  t->sw_if_index[VLIB_TX] = vnet_buffer (b)->sw_if_index[VLIB_TX];

  t->generic_flow_id = vnet_buffer2 (b)->session.generic_flow_id;
  t->flow_state = vnet_buffer2 (b)->session.state;

  if (ts)
    clib_memcpy (&t->ts, ts, sizeof (cnat_timestamp_t));

  t->flags = 0;
  if (rw)
    {
      clib_memcpy (&t->rw, rw, sizeof (cnat_timestamp_rewrite_t));
      t->flags |= CNAT_TRACE_REWRITE_FOUND;
    }
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
cnat_ip4_translate_l4 (ip4_header_t *ip4, udp_header_t *udp, u16 *pkt_csum,
		       ip4_address_t new_addr[VLIB_N_DIR], u16 new_port[VLIB_N_DIR], u32 oflags,
		       u16 *csum_diff, u8 *cts_flags)
{
  u16 old_port[VLIB_N_DIR];
  old_port[VLIB_TX] = udp->dst_port;
  old_port[VLIB_RX] = udp->src_port;
  ip_csum_t csum = *pkt_csum;

  udp->dst_port = new_port[VLIB_TX];
  udp->src_port = new_port[VLIB_RX];

  if (oflags &
      (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM | VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
    {
      *pkt_csum = ip4_pseudo_header_cksum2 (ip4, new_addr);
      return;
    }

  if (cts_flags && *cts_flags & CNAT_TS_RW_FLAG_CACHE_TS_L4)
    {
      csum = ip_csum_sub_even (csum, *csum_diff);
    }
  else
    {

      csum = ip_csum_update (csum, ip4->dst_address.as_u32, new_addr[VLIB_TX].as_u32, ip4_header_t,
			     dst_address);
      csum = ip_csum_update (csum, ip4->src_address.as_u32, new_addr[VLIB_RX].as_u32, ip4_header_t,
			     src_address);

      csum = ip_csum_update (csum, old_port[VLIB_TX], new_port[VLIB_TX], udp_header_t, dst_port);
      csum = ip_csum_update (csum, old_port[VLIB_RX], new_port[VLIB_RX], udp_header_t, src_port);

      if (csum_diff)
	{
	  *cts_flags |= CNAT_TS_RW_FLAG_CACHE_TS_L4;
	  *csum_diff = ip_csum_fold (ip_csum_add_even (csum, *pkt_csum));
	}
    }
  *pkt_csum = ip_csum_fold (csum);
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
cnat_ip4_translate_l3 (ip4_header_t *ip4, ip4_address_t new_addr[VLIB_N_DIR], u32 oflags,
		       u16 *csum_diff, u8 *cts_flags)
{
  ip4_address_t old_addr[VLIB_N_DIR];
  old_addr[VLIB_TX] = ip4->dst_address;
  old_addr[VLIB_RX] = ip4->src_address;
  ip_csum_t csum = ip4->checksum;

  ip4->dst_address = new_addr[VLIB_TX];
  ip4->src_address = new_addr[VLIB_RX];

  // We always compute the IP checksum even if oflags &
  // VNET_BUFFER_OFFLOAD_F_IP_CKSUM is set as this is relatively inexpensive
  // and will allow avoiding issues in driver that do not behave properly
  // downstream.

  if (cts_flags && *cts_flags & CNAT_TS_RW_FLAG_CACHE_TS_L3)
    {
      csum = ip_csum_sub_even (csum, *csum_diff);
    }
  else
    {
      csum = ip_csum_update (csum, old_addr[VLIB_TX].as_u32, new_addr[VLIB_TX].as_u32, ip4_header_t,
			     dst_address);
      csum = ip_csum_update (csum, old_addr[VLIB_RX].as_u32, new_addr[VLIB_RX].as_u32, ip4_header_t,
			     src_address);
      if (csum_diff)
	{
	  *cts_flags |= CNAT_TS_RW_FLAG_CACHE_TS_L3;
	  *csum_diff = ip_csum_fold (ip_csum_add_even (csum, ip4->checksum));
	}
    }

  ip4->checksum = ip_csum_fold (csum);
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

  cnat_ip4_translate_l3 (ip4, new_addr, oflags, NULL, 0);
  old_port = echo->identifier;
  echo->identifier = new_port[VLIB_RX];

  sum = icmp->checksum;
  sum =
    ip_csum_update (sum, old_port, new_port[VLIB_RX], udp_header_t, src_port);

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
  cnat_ip4_translate_l3 (outer_ip4, outer_new_addr, oflags, NULL, 0);

  if (ip4->protocol == IP_PROTOCOL_TCP)
    {
      inner_l4_old_sum = tcp->checksum;
      cnat_ip4_translate_l4 (ip4, udp, &tcp->checksum, new_addr, new_port, 0 /* flags */, NULL, 0);
      inner_l4_sum = tcp->checksum;
      /* TCP checksum changed */
      sum = ip_csum_update (sum, inner_l4_old_sum, inner_l4_sum, ip4_header_t,
			    checksum);
    }
  else if (ip4->protocol == IP_PROTOCOL_UDP)
    {
      inner_l4_old_sum = udp->checksum;
      cnat_ip4_translate_l4 (ip4, udp, &udp->checksum, new_addr, new_port, 0 /* flags */, NULL, 0);
      inner_l4_sum = udp->checksum;
      /* UDP checksum changed */
      sum = ip_csum_update (sum, inner_l4_old_sum, inner_l4_sum, ip4_header_t,
			    checksum);
    }
  else if (ip4->protocol == IP_PROTOCOL_ICMP)
    {
      icmp46_header_t *inner_icmp = (icmp46_header_t *) (ip4 + 1);
      if (icmp_type_is_echo (inner_icmp->type))
	{
	  cnat_echo_header_t *echo = (cnat_echo_header_t *) (inner_icmp + 1);
	  u16 old_id = echo->identifier;
	  echo->identifier = new_port[VLIB_RX];
	  /* Update outer ICMP checksum for identifier change */
	  sum = ip_csum_update (sum, old_id, new_port[VLIB_RX], udp_header_t, src_port);
	  /* Update inner ICMP checksum for identifier change */
	  inner_l4_old_sum = inner_icmp->checksum;
	  inner_icmp->checksum = ip_csum_fold (ip_csum_update (
	    inner_icmp->checksum, old_id, new_port[VLIB_RX], udp_header_t, src_port));
	  /* Update outer ICMP checksum for inner checksum change */
	  sum =
	    ip_csum_update (sum, inner_l4_old_sum, inner_icmp->checksum, ip4_header_t, checksum);
	}
      old_port[VLIB_TX] = 0;
      old_port[VLIB_RX] = 0;
    }
  else
    return;

  /* UDP/TCP Ports changed */
  if (old_port[VLIB_TX] && new_port[VLIB_TX])
    sum = ip_csum_update (sum, old_port[VLIB_TX], new_port[VLIB_TX],
			  udp_header_t, dst_port);

  if (old_port[VLIB_RX] && new_port[VLIB_RX])
    sum = ip_csum_update (sum, old_port[VLIB_RX], new_port[VLIB_RX],
			  udp_header_t, src_port);

  cnat_ip4_translate_l3 (ip4, new_addr, 0 /* oflags */, NULL, 0);
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
cnat_translation_ip4 (const cnat_5tuple_t *tuple, ip4_header_t *ip4, udp_header_t *udp,
		      u16 *lifetime, u32 oflags, cnat_cksum_diff_t *cksum, u8 *cts_flags)
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
      cnat_ip4_translate_l4 (ip4, udp, &tcp->checksum, new_addr, new_port, oflags, &cksum->l4,
			     cts_flags);
      cnat_ip4_translate_l3 (ip4, new_addr, oflags, &cksum->l3, cts_flags);
      cnat_tcp_update_session_lifetime (tcp, lifetime);
    }
  else if (ip4->protocol == IP_PROTOCOL_UDP)
    {
      cnat_ip4_translate_l4 (ip4, udp, &udp->checksum, new_addr, new_port, oflags, &cksum->l4,
			     cts_flags);
      cnat_ip4_translate_l3 (ip4, new_addr, oflags, &cksum->l3, cts_flags);
    }
  else if (ip4->protocol == IP_PROTOCOL_SCTP)
    {
      sctp_header_t *sctp = (sctp_header_t *) udp;
      cnat_ip4_translate_sctp (ip4, sctp, new_port);
      cnat_ip4_translate_l3 (ip4, new_addr, oflags, &cksum->l3, cts_flags);
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

  *sum = ip_csum_update (*sum, old_port[VLIB_TX], new_port[VLIB_TX],
			 udp_header_t, dst_port);

  *sum = ip_csum_update (*sum, old_port[VLIB_RX], new_port[VLIB_RX],
			 udp_header_t, src_port);
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
  sum =
    ip_csum_update (sum, old_port, new_port[VLIB_RX], udp_header_t, src_port);

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

      /* UDP/TCP checksum changed */
      sum = ip_csum_update (sum, inner_l4_old_sum, inner_l4_sum, ip4_header_t,
			    checksum);

      /* UDP/TCP Ports changed */
      sum = ip_csum_update (sum, old_port[VLIB_TX], new_port[VLIB_TX],
			    tcp_header_t, dst_port);

      sum = ip_csum_update (sum, old_port[VLIB_RX], new_port[VLIB_RX],
			    tcp_header_t, src_port);
    }
  else if (ip6->protocol == IP_PROTOCOL_UDP)
    {
      inner_l4_old_sum = inner_l4_sum = udp->checksum;
      cnat_ip6_translate_l4 (ip6, udp, &inner_l4_sum, new_addr, new_port,
			     0 /* oflags */);
      udp->checksum = ip_csum_fold (inner_l4_sum);

      /* UDP/TCP checksum changed */
      sum = ip_csum_update (sum, inner_l4_old_sum, inner_l4_sum, ip4_header_t,
			    checksum);

      /* UDP/TCP Ports changed */
      sum = ip_csum_update (sum, old_port[VLIB_TX], new_port[VLIB_TX],
			    udp_header_t, dst_port);

      sum = ip_csum_update (sum, old_port[VLIB_RX], new_port[VLIB_RX],
			    udp_header_t, src_port);
    }
  else if (ip6->protocol == IP_PROTOCOL_ICMP6)
    {
      /* Update ICMP6 checksum */
      icmp46_header_t *inner_icmp = (icmp46_header_t *) udp;
      ip_csum_t icmp_sum = inner_icmp->checksum;
      inner_l4_old_sum = inner_icmp->checksum;

      icmp_sum = ip_csum_add_even (icmp_sum, new_addr[VLIB_TX].as_u64[0]);
      icmp_sum = ip_csum_add_even (icmp_sum, new_addr[VLIB_TX].as_u64[1]);
      icmp_sum = ip_csum_sub_even (icmp_sum, ip6->dst_address.as_u64[0]);
      icmp_sum = ip_csum_sub_even (icmp_sum, ip6->dst_address.as_u64[1]);

      icmp_sum = ip_csum_add_even (icmp_sum, new_addr[VLIB_RX].as_u64[0]);
      icmp_sum = ip_csum_add_even (icmp_sum, new_addr[VLIB_RX].as_u64[1]);
      icmp_sum = ip_csum_sub_even (icmp_sum, ip6->src_address.as_u64[0]);
      icmp_sum = ip_csum_sub_even (icmp_sum, ip6->src_address.as_u64[1]);

      if (icmp6_type_is_echo (inner_icmp->type))
	{
	  cnat_echo_header_t *echo = (cnat_echo_header_t *) (inner_icmp + 1);
	  u16 old_id = echo->identifier;
	  echo->identifier = new_port[VLIB_RX];
	  icmp_sum = ip_csum_update (icmp_sum, old_id, new_port[VLIB_RX], udp_header_t, src_port);
	  /* Identifier changed in outer payload */
	  sum = ip_csum_update (sum, old_id, new_port[VLIB_RX], udp_header_t, src_port);
	}

      inner_icmp->checksum = ip_csum_fold (icmp_sum);

      /* Update ICMP6 checksum for inner checksum change */
      sum = ip_csum_update (sum, inner_l4_old_sum, inner_icmp->checksum, ip4_header_t, checksum);
    }
  else
    return;

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
cnat_translation_ip6 (const cnat_5tuple_t *tuple, ip6_header_t *ip6, udp_header_t *udp,
		      u16 *lifetime, u32 oflags)
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

/* Compute a session key out of a vlib_buffer
 * @param b            a vlib_buffer
 * @param af           the address family
 * @param iph_offset
 * @param swap         swap (src,dst) addr & port in tup / hash
 * @return tup         the computed 5tuple
 * @return hash        optional pointer to a u64 hash of the 5tuple
 */
static_always_inline void
cnat_make_buffer_5tuple (vlib_buffer_t *b, ip_address_family_t af, cnat_5tuple_t *tup,
			 u32 iph_offset, u8 swap)
{
  udp_header_t *udp;
  clib_memset (tup, 0, sizeof (*tup));
  /* We don't hash address family for now */
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
	      if (PREDICT_FALSE (ip4->protocol == IP_PROTOCOL_ICMP))
		{
		  icmp = (icmp46_header_t *) (ip4 + 1);
		  if (icmp_type_is_echo (icmp->type))
		    {
		      cnat_echo_header_t *echo =
			(cnat_echo_header_t *) (icmp + 1);
		      ip46_address_set_ip4 (&tup->ip[VLIB_RX ^ swap], &ip4->dst_address);
		      ip46_address_set_ip4 (&tup->ip[VLIB_TX ^ swap], &ip4->src_address);
		      tup->iproto = ip4->protocol;
		      tup->port[VLIB_TX ^ swap] = echo->identifier;
		      tup->port[VLIB_RX ^ swap] = echo->identifier;
		    }
		}
	      else
		{
		  udp = (udp_header_t *) (ip4 + 1);
		  /* Swap dst & src for search as ICMP payload is reversed */
		  ip46_address_set_ip4 (&tup->ip[VLIB_RX ^ swap], &ip4->dst_address);
		  ip46_address_set_ip4 (&tup->ip[VLIB_TX ^ swap], &ip4->src_address);
		  tup->iproto = ip4->protocol;
		  tup->port[VLIB_TX ^ swap] = udp->src_port;
		  tup->port[VLIB_RX ^ swap] = udp->dst_port;
		}
	    }
	  else if (icmp_type_is_echo (icmp->type))
	    {
	      cnat_echo_header_t *echo = (cnat_echo_header_t *) (icmp + 1);
	      ip46_address_set_ip4 (&tup->ip[VLIB_TX ^ swap], &ip4->dst_address);
	      ip46_address_set_ip4 (&tup->ip[VLIB_RX ^ swap], &ip4->src_address);
	      tup->iproto = ip4->protocol;
	      tup->port[VLIB_TX ^ swap] = echo->identifier;
	      tup->port[VLIB_RX ^ swap] = echo->identifier;
	    }
	}
      else if (ip4->protocol == IP_PROTOCOL_UDP || ip4->protocol == IP_PROTOCOL_TCP ||
	       ip4->protocol == IP_PROTOCOL_SCTP)
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
	      if (PREDICT_FALSE (ip6->protocol == IP_PROTOCOL_ICMP6))
		{
		  icmp = (icmp46_header_t *) (ip6 + 1);
		  if (icmp6_type_is_echo (icmp->type))
		    {
		      cnat_echo_header_t *echo =
			(cnat_echo_header_t *) (icmp + 1);
		      ip46_address_set_ip6 (&tup->ip[VLIB_RX ^ swap], &ip6->dst_address);
		      ip46_address_set_ip6 (&tup->ip[VLIB_TX ^ swap], &ip6->src_address);
		      tup->iproto = ip6->protocol;
		      tup->port[VLIB_TX ^ swap] = echo->identifier;
		      tup->port[VLIB_RX ^ swap] = echo->identifier;
		    }
		}
	      else
		{
		  udp = (udp_header_t *) (ip6 + 1);
		  /* Swap dst & src for search as ICMP payload is reversed */
		  ip46_address_set_ip6 (&tup->ip[VLIB_RX ^ swap], &ip6->dst_address);
		  ip46_address_set_ip6 (&tup->ip[VLIB_TX ^ swap], &ip6->src_address);
		  tup->iproto = ip6->protocol;
		  tup->port[VLIB_TX ^ swap] = udp->src_port;
		  tup->port[VLIB_RX ^ swap] = udp->dst_port;
		}
	    }
	  else if (icmp6_type_is_echo (icmp->type))
	    {
	      cnat_echo_header_t *echo = (cnat_echo_header_t *) (icmp + 1);
	      ip46_address_set_ip6 (&tup->ip[VLIB_TX ^ swap], &ip6->dst_address);
	      ip46_address_set_ip6 (&tup->ip[VLIB_RX ^ swap], &ip6->src_address);
	      tup->iproto = ip6->protocol;
	      tup->port[VLIB_TX ^ swap] = echo->identifier;
	      tup->port[VLIB_RX ^ swap] = echo->identifier;
	    }
	}
      else if (ip6->protocol == IP_PROTOCOL_UDP || ip6->protocol == IP_PROTOCOL_TCP ||
	       ip6->protocol == IP_PROTOCOL_SCTP)
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
cnat_rsession_create_client (cnat_timestamp_rewrite_t *rw, u32 ret_fib_index)
{
  cnat_client_t *cc;
  const ip_address_family_t af = ip46_address_is_ip4 (&rw->tuple.ip[VLIB_RX]) ? AF_IP4 : AF_IP6;

  /* is this the first time we've seen this source address */
  cc = (AF_IP4 == af ? cnat_client_ip4_find (&rw->tuple.ip[VLIB_RX].ip4, ret_fib_index) :
		       cnat_client_ip6_find (&rw->tuple.ip[VLIB_RX].ip6, ret_fib_index));

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
  ip46_address_copy (&ip_addr_46 (&cl_args.addr), &rw->tuple.ip[VLIB_RX]);
  cl_args.fib_index = ret_fib_index;

  /* Throttle */
  clib_spinlock_lock (&cnat_client_db.throttle_lock);

  p = hash_get_mem (cnat_client_db.throttle_mem, &cl_args);
  if (p)
    {
      refcnt = p[0] + 1;
      hash_set_mem (cnat_client_db.throttle_mem, &cl_args, refcnt);
    }
  else
    hash_set_mem_alloc (&cnat_client_db.throttle_mem, &cl_args, 0);

  clib_spinlock_unlock (&cnat_client_db.throttle_lock);

  /* fire client create to the main thread */
  if (!p)
    vlib_rpc_call_main_thread (cnat_client_learn, (u8 *) &cl_args, sizeof (cl_args));
}

/* This create a reverse session matching the return traffic
 * This return traffic is what a server replies, when you send
 * the ingress traffic with the rewrite operation 'rw' applied
 * */
static_always_inline void
cnat_rsession_create (cnat_timestamp_rewrite_t *rw, u32 flow_id, u32 ret_fib_index, int add_client,
		      u16 *sport, int *sport_retries, int *sport_failures)
{
  cnat_bihash_kv_t rkey = { 0 };
  cnat_session_t *rsession = (cnat_session_t *) &rkey;

  /* For ICMP echo, the echo identifier is a single field mapped to both
   * ports in the 5-tuple. Sync port[VLIB_TX] with port[VLIB_RX] (which
   * holds the possibly rewritten echo id) before the swap, so the reverse
   * session key matches the return packet's 5-tuple. */
  if (PREDICT_FALSE (rw->tuple.iproto == IP_PROTOCOL_ICMP || rw->tuple.iproto == IP_PROTOCOL_ICMP6))
    rw->tuple.port[VLIB_TX] = rw->tuple.port[VLIB_RX];

  /* create the reverse flow key */
  cnat_5tuple_copy (&rsession->key.cs_5tuple, &rw->tuple, 1 /* swap */);
  rsession->key.fib_index = ret_fib_index;

  rsession->value.cs_session_index = flow_id;
  rsession->value.cs_flags = CNAT_SESSION_IS_RETURN;

  if (add_client)
    {
      rsession->value.cs_flags |= CNAT_SESSION_FLAG_HAS_CLIENT;
      cnat_rsession_create_client (rw, CNAT_FIB_TABLE);
      cnat_client_throttle_pool_process (); /* FIXME */
    }

  if (sport)
    {
      /* Try to allocate the a new src port (hence a new dst port for the
       * return session). */
      *sport_retries = *sport_failures = 0;

      /* We 1st try to use the original src port */
      int rv = cnat_bihash_add_del (&cnat_session_db, &rkey, 2 /* no overwrite */);
      if (!rv)
	return; /* success! */

      /* The original src port is already in use, try something else: we'll
       * generate random ports and try to use that instead.
       * To do so, we recursively hash the flow id:
       *  - flow_id is unique per flow, hence it's a unique seed per flow
       *  - a 64-bits hash gives us up to 4x 16-bits port to try
       */
      u64 hash = flow_id;
      for (int i = 0; i < (CNAT_PORT_MAX_RETRIES + 3) / 4; i++)
	{
	  u64 hash_ = hash = clib_xxhash (hash);
	  for (int j = 0; j < 4; j++)
	    {
	      *sport = (hash_ & 0xffff);
	      /* if port is below 1024, add 1024 */
	      if (!(*sport & clib_host_to_net_u16 (~1023)))
		*sport |= clib_host_to_net_u16 (1024);
	      rsession->key.cs_5tuple.port[VLIB_TX] = *sport;
	      /* For ICMP echo, both ports in the 5-tuple map to the same
	       * echo identifier, so update port[VLIB_RX] as well. */
	      if (PREDICT_FALSE (rw->tuple.iproto == IP_PROTOCOL_ICMP ||
				 rw->tuple.iproto == IP_PROTOCOL_ICMP6))
		rsession->key.cs_5tuple.port[VLIB_RX] = *sport;
	      (*sport_retries)++;
	      int rv = cnat_bihash_add_del (&cnat_session_db, &rkey, 2 /* no overwrite */);
	      if (!rv)
		return;	   /* success ! */
	      hash_ >>= 2; /* try next port... */
	    }
	}

      /* no luck so far, let's overwrite some previous unlucky session... */
      (*sport_failures)++;
    }

  cnat_bihash_add_with_overwrite_cb (&cnat_session_db, &rkey, cnat_session_free_stale_cb, NULL);
}

static_always_inline void
cnat_set_rw_next_node (vlib_buffer_t *b, const cnat_timestamp_rewrite_t *rw, u16 *next0)
{
  if (rw)
    {
      *next0 = rw->cts_dpoi_next_node == (u16) ~0 ? *next0 : rw->cts_dpoi_next_node;
      vnet_buffer (b)->ip.adj_index[VLIB_TX] =
	rw->cts_lbi == (u32) ~0 ? vnet_buffer (b)->ip.adj_index[VLIB_TX] : rw->cts_lbi;
    }
}

static_always_inline void
cnat_translation (vlib_buffer_t *b, ip_address_family_t af, cnat_timestamp_rewrite_t *rw,
		  u16 *lifetime, u32 iph_offset)
{
  ip4_header_t *ip4 = NULL;
  ip6_header_t *ip6 = NULL;
  udp_header_t *udp0;

  if (PREDICT_FALSE (!rw))
    return;

  /* todo : we should pass rpaths as part of the api instead of a flag */
  if (PREDICT_FALSE (rw->cts_flags & CNAT_TS_RW_FLAG_NO_NAT))
    return;

  if (AF_IP4 == af)
    {
      ip4 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b) + iph_offset);
      udp0 = (udp_header_t *) (ip4 + 1);
      u8 cts_flags = rw->cts_flags;
      cnat_translation_ip4 (&rw->tuple, ip4, udp0, lifetime, vnet_buffer (b)->oflags, &rw->cksum,
			    &cts_flags);
      rw->cts_flags = cts_flags;
    }
  else
    {
      ip6 = (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b) + iph_offset);
      udp0 = (udp_header_t *) (ip6 + 1);
      cnat_translation_ip6 (&rw->tuple, ip6, udp0, lifetime, vnet_buffer (b)->oflags);
    }
}

always_inline uword
cnat_lookup_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
		    ip_address_family_t af, u8 do_trace, cnat_node_sub_t cnat_sub, u8 is_feature,
		    bool alloc_if_not_found)
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
  cnat_session_t *session[4];
  u64 hash[4];
  int rv[4];
  const bool is_v6 = AF_IP6 == af;
  u32 *fib_index_by_sw_if_index =
    is_v6 ? ip6_main.fib_index_by_sw_if_index : ip4_main.fib_index_by_sw_if_index;

  session[0] = ((cnat_session_t *) &bkey[0]);
  session[1] = ((cnat_session_t *) &bkey[1]);
  session[2] = ((cnat_session_t *) &bkey[2]);
  session[3] = ((cnat_session_t *) &bkey[3]);

  /* make sure all paddings are 0 */
  clib_memset_u8 (&session[0]->key, 0, sizeof (session[0]->key));
  clib_memset_u8 (&session[1]->key, 0, sizeof (session[1]->key));
  clib_memset_u8 (&session[2]->key, 0, sizeof (session[2]->key));
  clib_memset_u8 (&session[3]->key, 0, sizeof (session[3]->key));

  /* Kickstart our state */
  if (n_left >= 4)
    {
      cnat_make_buffer_5tuple (b[0], af, (cnat_5tuple_t *) &bkey[0], 0, 0);
      cnat_make_buffer_5tuple (b[1], af, (cnat_5tuple_t *) &bkey[1], 0, 0);
      cnat_make_buffer_5tuple (b[2], af, (cnat_5tuple_t *) &bkey[2], 0, 0);
      cnat_make_buffer_5tuple (b[3], af, (cnat_5tuple_t *) &bkey[3], 0, 0);

      ip_lookup_set_buffer_fib_index (fib_index_by_sw_if_index, b[0]);
      ip_lookup_set_buffer_fib_index (fib_index_by_sw_if_index, b[1]);
      ip_lookup_set_buffer_fib_index (fib_index_by_sw_if_index, b[2]);
      ip_lookup_set_buffer_fib_index (fib_index_by_sw_if_index, b[3]);

      session[0]->key.fib_index = vnet_buffer (b[0])->ip.fib_index;
      session[1]->key.fib_index = vnet_buffer (b[1])->ip.fib_index;
      session[2]->key.fib_index = vnet_buffer (b[2])->ip.fib_index;
      session[3]->key.fib_index = vnet_buffer (b[3])->ip.fib_index;

      hash[0] = cnat_bihash_hash (&bkey[0]);
      hash[1] = cnat_bihash_hash (&bkey[1]);
      hash[2] = cnat_bihash_hash (&bkey[2]);
      hash[3] = cnat_bihash_hash (&bkey[3]);

      if (is_feature)
	{
	  vnet_feature_next_u16 (&next[0], b[0]);
	  vnet_feature_next_u16 (&next[1], b[1]);
	  vnet_feature_next_u16 (&next[2], b[2]);
	  vnet_feature_next_u16 (&next[3], b[3]);
	}
    }

  if (n_left >= 8 && is_feature)
    {
      vnet_feature_next_u16 (&next[4], b[4]);
      vnet_feature_next_u16 (&next[5], b[5]);
      vnet_feature_next_u16 (&next[6], b[6]);
      vnet_feature_next_u16 (&next[7], b[7]);
    }

  while (n_left >= 4)
    {

      rv[0] = cnat_bihash_search_i2_hash (&cnat_session_db, hash[0], &bkey[0], &bvalue[0]);
      cnat_lookup_create_or_return (b[0], rv[0], &bkey[0], &bvalue[0], now, hash[0], is_v6,
				    alloc_if_not_found);
      rv[1] = cnat_bihash_search_i2_hash (&cnat_session_db, hash[1], &bkey[1],
					  &bvalue[1]);
      cnat_lookup_create_or_return (b[1], rv[1], &bkey[1], &bvalue[1], now, hash[1], is_v6,
				    alloc_if_not_found);
      rv[2] = cnat_bihash_search_i2_hash (&cnat_session_db, hash[2], &bkey[2], &bvalue[2]);
      cnat_lookup_create_or_return (b[2], rv[2], &bkey[2], &bvalue[2], now, hash[2], is_v6,
				    alloc_if_not_found);
      rv[3] = cnat_bihash_search_i2_hash (&cnat_session_db, hash[3], &bkey[3], &bvalue[3]);
      cnat_lookup_create_or_return (b[3], rv[3], &bkey[3], &bvalue[3], now, hash[3], is_v6,
				    alloc_if_not_found);

      if (cnat_sub != NULL)
	{
	  cnat_sub (vm, node, b[0], &next[0], af, now, do_trace);
	  cnat_sub (vm, node, b[1], &next[1], af, now, do_trace);
	  cnat_sub (vm, node, b[2], &next[2], af, now, do_trace);
	  cnat_sub (vm, node, b[3], &next[3], af, now, do_trace);
	}

      if (n_left >= 8)
	{
	  cnat_make_buffer_5tuple (b[4], af, (cnat_5tuple_t *) &bkey[0], 0, 0);
	  cnat_make_buffer_5tuple (b[5], af, (cnat_5tuple_t *) &bkey[1], 0, 0);
	  cnat_make_buffer_5tuple (b[6], af, (cnat_5tuple_t *) &bkey[2], 0, 0);
	  cnat_make_buffer_5tuple (b[7], af, (cnat_5tuple_t *) &bkey[3], 0, 0);

	  ip_lookup_set_buffer_fib_index (fib_index_by_sw_if_index, b[4]);
	  ip_lookup_set_buffer_fib_index (fib_index_by_sw_if_index, b[5]);
	  ip_lookup_set_buffer_fib_index (fib_index_by_sw_if_index, b[6]);
	  ip_lookup_set_buffer_fib_index (fib_index_by_sw_if_index, b[7]);

	  session[0]->key.fib_index = vnet_buffer (b[4])->ip.fib_index;
	  session[1]->key.fib_index = vnet_buffer (b[5])->ip.fib_index;
	  session[2]->key.fib_index = vnet_buffer (b[6])->ip.fib_index;
	  session[3]->key.fib_index = vnet_buffer (b[7])->ip.fib_index;

	  hash[0] = cnat_bihash_hash (&bkey[0]);
	  hash[1] = cnat_bihash_hash (&bkey[1]);
	  hash[2] = cnat_bihash_hash (&bkey[2]);
	  hash[3] = cnat_bihash_hash (&bkey[3]);

	  cnat_bihash_prefetch_bucket (&cnat_session_db, hash[0]);
	  cnat_bihash_prefetch_bucket (&cnat_session_db, hash[1]);
	  cnat_bihash_prefetch_bucket (&cnat_session_db, hash[2]);
	  cnat_bihash_prefetch_bucket (&cnat_session_db, hash[3]);
	}

      if (n_left >= 12)
	{
	  if (is_feature)
	    {
	      vnet_feature_next_u16 (&next[8], b[8]);
	      vnet_feature_next_u16 (&next[9], b[9]);
	      vnet_feature_next_u16 (&next[10], b[10]);
	      vnet_feature_next_u16 (&next[11], b[11]);
	    }

	  vlib_prefetch_buffer_data (b[8], LOAD);
	  vlib_prefetch_buffer_data (b[9], LOAD);
	  vlib_prefetch_buffer_data (b[10], LOAD);
	  vlib_prefetch_buffer_data (b[11], LOAD);
	}

      if (n_left >= 16)
	{
	  vlib_prefetch_buffer_header (b[12], LOAD);
	  vlib_prefetch_buffer_header (b[13], LOAD);
	  vlib_prefetch_buffer_header (b[14], LOAD);
	  vlib_prefetch_buffer_header (b[15], LOAD);
	}

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      if (is_feature)
	vnet_feature_next_u16 (&next[0], b[0]);

      cnat_make_buffer_5tuple (b[0], af, (cnat_5tuple_t *) &bkey[0], 0, 0);
      ip_lookup_set_buffer_fib_index (fib_index_by_sw_if_index, b[0]);
      session[0]->key.fib_index = vnet_buffer (b[0])->ip.fib_index;
      hash[0] = cnat_bihash_hash (&bkey[0]);

      rv[0] = cnat_bihash_search_i2_hash (&cnat_session_db, hash[0], &bkey[0], &bvalue[0]);
      cnat_lookup_create_or_return (b[0], rv[0], &bkey[0], &bvalue[0], now, hash[0], is_v6,
				    alloc_if_not_found);

      if (cnat_sub != NULL)
	cnat_sub (vm, node, b[0], &next[0], af, now, do_trace);

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

static_always_inline void
cnat_node_select_ip4 (ip4_address_t *ip, const ip4_address_t *pfx, u32 mask)
{
  if ((u32) ~0 == mask)
    {
      /* /32 prefix: copy the address */
      ip->as_u32 = pfx->as_u32;
    }
  else
    {
      ASSERT (0 == (pfx->as_u32 & mask));
      u32 addr;
#ifdef clib_crc32c_uses_intrinsics
      addr = clib_crc32c ((void *) ip, sizeof (*ip));
#else
      addr = clib_xxhash (ip->as_u32);
#endif
      ip->as_u32 = pfx->as_u32 | (addr & mask);
    }
}

static_always_inline void
cnat_node_select_ip6 (ip6_address_t *ip, const ip6_address_t *pfx, u64 mask)
{
  if ((u64) ~0 == mask)
    {
      /* /128 prefix: copy the address */
      ip6_address_copy (ip, pfx);
    }
  else
    {
      ASSERT (0 == (pfx->as_u64[1] & mask));
      union
      {
	u64 as_u64;
	u32 as_u32[2];
      } addr;
#ifdef clib_crc32c_uses_intrinsics
      addr.as_u32[0] = ip->as_u32[2];
      addr.as_u32[1] = clib_crc32c ((void *) ip, sizeof (*ip));
#else
      addr.as_u64 = clib_xxhash (ip6_address_hash_to_u64 (ip));
#endif
      ip->as_u64[0] = pfx->as_u64[0];
      ip->as_u64[1] = pfx->as_u64[1] | (addr.as_u64 & mask);
    }
}

#endif
