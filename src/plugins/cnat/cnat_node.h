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
#include <cnat/cnat_session.h>
#include <cnat/cnat_client.h>
#include <cnat/cnat_inline.h>

typedef uword (*cnat_node_sub_t) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_buffer_t * b,
				  cnat_node_ctx_t * ctx, int rv,
				  cnat_session_t * session);

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

static_always_inline u8
has_ip6_address (ip6_address_t * a)
{
  return ((0 != a->as_u64[0]) || (0 != a->as_u64[1]));
}

static_always_inline void
cnat_ip4_translate_l4 (ip4_header_t * ip4, udp_header_t * udp,
		       ip_csum_t * sum,
		       ip4_address_t new_addr[VLIB_N_DIR],
		       u16 new_port[VLIB_N_DIR])
{
  u16 old_port[VLIB_N_DIR];
  ip4_address_t old_addr[VLIB_N_DIR];

  /* Fastpath no checksum */
  if (PREDICT_TRUE (0 == *sum))
    {
      udp->dst_port = new_port[VLIB_TX];
      udp->src_port = new_port[VLIB_RX];
      return;
    }

  old_port[VLIB_TX] = udp->dst_port;
  old_port[VLIB_RX] = udp->src_port;
  old_addr[VLIB_TX] = ip4->dst_address;
  old_addr[VLIB_RX] = ip4->src_address;

  if (new_addr[VLIB_TX].as_u32)
    {
      *sum =
	ip_csum_update (*sum, old_addr[VLIB_TX].as_u32,
			new_addr[VLIB_TX].as_u32, ip4_header_t, dst_address);
    }
  if (new_port[VLIB_TX])
    {
      udp->dst_port = new_port[VLIB_TX];
      *sum = ip_csum_update (*sum, old_port[VLIB_TX], new_port[VLIB_TX],
			     ip4_header_t /* cheat */ ,
			     length /* changed member */ );
    }
  if (new_addr[VLIB_RX].as_u32)
    {
      *sum =
	ip_csum_update (*sum, old_addr[VLIB_RX].as_u32,
			new_addr[VLIB_RX].as_u32, ip4_header_t, src_address);
    }
  if (new_port[VLIB_RX])
    {
      udp->src_port = new_port[VLIB_RX];
      *sum = ip_csum_update (*sum, old_port[VLIB_RX], new_port[VLIB_RX],
			     ip4_header_t /* cheat */ ,
			     length /* changed member */ );
    }
}

static_always_inline void
cnat_ip4_translate_l3 (ip4_header_t * ip4, ip4_address_t new_addr[VLIB_N_DIR])
{
  ip4_address_t old_addr[VLIB_N_DIR];
  ip_csum_t sum;

  old_addr[VLIB_TX] = ip4->dst_address;
  old_addr[VLIB_RX] = ip4->src_address;

  sum = ip4->checksum;
  if (new_addr[VLIB_TX].as_u32)
    {
      ip4->dst_address = new_addr[VLIB_TX];
      sum =
	ip_csum_update (sum, old_addr[VLIB_TX].as_u32,
			new_addr[VLIB_TX].as_u32, ip4_header_t, dst_address);
    }
  if (new_addr[VLIB_RX].as_u32)
    {
      ip4->src_address = new_addr[VLIB_RX];
      sum =
	ip_csum_update (sum, old_addr[VLIB_RX].as_u32,
			new_addr[VLIB_RX].as_u32, ip4_header_t, src_address);
    }
  ip4->checksum = ip_csum_fold (sum);
}

static_always_inline void
cnat_tcp_update_session_lifetime (tcp_header_t * tcp, u32 index)
{
  cnat_main_t *cm = &cnat_main;
  if (PREDICT_FALSE (tcp_fin (tcp)))
    {
      cnat_timestamp_set_lifetime (index, CNAT_DEFAULT_TCP_RST_TIMEOUT);
    }

  if (PREDICT_FALSE (tcp_rst (tcp)))
    {
      cnat_timestamp_set_lifetime (index, CNAT_DEFAULT_TCP_RST_TIMEOUT);
    }

  if (PREDICT_FALSE (tcp_syn (tcp) && tcp_ack (tcp)))
    {
      cnat_timestamp_set_lifetime (index, cm->tcp_max_age);
    }
}

static_always_inline void
cnat_translation_icmp4_echo (ip4_header_t * ip4, icmp46_header_t * icmp,
			     ip4_address_t new_addr[VLIB_N_DIR],
			     u16 new_port[VLIB_N_DIR])
{
  ip_csum_t sum;
  u16 old_port;
  cnat_echo_header_t *echo = (cnat_echo_header_t *) (icmp + 1);

  cnat_ip4_translate_l3 (ip4, new_addr);
  old_port = echo->identifier;
  echo->identifier = new_port[VLIB_RX];

  sum = icmp->checksum;
  sum = ip_csum_update (sum, old_port, new_port[VLIB_RX],
			ip4_header_t /* cheat */ ,
			length /* changed member */ );

  icmp->checksum = ip_csum_fold (sum);
}

static_always_inline void
cnat_translation_icmp4_error (ip4_header_t * outer_ip4,
			      icmp46_header_t * icmp,
			      ip4_address_t outer_new_addr[VLIB_N_DIR],
			      u16 outer_new_port[VLIB_N_DIR],
			      u8 snat_outer_ip)
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
  cnat_ip4_translate_l3 (outer_ip4, outer_new_addr);

  if (ip4->protocol == IP_PROTOCOL_TCP)
    {
      inner_l4_old_sum = inner_l4_sum = tcp->checksum;
      cnat_ip4_translate_l4 (ip4, udp, &inner_l4_sum, new_addr, new_port);
      tcp->checksum = ip_csum_fold (inner_l4_sum);
    }
  else if (ip4->protocol == IP_PROTOCOL_UDP)
    {
      inner_l4_old_sum = inner_l4_sum = udp->checksum;
      cnat_ip4_translate_l4 (ip4, udp, &inner_l4_sum, new_addr, new_port);
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


  cnat_ip4_translate_l3 (ip4, new_addr);
  ip_csum_t new_ip_sum = ip4->checksum;
  /* IP checksum changed */
  sum = ip_csum_update (sum, old_ip_sum, new_ip_sum, ip4_header_t, checksum);

  /* IP src/dst addr changed */
  if (new_addr[VLIB_TX].as_u32)
    sum =
      ip_csum_update (sum, old_addr[VLIB_TX].as_u32, new_addr[VLIB_TX].as_u32,
		      ip4_header_t, dst_address);

  if (new_addr[VLIB_RX].as_u32)
    sum =
      ip_csum_update (sum, old_addr[VLIB_RX].as_u32, new_addr[VLIB_RX].as_u32,
		      ip4_header_t, src_address);

  icmp->checksum = ip_csum_fold (sum);
}

static_always_inline void
cnat_translation_ip4 (const cnat_session_t * session,
		      ip4_header_t * ip4, udp_header_t * udp)
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
      cnat_ip4_translate_l4 (ip4, udp, &sum, new_addr, new_port);
      tcp->checksum = ip_csum_fold (sum);
      cnat_ip4_translate_l3 (ip4, new_addr);
      cnat_tcp_update_session_lifetime (tcp, session->value.cs_ts_index);
    }
  else if (ip4->protocol == IP_PROTOCOL_UDP)
    {
      ip_csum_t sum = udp->checksum;
      cnat_ip4_translate_l4 (ip4, udp, &sum, new_addr, new_port);
      udp->checksum = ip_csum_fold (sum);
      cnat_ip4_translate_l3 (ip4, new_addr);
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
					snat_outer_ip);
	}
      else if (icmp_type_is_echo (icmp->type))
	cnat_translation_icmp4_echo (ip4, icmp, new_addr, new_port);
    }
}

static_always_inline void
cnat_ip6_translate_l3 (ip6_header_t * ip6, ip6_address_t new_addr[VLIB_N_DIR])
{
  if (has_ip6_address (&new_addr[VLIB_TX]))
    ip6_address_copy (&ip6->dst_address, &new_addr[VLIB_TX]);
  if (has_ip6_address (&new_addr[VLIB_RX]))
    ip6_address_copy (&ip6->src_address, &new_addr[VLIB_RX]);
}

static_always_inline void
cnat_ip6_translate_l4 (ip6_header_t * ip6, udp_header_t * udp,
		       ip_csum_t * sum,
		       ip6_address_t new_addr[VLIB_N_DIR],
		       u16 new_port[VLIB_N_DIR])
{
  u16 old_port[VLIB_N_DIR];
  ip6_address_t old_addr[VLIB_N_DIR];

  /* Fastpath no checksum */
  if (PREDICT_TRUE (0 == *sum))
    {
      udp->dst_port = new_port[VLIB_TX];
      udp->src_port = new_port[VLIB_RX];
      return;
    }

  old_port[VLIB_TX] = udp->dst_port;
  old_port[VLIB_RX] = udp->src_port;
  ip6_address_copy (&old_addr[VLIB_TX], &ip6->dst_address);
  ip6_address_copy (&old_addr[VLIB_RX], &ip6->src_address);

  if (has_ip6_address (&new_addr[VLIB_TX]))
    {
      *sum = ip_csum_add_even (*sum, new_addr[VLIB_TX].as_u64[0]);
      *sum = ip_csum_add_even (*sum, new_addr[VLIB_TX].as_u64[1]);
      *sum = ip_csum_sub_even (*sum, old_addr[VLIB_TX].as_u64[0]);
      *sum = ip_csum_sub_even (*sum, old_addr[VLIB_TX].as_u64[1]);
    }

  if (new_port[VLIB_TX])
    {
      udp->dst_port = new_port[VLIB_TX];
      *sum = ip_csum_update (*sum, old_port[VLIB_TX], new_port[VLIB_TX],
			     ip4_header_t /* cheat */ ,
			     length /* changed member */ );
    }
  if (has_ip6_address (&new_addr[VLIB_RX]))
    {
      *sum = ip_csum_add_even (*sum, new_addr[VLIB_RX].as_u64[0]);
      *sum = ip_csum_add_even (*sum, new_addr[VLIB_RX].as_u64[1]);
      *sum = ip_csum_sub_even (*sum, old_addr[VLIB_RX].as_u64[0]);
      *sum = ip_csum_sub_even (*sum, old_addr[VLIB_RX].as_u64[1]);
    }

  if (new_port[VLIB_RX])
    {
      udp->src_port = new_port[VLIB_RX];
      *sum = ip_csum_update (*sum, old_port[VLIB_RX], new_port[VLIB_RX],
			     ip4_header_t /* cheat */ ,
			     length /* changed member */ );
    }
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
  if (has_ip6_address (&new_addr[VLIB_TX]))
    {
      sum = ip_csum_add_even (sum, new_addr[VLIB_TX].as_u64[0]);
      sum = ip_csum_add_even (sum, new_addr[VLIB_TX].as_u64[1]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_TX].as_u64[0]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_TX].as_u64[1]);
    }

  if (has_ip6_address (&new_addr[VLIB_RX]))
    {
      sum = ip_csum_add_even (sum, new_addr[VLIB_RX].as_u64[0]);
      sum = ip_csum_add_even (sum, new_addr[VLIB_RX].as_u64[1]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_RX].as_u64[0]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_RX].as_u64[1]);
    }

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
  if (has_ip6_address (&outer_new_addr[VLIB_TX]))
    {
      sum = ip_csum_add_even (sum, outer_new_addr[VLIB_TX].as_u64[0]);
      sum = ip_csum_add_even (sum, outer_new_addr[VLIB_TX].as_u64[1]);
      sum = ip_csum_sub_even (sum, outer_old_addr[VLIB_TX].as_u64[0]);
      sum = ip_csum_sub_even (sum, outer_old_addr[VLIB_TX].as_u64[1]);
    }

  if (has_ip6_address (&outer_new_addr[VLIB_RX]))
    {
      sum = ip_csum_add_even (sum, outer_new_addr[VLIB_RX].as_u64[0]);
      sum = ip_csum_add_even (sum, outer_new_addr[VLIB_RX].as_u64[1]);
      sum = ip_csum_sub_even (sum, outer_old_addr[VLIB_RX].as_u64[0]);
      sum = ip_csum_sub_even (sum, outer_old_addr[VLIB_RX].as_u64[1]);
    }

  /* Translate inner TCP / UDP */
  if (ip6->protocol == IP_PROTOCOL_TCP)
    {
      inner_l4_old_sum = inner_l4_sum = tcp->checksum;
      cnat_ip6_translate_l4 (ip6, udp, &inner_l4_sum, new_addr, new_port);
      tcp->checksum = ip_csum_fold (inner_l4_sum);
    }
  else if (ip6->protocol == IP_PROTOCOL_UDP)
    {
      inner_l4_old_sum = inner_l4_sum = udp->checksum;
      cnat_ip6_translate_l4 (ip6, udp, &inner_l4_sum, new_addr, new_port);
      udp->checksum = ip_csum_fold (inner_l4_sum);
    }
  else
    return;

  /* UDP/TCP checksum changed */
  sum = ip_csum_update (sum, inner_l4_old_sum, inner_l4_sum,
			ip4_header_t /* cheat */ ,
			checksum);

  /* UDP/TCP Ports changed */
  if (old_port[VLIB_TX] && new_port[VLIB_TX])
    sum = ip_csum_update (sum, old_port[VLIB_TX], new_port[VLIB_TX],
			  ip4_header_t /* cheat */ ,
			  length /* changed member */ );

  if (old_port[VLIB_RX] && new_port[VLIB_RX])
    sum = ip_csum_update (sum, old_port[VLIB_RX], new_port[VLIB_RX],
			  ip4_header_t /* cheat */ ,
			  length /* changed member */ );


  cnat_ip6_translate_l3 (ip6, new_addr);
  /* IP src/dst addr changed */
  if (has_ip6_address (&new_addr[VLIB_TX]))
    {
      sum = ip_csum_add_even (sum, new_addr[VLIB_TX].as_u64[0]);
      sum = ip_csum_add_even (sum, new_addr[VLIB_TX].as_u64[1]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_TX].as_u64[0]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_TX].as_u64[1]);
    }

  if (has_ip6_address (&new_addr[VLIB_RX]))
    {
      sum = ip_csum_add_even (sum, new_addr[VLIB_RX].as_u64[0]);
      sum = ip_csum_add_even (sum, new_addr[VLIB_RX].as_u64[1]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_RX].as_u64[0]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_RX].as_u64[1]);
    }

  icmp->checksum = ip_csum_fold (sum);
}

static_always_inline void
cnat_translation_ip6 (const cnat_session_t * session,
		      ip6_header_t * ip6, udp_header_t * udp)
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
      cnat_ip6_translate_l4 (ip6, udp, &sum, new_addr, new_port);
      tcp->checksum = ip_csum_fold (sum);
      cnat_ip6_translate_l3 (ip6, new_addr);
      cnat_tcp_update_session_lifetime (tcp, session->value.cs_ts_index);
    }
  else if (ip6->protocol == IP_PROTOCOL_UDP)
    {
      ip_csum_t sum = udp->checksum;
      cnat_ip6_translate_l4 (ip6, udp, &sum, new_addr, new_port);
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
cnat_session_make_key (vlib_buffer_t * b, ip_address_family_t af,
		       clib_bihash_kv_40_48_t * bkey)
{
  udp_header_t *udp;
  cnat_session_t *session = (cnat_session_t *) bkey;
  session->key.cs_af = af;
  session->key.__cs_pad[0] = 0;
  session->key.__cs_pad[1] = 0;
  if (AF_IP4 == af)
    {
      ip4_header_t *ip4;
      ip4 = vlib_buffer_get_current (b);
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
      else
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

    }
  else
    {
      ip6_header_t *ip6;
      ip6 = vlib_buffer_get_current (b);
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
      else
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
    }
  return;

error:
  /* Ensure we dont find anything */
  session->key.cs_proto = 0;
  return;
}

/**
 * Create NAT sessions
 */

static_always_inline void
cnat_session_create (cnat_session_t * session, cnat_node_ctx_t * ctx,
		     u8 rsession_flags)
{
  cnat_client_t *cc;
  clib_bihash_kv_40_48_t rkey;
  cnat_session_t *rsession = (cnat_session_t *) & rkey;
  clib_bihash_kv_40_48_t *bkey = (clib_bihash_kv_40_48_t *) session;
  clib_bihash_kv_40_48_t rvalue;
  int rv;

  session->value.cs_ts_index = cnat_timestamp_new (ctx->now);
  clib_bihash_add_del_40_48 (&cnat_session_db, bkey, 1);

  /* is this the first time we've seen this source address */
  if (!(rsession_flags & CNAT_SESSION_FLAG_NO_CLIENT))
    {
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
	    vl_api_rpc_call_main_thread (cnat_client_learn, (u8 *) & addr,
					 sizeof (addr));
	}
      else
	{
	  /* Refcount reverse session */
	  cnat_client_cnt_session (cc);
	}
    }

  /* create the reverse flow key */
  ip46_address_copy (&rsession->key.cs_ip[VLIB_RX],
		     &session->value.cs_ip[VLIB_TX]);
  ip46_address_copy (&rsession->key.cs_ip[VLIB_TX],
		     &session->value.cs_ip[VLIB_RX]);
  rsession->key.cs_proto = session->key.cs_proto;
  rsession->key.__cs_pad[0] = 0;
  rsession->key.__cs_pad[1] = 0;
  rsession->key.cs_af = ctx->af;
  rsession->key.cs_port[VLIB_RX] = session->value.cs_port[VLIB_TX];
  rsession->key.cs_port[VLIB_TX] = session->value.cs_port[VLIB_RX];

  /* First search for existing reverse session */
  rv = clib_bihash_search_inline_2_40_48 (&cnat_session_db, &rkey, &rvalue);
  if (!rv)
    {
      /* Reverse session already exists
         cleanup before creating for refcnts */
      cnat_session_t *found_rsession = (cnat_session_t *) & rvalue;
      cnat_session_free (found_rsession);
    }
  /* add the reverse flow */
  ip46_address_copy (&rsession->value.cs_ip[VLIB_RX],
		     &session->key.cs_ip[VLIB_TX]);
  ip46_address_copy (&rsession->value.cs_ip[VLIB_TX],
		     &session->key.cs_ip[VLIB_RX]);
  rsession->value.cs_ts_index = session->value.cs_ts_index;
  rsession->value.cs_lbi = INDEX_INVALID;
  rsession->value.flags = rsession_flags;
  rsession->value.cs_port[VLIB_TX] = session->key.cs_port[VLIB_RX];
  rsession->value.cs_port[VLIB_RX] = session->key.cs_port[VLIB_TX];

  clib_bihash_add_del_40_48 (&cnat_session_db, &rkey, 1);
}

always_inline uword
cnat_node_inline (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame,
		  cnat_node_sub_t cnat_sub,
		  ip_address_family_t af, u8 do_trace)
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
  clib_bihash_kv_40_48_t bkey[4], bvalue[4];
  u64 hash[4];
  int rv[4];

  cnat_node_ctx_t ctx = { now, thread_index, af, do_trace };

  if (n_left >= 8)
    {
      /* Kickstart our state */
      cnat_session_make_key (b[3], af, &bkey[3]);
      cnat_session_make_key (b[2], af, &bkey[2]);
      cnat_session_make_key (b[1], af, &bkey[1]);
      cnat_session_make_key (b[0], af, &bkey[0]);

      hash[3] = clib_bihash_hash_40_48 (&bkey[3]);
      hash[2] = clib_bihash_hash_40_48 (&bkey[2]);
      hash[1] = clib_bihash_hash_40_48 (&bkey[1]);
      hash[0] = clib_bihash_hash_40_48 (&bkey[0]);
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

      rv[3] =
	clib_bihash_search_inline_2_with_hash_40_48 (&cnat_session_db,
						     hash[3], &bkey[3],
						     &bvalue[3]);
      session[3] = (cnat_session_t *) (rv[3] ? &bkey[3] : &bvalue[3]);
      next[3] = cnat_sub (vm, node, b[3], &ctx, rv[3], session[3]);

      rv[2] =
	clib_bihash_search_inline_2_with_hash_40_48 (&cnat_session_db,
						     hash[2], &bkey[2],
						     &bvalue[2]);
      session[2] = (cnat_session_t *) (rv[2] ? &bkey[2] : &bvalue[2]);
      next[2] = cnat_sub (vm, node, b[2], &ctx, rv[2], session[2]);

      rv[1] =
	clib_bihash_search_inline_2_with_hash_40_48 (&cnat_session_db,
						     hash[1], &bkey[1],
						     &bvalue[1]);
      session[1] = (cnat_session_t *) (rv[1] ? &bkey[1] : &bvalue[1]);
      next[1] = cnat_sub (vm, node, b[1], &ctx, rv[1], session[1]);

      rv[0] =
	clib_bihash_search_inline_2_with_hash_40_48 (&cnat_session_db,
						     hash[0], &bkey[0],
						     &bvalue[0]);
      session[0] = (cnat_session_t *) (rv[0] ? &bkey[0] : &bvalue[0]);
      next[0] = cnat_sub (vm, node, b[0], &ctx, rv[0], session[0]);

      cnat_session_make_key (b[7], af, &bkey[3]);
      cnat_session_make_key (b[6], af, &bkey[2]);
      cnat_session_make_key (b[5], af, &bkey[1]);
      cnat_session_make_key (b[4], af, &bkey[0]);

      hash[3] = clib_bihash_hash_40_48 (&bkey[3]);
      hash[2] = clib_bihash_hash_40_48 (&bkey[2]);
      hash[1] = clib_bihash_hash_40_48 (&bkey[1]);
      hash[0] = clib_bihash_hash_40_48 (&bkey[0]);

      clib_bihash_prefetch_bucket_40_48 (&cnat_session_db, hash[3]);
      clib_bihash_prefetch_bucket_40_48 (&cnat_session_db, hash[2]);
      clib_bihash_prefetch_bucket_40_48 (&cnat_session_db, hash[1]);
      clib_bihash_prefetch_bucket_40_48 (&cnat_session_db, hash[0]);

      clib_bihash_prefetch_data_40_48 (&cnat_session_db, hash[3]);
      clib_bihash_prefetch_data_40_48 (&cnat_session_db, hash[2]);
      clib_bihash_prefetch_data_40_48 (&cnat_session_db, hash[1]);
      clib_bihash_prefetch_data_40_48 (&cnat_session_db, hash[0]);

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      cnat_session_make_key (b[0], af, &bkey[0]);
      rv[0] = clib_bihash_search_inline_2_40_48 (&cnat_session_db,
						 &bkey[0], &bvalue[0]);

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
