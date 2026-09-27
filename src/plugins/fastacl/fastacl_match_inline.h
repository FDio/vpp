/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#ifndef __included_fastacl_match_inline_h__
#define __included_fastacl_match_inline_h__

#include <vnet/ip/icmp46_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <fastacl/fastacl_types.h>

static_always_inline int
fastacl_match_fields (fastacl_match_t *m, u8 pkt_proto, u16 l4_src_port, u16 l4_dst_port, u8 *l4,
		      u16 l4_bytes, u16 pkt_len, u8 pkt_dscp, u8 pkt_frag_flags)
{
  if ((m->flags & FASTACL_MATCH_PROTO) && pkt_proto != m->proto)
    return 0;
  if (m->flags & FASTACL_MATCH_PORT_BITS)
    {
      if ((pkt_proto != IP_PROTOCOL_TCP && pkt_proto != IP_PROTOCOL_UDP) ||
	  l4_bytes < FASTACL_L4_PORTS_BYTES)
	return 0;
    }
  if ((m->flags & FASTACL_MATCH_DST_PORT) &&
      (l4_dst_port < m->dst_port_min || l4_dst_port > m->dst_port_max))
    return 0;
  if ((m->flags & FASTACL_MATCH_SRC_PORT) &&
      (l4_src_port < m->src_port_min || l4_src_port > m->src_port_max))
    return 0;
  if (m->flags & FASTACL_MATCH_EITHER_PORT)
    {
      int src_in = (l4_src_port >= m->either_port_min && l4_src_port <= m->either_port_max);
      int dst_in = (l4_dst_port >= m->either_port_min && l4_dst_port <= m->either_port_max);
      if (!src_in && !dst_in)
	return 0;
    }
  if (m->flags & FASTACL_MATCH_ICMP_BITS)
    {
      if ((pkt_proto != IP_PROTOCOL_ICMP && pkt_proto != IP_PROTOCOL_ICMP6) || !l4)
	return 0;
      icmp46_header_t *icmp = (icmp46_header_t *) l4;
      if (m->flags & FASTACL_MATCH_ICMP_TYPE)
	{
	  if (l4_bytes < FASTACL_L4_ICMP_TYPE_BYTES || icmp->type != m->icmp_type)
	    return 0;
	}
      if (m->flags & FASTACL_MATCH_ICMP_CODE)
	{
	  if (l4_bytes < FASTACL_L4_ICMP_CODE_BYTES || icmp->code != m->icmp_code)
	    return 0;
	}
    }
  if (m->flags & FASTACL_MATCH_TCP_FLAGS)
    {
      if (pkt_proto != IP_PROTOCOL_TCP)
	return 0;
      if (!l4 || l4_bytes < FASTACL_L4_TCP_FLAGS_BYTES)
	return 0;
      if ((((tcp_header_t *) l4)->flags & m->tcp_flags_mask) != m->tcp_flags_value)
	return 0;
    }
  if ((m->flags & FASTACL_MATCH_PKT_LEN) && (pkt_len < m->pkt_len_min || pkt_len > m->pkt_len_max))
    return 0;
  if ((m->flags & FASTACL_MATCH_DSCP) && pkt_dscp != m->dscp)
    return 0;
  if (m->flags & FASTACL_MATCH_FRAGMENT)
    {
      u8 fmask = m->fragment_mask ? m->fragment_mask : m->fragment_flags;
      if ((pkt_frag_flags & fmask) != m->fragment_flags)
	return 0;
    }
  return 1;
}

#endif
