/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <lisp/lisp-cp/packets.h>
#include <lisp/lisp-cp/lisp_cp_messages.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

/* Returns IP ID for the packet */
/* static u16 ip_id = 0;
static inline u16
get_IP_ID()
{
    ip_id++;
    return (ip_id);
} */

u16
udp_ip4_checksum (const void *b, u32 len, u8 * src, u8 * dst)
{
  const u16 *buf = b;
  u16 *ip_src = (u16 *) src;
  u16 *ip_dst = (u16 *) dst;
  u32 length = len;
  u32 sum = 0;

  while (len > 1)
    {
      sum += *buf++;
      if (sum & 0x80000000)
	sum = (sum & 0xFFFF) + (sum >> 16);
      len -= 2;
    }

  /* Add the padding if the packet length is odd */
  if (len & 1)
    sum += *((u8 *) buf);

  /* Add the pseudo-header */
  sum += *(ip_src++);
  sum += *ip_src;

  sum += *(ip_dst++);
  sum += *ip_dst;

  sum += clib_host_to_net_u16 (IP_PROTOCOL_UDP);
  sum += clib_host_to_net_u16 (length);

  /* Add the carries */
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  /* Return the one's complement of sum */
  return ((u16) (~sum));
}

u16
udp_ip6_checksum (ip6_header_t * ip6, udp_header_t * up, u32 len)
{
  size_t i;
  register const u16 *sp;
  u32 sum;
  union
  {
    struct
    {
      ip6_address_t ph_src;
      ip6_address_t ph_dst;
      u32 ph_len;
      u8 ph_zero[3];
      u8 ph_nxt;
    } ph;
    u16 pa[20];
  } phu;

  /* pseudo-header */
  clib_memset (&phu, 0, sizeof (phu));
  phu.ph.ph_src = ip6->src_address;
  phu.ph.ph_dst = ip6->dst_address;
  phu.ph.ph_len = clib_host_to_net_u32 (len);
  phu.ph.ph_nxt = IP_PROTOCOL_UDP;

  sum = 0;
  for (i = 0; i < sizeof (phu.pa) / sizeof (phu.pa[0]); i++)
    sum += phu.pa[i];

  sp = (const u16 *) up;

  for (i = 0; i < (len & ~1); i += 2)
    sum += *sp++;

  if (len & 1)
    sum += clib_host_to_net_u16 ((*(const u8 *) sp) << 8);

  while (sum > 0xffff)
    sum = (sum & 0xffff) + (sum >> 16);
  sum = ~sum & 0xffff;

  return (sum);
}

u16
udp_checksum (udp_header_t * uh, u32 udp_len, void *ih, u8 version)
{
  switch (version)
    {
    case AF_IP4:
      return (udp_ip4_checksum (uh, udp_len,
				((ip4_header_t *) ih)->src_address.as_u8,
				((ip4_header_t *) ih)->dst_address.as_u8));
    case AF_IP6:
      return (udp_ip6_checksum (ih, uh, udp_len));
    default:
      return ~0;
    }
}

void *
pkt_push_udp (vlib_main_t * vm, vlib_buffer_t * b, u16 sp, u16 dp)
{
  udp_header_t *uh;
  u16 udp_len = sizeof (udp_header_t) + vlib_buffer_length_in_chain (vm, b);

  uh = vlib_buffer_push_uninit (b, sizeof (*uh));

  uh->src_port = clib_host_to_net_u16 (sp);
  uh->dst_port = clib_host_to_net_u16 (dp);
  uh->length = clib_host_to_net_u16 (udp_len);
  uh->checksum = 0;
  return uh;
}

void *
pkt_push_ip (vlib_main_t * vm, vlib_buffer_t * b, ip_address_t * src,
	     ip_address_t * dst, u32 proto, u8 csum_offload)
{
  if (ip_addr_version (src) != ip_addr_version (dst))
    {
      clib_warning ("src %U and dst %U IP have different AFI! Discarding!",
		    format_ip_address, src, format_ip_address, dst);
      return 0;
    }

  switch (ip_addr_version (src))
    {
    case AF_IP4:
      return vlib_buffer_push_ip4 (vm, b, &ip_addr_v4 (src),
				   &ip_addr_v4 (dst), proto, csum_offload);
      break;
    case AF_IP6:
      return vlib_buffer_push_ip6 (vm, b, &ip_addr_v6 (src),
				   &ip_addr_v6 (dst), proto);
      break;
    }

  return 0;
}

void *
pkt_push_udp_and_ip (vlib_main_t * vm, vlib_buffer_t * b, u16 sp, u16 dp,
		     ip_address_t * sip, ip_address_t * dip, u8 csum_offload)
{
  u16 udpsum;
  udp_header_t *uh;
  void *ih;

  uh = pkt_push_udp (vm, b, sp, dp);

  if (csum_offload)
    {
      ih = pkt_push_ip (vm, b, sip, dip, IP_PROTOCOL_UDP, 1);
      vnet_buffer_offload_flags_set (b, VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);
      vnet_buffer (b)->l3_hdr_offset = (u8 *) ih - b->data;
      vnet_buffer (b)->l4_hdr_offset = (u8 *) uh - b->data;
      uh->checksum = 0;
    }
  else
    {
      ih = pkt_push_ip (vm, b, sip, dip, IP_PROTOCOL_UDP, 0);
      udpsum = udp_checksum (uh, clib_net_to_host_u16 (uh->length), ih,
			     ip_addr_version (sip));
      if (udpsum == (u16) ~ 0)
	{
	  clib_warning ("Failed UDP checksum! Discarding");
	  return 0;
	}
      /* clear flags used for csum since we're not offloading */
      b->flags &= ~(VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_IS_IP6);
      uh->checksum = udpsum;
    }
  return ih;
}

void *
pkt_push_ecm_hdr (vlib_buffer_t * b)
{
  ecm_hdr_t *h;
  h = vlib_buffer_push_uninit (b, sizeof (h[0]));

  clib_memset (h, 0, sizeof (h[0]));
  h->type = LISP_ENCAP_CONTROL_TYPE;
  clib_memset (h->reserved2, 0, sizeof (h->reserved2));

  return h;
}

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
