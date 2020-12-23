/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * ip4/packet.h: ip4 packet format
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_ip4_packet_h
#define included_ip4_packet_h

#include <vnet/ip/ip_packet.h>	/* for ip_csum_t */
#include <vnet/tcp/tcp_packet.h>	/* for tcp_header_t */
#include <vppinfra/byte_order.h>	/* for clib_net_to_host_u16 */
#include <vppinfra/warnings.h>	/* for WARN_OFF/WARN_ON macro */

/* IP4 address which can be accessed either as 4 bytes
   or as a 32-bit number. */
typedef union
{
  u8 data[4];
  u32 data_u32;
  /* Aliases. */
  u8 as_u8[4];
  u16 as_u16[2];
  u32 as_u32;
} ip4_address_t;

typedef struct
{
  /* IP address must be first for ip_interface_address_get_address() to work */
  ip4_address_t ip4_addr;
  u32 fib_index;
} ip4_address_fib_t;

always_inline void
ip4_addr_fib_init (ip4_address_fib_t * addr_fib,
		   const ip4_address_t * address, u32 fib_index)
{
  clib_memcpy_fast (&addr_fib->ip4_addr, address,
		    sizeof (addr_fib->ip4_addr));
  addr_fib->fib_index = fib_index;
}

/* (src,dst) pair of addresses as found in packet header. */
typedef struct
{
  ip4_address_t src, dst;
} ip4_address_pair_t;

typedef struct
{
  ip4_address_t addr, mask;
} ip4_address_and_mask_t;

typedef union
{
  struct
  {
    /* 4 bit packet length (in 32bit units) and version VVVVLLLL.
       e.g. for packets w/ no options ip_version_and_header_length == 0x45. */
    u8 ip_version_and_header_length;

    /* Type of service. */
    ip_dscp_t tos;

    /* Total layer 3 packet length including this header. */
    u16 length;

    /* Fragmentation ID. */
    u16 fragment_id;

    /* 3 bits of flags and 13 bits of fragment offset (in units
       of 8 byte quantities). */
    u16 flags_and_fragment_offset;
#define IP4_HEADER_FLAG_MORE_FRAGMENTS (1 << 13)
#define IP4_HEADER_FLAG_DONT_FRAGMENT (1 << 14)
#define IP4_HEADER_FLAG_CONGESTION (1 << 15)

    /* Time to live decremented by router at each hop. */
    u8 ttl;

    /* Next level protocol packet. */
    u8 protocol;

    /* Checksum. */
    u16 checksum;

    /* Source and destination address. */
    union
    {
      struct
      {
	ip4_address_t src_address, dst_address;
      };
      ip4_address_pair_t address_pair;
    };
  };

  /* For checksumming we'll want to access IP header in word sized chunks. */
  /* For 64 bit machines. */
  /* *INDENT-OFF* */
  CLIB_PACKED (struct {
    u64 checksum_data_64[2];
    u32 checksum_data_64_32[1];
  });
  /* *INDENT-ON* */

  /* For 32 bit machines. */
  /* *INDENT-OFF* */
  CLIB_PACKED (struct {
    u32 checksum_data_32[5];
  });
  /* *INDENT-ON* */
} ip4_header_t;

/* Value of ip_version_and_header_length for packets w/o options. */
#define IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS \
  ((4 << 4) | (sizeof (ip4_header_t) / sizeof (u32)))

#define IP4_ROUTER_ALERT_OPTION 20

always_inline u16
ip4_get_fragment_offset (const ip4_header_t * i)
{
  return clib_net_to_host_u16 (i->flags_and_fragment_offset) & 0x1fff;
}

always_inline u16
ip4_get_fragment_more (const ip4_header_t * i)
{
  return clib_net_to_host_u16 (i->flags_and_fragment_offset) &
    IP4_HEADER_FLAG_MORE_FRAGMENTS;
}

always_inline int
ip4_is_fragment (const ip4_header_t * i)
{
  return (i->flags_and_fragment_offset &
	  clib_net_to_host_u16 (0x1fff | IP4_HEADER_FLAG_MORE_FRAGMENTS));
}

always_inline int
ip4_is_first_fragment (const ip4_header_t * i)
{
  return (i->flags_and_fragment_offset &
	  clib_net_to_host_u16 (0x1fff | IP4_HEADER_FLAG_MORE_FRAGMENTS)) ==
    clib_net_to_host_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);
}

/* Fragment offset in bytes. */
always_inline int
ip4_get_fragment_offset_bytes (const ip4_header_t * i)
{
  return 8 * ip4_get_fragment_offset (i);
}

always_inline int
ip4_header_bytes (const ip4_header_t * i)
{
  return sizeof (u32) * (i->ip_version_and_header_length & 0xf);
}

always_inline void *
ip4_next_header (ip4_header_t * i)
{
  return (void *) i + ip4_header_bytes (i);
}

/* Turn off array bounds check due to ip4_header_t
   option field operations. */

/* *INDENT-OFF* */
WARN_OFF(array-bounds)
/* *INDENT-ON* */

static_always_inline u16
ip4_header_checksum_inline (ip4_header_t * i, int with_checksum)
{
  int option_len = (i->ip_version_and_header_length & 0xf) - 5;
  uword sum = 0;
#if uword_bits == 64
  u32 *iphdr = (u32 *) i;

  sum += iphdr[0];
  sum += iphdr[1];
  sum += with_checksum ? iphdr[2] : *(u16 *) (iphdr + 2);
  /* skip checksum */
  sum += iphdr[3];
  sum += iphdr[4];

  if (PREDICT_FALSE (option_len > 0))
    switch (option_len)
      {
      case 10:
	sum += iphdr[14];
      case 9:
	sum += iphdr[13];
      case 8:
	sum += iphdr[12];
      case 7:
	sum += iphdr[11];
      case 6:
	sum += iphdr[10];
      case 5:
	sum += iphdr[9];
      case 4:
	sum += iphdr[8];
      case 3:
	sum += iphdr[7];
      case 2:
	sum += iphdr[6];
      case 1:
	sum += iphdr[5];
      default:
	break;
      }

  sum = ((u32) sum) + (sum >> 32);
#else
  u16 *iphdr = (u16 *) i;

  sum += iphdr[0];
  sum += iphdr[1];
  sum += iphdr[2];
  sum += iphdr[3];
  sum += iphdr[4];
  if (with_checksum)
    sum += iphdr[5];
  sum += iphdr[6];
  sum += iphdr[7];
  sum += iphdr[8];
  sum += iphdr[9];

  if (PREDICT_FALSE (option_len > 0))
    switch (option_len)
      {
      case 10:
	sum += iphdr[28];
	sum += iphdr[29];
      case 9:
	sum += iphdr[26];
	sum += iphdr[27];
      case 8:
	sum += iphdr[24];
	sum += iphdr[25];
      case 7:
	sum += iphdr[22];
	sum += iphdr[23];
      case 6:
	sum += iphdr[20];
	sum += iphdr[21];
      case 5:
	sum += iphdr[18];
	sum += iphdr[19];
      case 4:
	sum += iphdr[16];
	sum += iphdr[17];
      case 3:
	sum += iphdr[14];
	sum += iphdr[15];
      case 2:
	sum += iphdr[12];
	sum += iphdr[13];
      case 1:
	sum += iphdr[10];
	sum += iphdr[11];
      default:
	break;
      }
#endif

  sum = ((u16) sum) + (sum >> 16);
  sum = ((u16) sum) + (sum >> 16);
  return ~((u16) sum);
}

/* *INDENT-OFF* */
WARN_ON(array-bounds)
/* *INDENT-ON* */

always_inline u16
ip4_header_checksum (ip4_header_t * i)
{
  return ip4_header_checksum_inline (i, /* with_checksum */ 0);
}

always_inline void
ip4_header_set_dscp (ip4_header_t * ip4, ip_dscp_t dscp)
{
  ip4->tos &= ~0xfc;
  /* not masking the dscp value to save th instruction
   * it shouldn't b necessary since the argument is an enum
   * whose range is therefore constrained in the CP. in the
   * DP it will have been taken from another packet, so again
   * constrained in  value */
  ip4->tos |= dscp << IP_PACKET_TC_FIELD_DSCP_BIT_SHIFT;
}

always_inline void
ip4_header_set_ecn (ip4_header_t * ip4, ip_ecn_t ecn)
{
  ip4->tos &= ~IP_PACKET_TC_FIELD_ECN_MASK;
  ip4->tos |= ecn;
}

always_inline void
ip4_header_set_ecn_w_chksum (ip4_header_t * ip4, ip_ecn_t ecn)
{
  ip_csum_t sum = ip4->checksum;
  u8 old = ip4->tos;
  u8 new = (old & ~IP_PACKET_TC_FIELD_ECN_MASK) | ecn;

  sum = ip_csum_update (sum, old, new, ip4_header_t, tos);
  ip4->checksum = ip_csum_fold (sum);
  ip4->tos = new;
}

always_inline ip_dscp_t
ip4_header_get_dscp (const ip4_header_t * ip4)
{
  return (ip4->tos >> IP_PACKET_TC_FIELD_DSCP_BIT_SHIFT);
}

always_inline ip_ecn_t
ip4_header_get_ecn (const ip4_header_t * ip4)
{
  return (ip4->tos & IP_PACKET_TC_FIELD_ECN_MASK);
}

always_inline u8
ip4_header_get_ttl (const ip4_header_t *ip4)
{
  return (ip4->ttl);
}

always_inline void
ip4_header_set_ttl (ip4_header_t *ip4, u8 ttl)
{
  ip4->ttl = ttl;
}

always_inline void
ip4_header_set_df (ip4_header_t * ip4)
{
  ip4->flags_and_fragment_offset |=
    clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);
}

always_inline void
ip4_header_clear_df (ip4_header_t * ip4)
{
  ip4->flags_and_fragment_offset &=
    ~clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);
}

always_inline u8
ip4_header_get_df (const ip4_header_t * ip4)
{
  return (! !(ip4->flags_and_fragment_offset &
	      clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT)));
}

static inline uword
ip4_header_checksum_is_valid (ip4_header_t * i)
{
  return ip4_header_checksum_inline (i, /* with_checksum */ 1) == 0;
}

#define ip4_partial_header_checksum_x1(ip0,sum0)			\
do {									\
  if (BITS (ip_csum_t) > 32)						\
    {									\
      sum0 = ip0->checksum_data_64[0];					\
      sum0 = ip_csum_with_carry (sum0, ip0->checksum_data_64[1]);	\
      sum0 = ip_csum_with_carry (sum0, ip0->checksum_data_64_32[0]);	\
    }									\
  else									\
    {									\
      sum0 = ip0->checksum_data_32[0];					\
      sum0 = ip_csum_with_carry (sum0, ip0->checksum_data_32[1]);	\
      sum0 = ip_csum_with_carry (sum0, ip0->checksum_data_32[2]);	\
      sum0 = ip_csum_with_carry (sum0, ip0->checksum_data_32[3]);	\
      sum0 = ip_csum_with_carry (sum0, ip0->checksum_data_32[4]);	\
    }									\
} while (0)

#define ip4_partial_header_checksum_x2(ip0,ip1,sum0,sum1)		\
do {									\
  if (BITS (ip_csum_t) > 32)						\
    {									\
      sum0 = ip0->checksum_data_64[0];					\
      sum1 = ip1->checksum_data_64[0];					\
      sum0 = ip_csum_with_carry (sum0, ip0->checksum_data_64[1]);	\
      sum1 = ip_csum_with_carry (sum1, ip1->checksum_data_64[1]);	\
      sum0 = ip_csum_with_carry (sum0, ip0->checksum_data_64_32[0]);	\
      sum1 = ip_csum_with_carry (sum1, ip1->checksum_data_64_32[0]);	\
    }									\
  else									\
    {									\
      sum0 = ip0->checksum_data_32[0];					\
      sum1 = ip1->checksum_data_32[0];					\
      sum0 = ip_csum_with_carry (sum0, ip0->checksum_data_32[1]);	\
      sum1 = ip_csum_with_carry (sum1, ip1->checksum_data_32[1]);	\
      sum0 = ip_csum_with_carry (sum0, ip0->checksum_data_32[2]);	\
      sum1 = ip_csum_with_carry (sum1, ip1->checksum_data_32[2]);	\
      sum0 = ip_csum_with_carry (sum0, ip0->checksum_data_32[3]);	\
      sum1 = ip_csum_with_carry (sum1, ip1->checksum_data_32[3]);	\
      sum0 = ip_csum_with_carry (sum0, ip0->checksum_data_32[4]);	\
      sum1 = ip_csum_with_carry (sum1, ip1->checksum_data_32[4]);	\
    }									\
} while (0)

always_inline uword
ip4_address_is_multicast (const ip4_address_t * a)
{
  return (a->data[0] & 0xf0) == 0xe0;
}

always_inline uword
ip4_address_is_global_broadcast (const ip4_address_t * a)
{
  return (a->as_u32) == 0xffffffff;
}

always_inline void
ip4_multicast_address_set_for_group (ip4_address_t * a,
				     ip_multicast_group_t g)
{
  ASSERT ((u32) g < (1 << 28));
  a->as_u32 = clib_host_to_net_u32 ((0xe << 28) + g);
}

always_inline void
ip4_multicast_ethernet_address (u8 * ethernet_address,
				const ip4_address_t * a)
{
  const u8 *d = a->as_u8;

  ethernet_address[0] = 0x01;
  ethernet_address[1] = 0x00;
  ethernet_address[2] = 0x5e;
  ethernet_address[3] = d[1] & 0x7f;
  ethernet_address[4] = d[2];
  ethernet_address[5] = d[3];
}

always_inline void
ip4_tcp_reply_x1 (ip4_header_t * ip0, tcp_header_t * tcp0)
{
  u32 src0, dst0;

  src0 = ip0->src_address.data_u32;
  dst0 = ip0->dst_address.data_u32;
  ip0->src_address.data_u32 = dst0;
  ip0->dst_address.data_u32 = src0;

  src0 = tcp0->src;
  dst0 = tcp0->dst;
  tcp0->src = dst0;
  tcp0->dst = src0;
}

always_inline void
ip4_tcp_reply_x2 (ip4_header_t * ip0, ip4_header_t * ip1,
		  tcp_header_t * tcp0, tcp_header_t * tcp1)
{
  u32 src0, dst0, src1, dst1;

  src0 = ip0->src_address.data_u32;
  src1 = ip1->src_address.data_u32;
  dst0 = ip0->dst_address.data_u32;
  dst1 = ip1->dst_address.data_u32;
  ip0->src_address.data_u32 = dst0;
  ip1->src_address.data_u32 = dst1;
  ip0->dst_address.data_u32 = src0;
  ip1->dst_address.data_u32 = src1;

  src0 = tcp0->src;
  src1 = tcp1->src;
  dst0 = tcp0->dst;
  dst1 = tcp1->dst;
  tcp0->src = dst0;
  tcp1->src = dst1;
  tcp0->dst = src0;
  tcp1->dst = src1;
}

#endif /* included_ip4_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
