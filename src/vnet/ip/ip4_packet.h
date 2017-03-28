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
ip4_addr_fib_init (ip4_address_fib_t * addr_fib, ip4_address_t * address,
		   u32 fib_index)
{
  clib_memcpy (&addr_fib->ip4_addr, address, sizeof (addr_fib->ip4_addr));
  addr_fib->fib_index = fib_index;
}

/* (src,dst) pair of addresses as found in packet header. */
typedef struct
{
  ip4_address_t src, dst;
} ip4_address_pair_t;

/* If address is a valid netmask, return length of mask. */
always_inline uword
ip4_address_netmask_length (ip4_address_t * a)
{
  uword result = 0;
  uword i;
  for (i = 0; i < ARRAY_LEN (a->as_u8); i++)
    {
      switch (a->as_u8[i])
	{
	case 0xff:
	  result += 8;
	  break;
	case 0xfe:
	  result += 7;
	  goto done;
	case 0xfc:
	  result += 6;
	  goto done;
	case 0xf8:
	  result += 5;
	  goto done;
	case 0xf0:
	  result += 4;
	  goto done;
	case 0xe0:
	  result += 3;
	  goto done;
	case 0xc0:
	  result += 2;
	  goto done;
	case 0x80:
	  result += 1;
	  goto done;
	case 0x00:
	  result += 0;
	  goto done;
	default:
	  /* Not a valid netmask mask. */
	  return ~0;
	}
    }
done:
  return result;
}

typedef union
{
  struct
  {
    /* 4 bit packet length (in 32bit units) and version VVVVLLLL.
       e.g. for packets w/ no options ip_version_and_header_length == 0x45. */
    u8 ip_version_and_header_length;

    /* Type of service. */
    u8 tos;

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

always_inline int
ip4_get_fragment_offset (ip4_header_t * i)
{
  return clib_net_to_host_u16 (i->flags_and_fragment_offset) & 0x1fff;
}

always_inline int
ip4_get_fragment_more (ip4_header_t * i)
{
  return clib_net_to_host_u16 (i->flags_and_fragment_offset) &
    IP4_HEADER_FLAG_MORE_FRAGMENTS;
}

always_inline int
ip4_is_fragment (ip4_header_t * i)
{
  return (i->flags_and_fragment_offset &
	  clib_net_to_host_u16 (0x1fff | IP4_HEADER_FLAG_MORE_FRAGMENTS));
}

always_inline int
ip4_is_first_fragment (ip4_header_t * i)
{
  return (i->flags_and_fragment_offset &
	  clib_net_to_host_u16 (0x1fff | IP4_HEADER_FLAG_MORE_FRAGMENTS)) ==
    clib_net_to_host_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);
}

/* Fragment offset in bytes. */
always_inline int
ip4_get_fragment_offset_bytes (ip4_header_t * i)
{
  return 8 * ip4_get_fragment_offset (i);
}

always_inline int
ip4_header_bytes (ip4_header_t * i)
{
  return sizeof (u32) * (i->ip_version_and_header_length & 0xf);
}

always_inline void *
ip4_next_header (ip4_header_t * i)
{
  return (void *) i + ip4_header_bytes (i);
}

always_inline u16
ip4_header_checksum (ip4_header_t * i)
{
  u16 save, csum;
  ip_csum_t sum;

  save = i->checksum;
  i->checksum = 0;
  sum = ip_incremental_checksum (0, i, ip4_header_bytes (i));
  csum = ~ip_csum_fold (sum);

  i->checksum = save;

  /* Make checksum agree for special case where either
     0 or 0xffff would give same 1s complement sum. */
  if (csum == 0 && save == 0xffff)
    csum = save;

  return csum;
}

static inline uword
ip4_header_checksum_is_valid (ip4_header_t * i)
{
  return i->checksum == ip4_header_checksum (i);
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
ip4_address_is_multicast (ip4_address_t * a)
{
  return (a->data[0] & 0xf0) == 0xe0;
}

always_inline void
ip4_multicast_address_set_for_group (ip4_address_t * a,
				     ip_multicast_group_t g)
{
  ASSERT ((u32) g < (1 << 28));
  a->as_u32 = clib_host_to_net_u32 ((0xe << 28) + g);
}

always_inline void
ip4_multicast_ethernet_address (u8 * ethernet_address, ip4_address_t * a)
{
  u8 *d = a->as_u8;

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
