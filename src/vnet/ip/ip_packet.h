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
 * ip/ip_packet.h: packet format common between ip4 & ip6
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

#ifndef included_ip_packet_h
#define included_ip_packet_h

#include <vppinfra/byte_order.h>
#include <vppinfra/error.h>

typedef enum ip_protocol
{
#define ip_protocol(n,s) IP_PROTOCOL_##s = n,
#include "protocols.def"
#undef ip_protocol
} ip_protocol_t;

/* TCP/UDP ports. */
typedef enum
{
#define ip_port(s,n) IP_PORT_##s = n,
#include "ports.def"
#undef ip_port
} ip_port_t;

/* Classifies protocols into UDP, ICMP or other. */
typedef enum
{
  IP_BUILTIN_PROTOCOL_UDP,
  IP_BUILTIN_PROTOCOL_ICMP,
  IP_BUILTIN_PROTOCOL_UNKNOWN,
} ip_builtin_protocol_t;

#define foreach_ip_builtin_multicast_group	\
  _ (1, all_hosts_on_subnet)			\
  _ (2, all_routers_on_subnet)			\
  _ (4, dvmrp)					\
  _ (5, ospf_all_routers)			\
  _ (6, ospf_designated_routers)		\
  _ (13, pim)					\
  _ (18, vrrp)					\
  _ (102, hsrp)					\
  _ (22, igmp_v3)

typedef enum
{
#define _(n,f) IP_MULTICAST_GROUP_##f = n,
  foreach_ip_builtin_multicast_group
#undef _
} ip_multicast_group_t;

/* IP checksum support. */

static_always_inline u16
ip_csum (void *data, u16 n_left)
{
  u32 sum;
#ifdef CLIB_HAVE_VEC256
  u16x16 v1, v2;
  u32x8 zero = { 0 };
  u32x8 sum8 = { 0 };
  u32x4 sum4;
#endif

  /* if there is odd number of bytes, pad by zero and store in sum */
  sum = (n_left & 1) ? ((u8 *) data)[n_left - 1] << 8 : 0;

  /* we deal with words */
  n_left >>= 1;

#ifdef CLIB_HAVE_VEC256
  while (n_left >= 32)
    {
      v1 = u16x16_load_unaligned (data);
      v2 = u16x16_load_unaligned (data + 32);

#ifdef CLIB_ARCH_IS_LITTLE_ENDIAN
      v1 = u16x16_byte_swap (v1);
      v2 = u16x16_byte_swap (v2);
#endif
      sum8 += u16x8_extend_to_u32x8 (u16x16_extract_lo (v1));
      sum8 += u16x8_extend_to_u32x8 (u16x16_extract_hi (v1));
      sum8 += u16x8_extend_to_u32x8 (u16x16_extract_lo (v2));
      sum8 += u16x8_extend_to_u32x8 (u16x16_extract_hi (v2));
      n_left -= 32;
      data += 64;
    }

  if (n_left >= 16)
    {
      v1 = u16x16_load_unaligned (data);
#ifdef CLIB_ARCH_IS_LITTLE_ENDIAN
      v1 = u16x16_byte_swap (v1);
#endif
      v1 = u16x16_byte_swap (u16x16_load_unaligned (data));
      sum8 += u16x8_extend_to_u32x8 (u16x16_extract_lo (v1));
      sum8 += u16x8_extend_to_u32x8 (u16x16_extract_hi (v1));
      n_left -= 16;
      data += 32;
    }

  if (n_left)
    {
      v1 = u16x16_load_unaligned (data);
#ifdef CLIB_ARCH_IS_LITTLE_ENDIAN
      v1 = u16x16_byte_swap (v1);
#endif
      v1 = u16x16_mask_last (v1, 16 - n_left);
      sum8 += u16x8_extend_to_u32x8 (u16x16_extract_lo (v1));
      sum8 += u16x8_extend_to_u32x8 (u16x16_extract_hi (v1));
    }

  sum8 = u32x8_hadd (sum8, zero);
  sum4 = u32x8_extract_lo (sum8) + u32x8_extract_hi (sum8);
  sum = sum4[0] + sum4[1];

#else
  /* scalar version */
  while (n_left >= 8)
    {
      sum += clib_net_to_host_u16 (*((u16 *) data + 0));
      sum += clib_net_to_host_u16 (*((u16 *) data + 1));
      sum += clib_net_to_host_u16 (*((u16 *) data + 2));
      sum += clib_net_to_host_u16 (*((u16 *) data + 3));
      sum += clib_net_to_host_u16 (*((u16 *) data + 4));
      sum += clib_net_to_host_u16 (*((u16 *) data + 5));
      sum += clib_net_to_host_u16 (*((u16 *) data + 6));
      sum += clib_net_to_host_u16 (*((u16 *) data + 7));
      n_left -= 8;
      data += 16;
    }
  while (n_left)
    {
      sum += clib_net_to_host_u16 (*(u16 *) data);
      n_left -= 1;
      data += 2;
    }
#endif

  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  return ~((u16) sum);
}

/* Incremental checksum update. */
typedef uword ip_csum_t;

always_inline ip_csum_t
ip_csum_with_carry (ip_csum_t sum, ip_csum_t x)
{
  ip_csum_t t = sum + x;
  return t + (t < x);
}

/* Update checksum changing field at even byte offset from x -> 0. */
always_inline ip_csum_t
ip_csum_add_even (ip_csum_t c, ip_csum_t x)
{
  ip_csum_t d;

  d = c - x;

  /* Fold in carry from high bit. */
  d -= d > c;

  ip_csum_t t = ip_csum_with_carry (d, x);
  ASSERT ((t - c == 0) || (t - c == ~0));

  return d;
}

/* Update checksum changing field at even byte offset from 0 -> x. */
always_inline ip_csum_t
ip_csum_sub_even (ip_csum_t c, ip_csum_t x)
{
  return ip_csum_with_carry (c, x);
}

always_inline ip_csum_t
ip_csum_update_inline (ip_csum_t sum, ip_csum_t old, ip_csum_t new,
		       u32 field_byte_offset, u32 field_n_bytes)
{
  /* For even 1-byte fields on big-endian and odd 1-byte fields on little endian
     we need to shift byte into place for checksum. */
  if ((field_n_bytes % 2)
      && (field_byte_offset % 2) == CLIB_ARCH_IS_LITTLE_ENDIAN)
    {
      old = old << 8;
      new = new << 8;
    }
  sum = ip_csum_sub_even (sum, old);
  sum = ip_csum_add_even (sum, new);
  return sum;
}

#define ip_csum_update(sum,old,new,type,field)			\
  ip_csum_update_inline ((sum), (old), (new),			\
			 STRUCT_OFFSET_OF (type, field),	\
			 STRUCT_SIZE_OF (type, field))

always_inline u16
ip_csum_fold (ip_csum_t c)
{
  /* Reduce to 16 bits. */
#if uword_bits == 64
  c = (c & (ip_csum_t) 0xffffffff) + (c >> (ip_csum_t) 32);
  c = (c & 0xffff) + (c >> 16);
#endif

  c = (c & 0xffff) + (c >> 16);
  c = (c & 0xffff) + (c >> 16);

  return c;
}

extern ip_csum_t (*vnet_incremental_checksum_fp) (ip_csum_t, void *, uword);

always_inline ip_csum_t
ip_incremental_checksum (ip_csum_t sum, void *_data, uword n_bytes)
{
  return (*vnet_incremental_checksum_fp) (sum, _data, n_bytes);
}

always_inline u16
ip_csum_and_memcpy_fold (ip_csum_t sum, void *dst)
{
  return ip_csum_fold (sum);
}

/* Checksum routine. */
ip_csum_t ip_incremental_checksum (ip_csum_t sum, void *data, uword n_bytes);

#endif /* included_ip_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
