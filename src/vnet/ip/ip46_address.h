/*
 * Copyright (c) 2015-2019 Cisco and/or its affiliates.
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

#ifndef included_ip46_address_h
#define included_ip46_address_h

#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip4_packet.h>

typedef enum
{
  IP46_TYPE_ANY,
  IP46_TYPE_BOTH = IP46_TYPE_ANY,
  IP46_TYPE_IP4,
  IP46_TYPE_IP6
} ip46_type_t;

#define IP46_N_TYPES (IP46_TYPE_IP6+2)

#define FOREACH_IP46_TYPE(_type) \
  for (_type = IP46_TYPE_IP4; _type <= IP46_TYPE_IP6; _type++)

extern u8 *format_ip46_type (u8 * s, va_list * args);

/* *INDENT-OFF* */
typedef CLIB_PACKED (union ip46_address_t_ {
  struct {
    u32 pad[3];
    ip4_address_t ip4;
  };
  ip6_address_t ip6;
  u8 as_u8[16];
  u64 as_u64[2];
}) ip46_address_t;
/* *INDENT-ON* */


format_function_t format_ip46_address;

#define ip46_address_initializer {{{ 0 }}}

always_inline u8
ip46_address_is_ip4 (const ip46_address_t * ip46)
{
  return (((ip46)->pad[0] | (ip46)->pad[1] | (ip46)->pad[2]) == 0);
}

always_inline void
ip46_address_mask_ip4 (ip46_address_t * ip46)
{
  ((ip46)->pad[0] = (ip46)->pad[1] = (ip46)->pad[2] = 0);
}

always_inline void
ip46_address_set_ip4 (ip46_address_t * ip46, const ip4_address_t * ip)
{
  ip46_address_mask_ip4 (ip46);
  ip46->ip4 = *ip;
}

always_inline void
ip46_address_reset (ip46_address_t * ip46)
{
  ip46->as_u64[0] = ip46->as_u64[1] = 0;
}

always_inline int
ip46_address_cmp (const ip46_address_t * ip46_1,
		  const ip46_address_t * ip46_2)
{
  return (memcmp (ip46_1, ip46_2, sizeof (*ip46_1)));
}

always_inline u8
ip46_address_is_zero (const ip46_address_t * ip46)
{
  return (ip46->as_u64[0] == 0 && ip46->as_u64[1] == 0);
}

always_inline u8
ip46_address_is_equal (const ip46_address_t * ip46_1,
		       const ip46_address_t * ip46_2)
{
  return ((ip46_1->as_u64[0] == ip46_2->as_u64[0]) &&
	  (ip46_1->as_u64[1] == ip46_2->as_u64[1]));
}

static_always_inline int
ip4_address_is_equal (const ip4_address_t * ip4_1,
		      const ip4_address_t * ip4_2)
{
  return (ip4_1->as_u32 == ip4_2->as_u32);
}

static_always_inline int
ip46_address_is_equal_v4 (const ip46_address_t * ip46,
			  const ip4_address_t * ip4)
{
  return (ip46->ip4.as_u32 == ip4->as_u32);
}

static_always_inline int
ip46_address_is_equal_v6 (const ip46_address_t * ip46,
			  const ip6_address_t * ip6)
{
  return ((ip46->ip6.as_u64[0] == ip6->as_u64[0]) &&
	  (ip46->ip6.as_u64[1] == ip6->as_u64[1]));
}

static_always_inline void
ip46_address_copy (ip46_address_t * dst, const ip46_address_t * src)
{
  dst->as_u64[0] = src->as_u64[0];
  dst->as_u64[1] = src->as_u64[1];
}

static_always_inline void
ip46_address_set_ip6 (ip46_address_t * dst, const ip6_address_t * src)
{
  dst->as_u64[0] = src->as_u64[0];
  dst->as_u64[1] = src->as_u64[1];
}

always_inline ip46_address_t
to_ip46 (u32 is_ipv6, u8 * buf)
{
  ip46_address_t ip;
  if (is_ipv6)
    ip.ip6 = *((ip6_address_t *) buf);
  else
    ip46_address_set_ip4 (&ip, (ip4_address_t *) buf);
  return ip;
}

always_inline ip46_type_t
ip46_address_get_type (const ip46_address_t * ip)
{
  return (ip46_address_is_ip4 (ip) ? IP46_TYPE_IP4 : IP46_TYPE_IP6);
}

always_inline uword
ip46_address_is_multicast (const ip46_address_t * a)
{
  return ip46_address_is_ip4 (a) ? ip4_address_is_multicast (&a->ip4) :
    ip6_address_is_multicast (&a->ip6);
}

extern void ip4_address_increment (ip4_address_t * i);
extern void ip6_address_increment (ip6_address_t * i);
extern void ip46_address_increment (ip46_type_t type, ip46_address_t * ip);

#endif /* included_ip46_address_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
