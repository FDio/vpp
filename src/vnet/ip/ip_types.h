/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef __IP_TYPES_H__
#define __IP_TYPES_H__

#include <vnet/fib/fib_types.h>

typedef enum ip_address_family_t_
{
  AF_IP4,
  AF_IP6,
} __clib_packed ip_address_family_t;

#define N_AF (AF_IP6+1)

extern uword unformat_ip_address_family (unformat_input_t * input,
					 va_list * args);
extern u8 *format_ip_address_family (u8 * s, va_list * args);

#define FOR_EACH_IP_ADDRESS_FAMILY(_af) \
  for (_af = AF_IP4; _af <= AF_IP6; _af++)

extern vnet_link_t ip_address_family_to_link_type (ip_address_family_t af);
extern fib_protocol_t ip_address_family_to_fib_proto (ip_address_family_t af);
extern ip_address_family_t ip_address_family_from_fib_proto (fib_protocol_t
							     fp);

typedef enum ip_sub_address_family_t_
{
  SAFI_UNICAST,
  SAFI_MULTICAST,
} __clib_packed ip_sub_address_family_t;

#define N_SAFI (SAFI_MULTICAST+1)

extern uword unformat_ip_sub_address_family (unformat_input_t * input,
					     va_list * args);
extern u8 *format_ip_sub_address_family (u8 * s, va_list * args);

#define FOR_EACH_IP_ADDRESS_SUB_FAMILY(_safi) \
  for (_safi = SAFI_UNICAST; _safi <= SAFI_MULTICAST; _safi++)

#define u8_ptr_add(ptr, index) (((u8 *)ptr) + index)
#define u16_net_add(u, val) clib_host_to_net_u16(clib_net_to_host_u16(u) + (val))

/**
 * Locations in the IP switch path where features can be applied
 */
#define foreach_ip_feature_location                 \
  _(INPUT, "input")                                 \
  _(OUTPUT, "output")                               \
  _(LOCAL, "local")                                 \
  _(PUNT, "punt")                                   \
  _(DROP, "drop")                                   \

typedef enum ip_feature_location_t_
{
#define _(a,b) IP_FEATURE_##a,
  foreach_ip_feature_location
#undef _
} __clib_packed ip_feature_location_t;

#define N_IP_FEATURE_LOCATIONS (IP_FEATURE_DROP+1)

/* *INDENT-OFF* */
typedef struct ip_address
{
  ip46_address_t ip;
  ip_address_family_t version;
} __clib_packed ip_address_t;
/* *INDENT-ON* */

#define IP_ADDRESS_V4_ALL_0S {.ip.ip4.as_u32 = 0, .version = AF_IP4}
#define IP_ADDRESS_V6_ALL_0S {.ip.ip6.as_u64 = {0, 0}, .version = AF_IP6}
#define ip_address_initializer IP_ADDRESS_V6_ALL_0S

#define ip_addr_46(_a) (_a)->ip
#define ip_addr_v4(_a) (_a)->ip.ip4
#define ip_addr_v6(_a) (_a)->ip.ip6
#define ip_addr_version(_a) (_a)->version

extern u8 *ip_addr_bytes (ip_address_t * ip);

extern bool ip_address_is_zero (const ip_address_t * ip);
extern int ip_address_cmp (const ip_address_t * ip1,
			   const ip_address_t * ip2);
extern void ip_address_copy (ip_address_t * dst, const ip_address_t * src);
extern void ip_address_copy_addr (void *dst, const ip_address_t * src);
extern void ip_address_set (ip_address_t * dst, const void *src,
			    ip_address_family_t version);
extern u16 ip_address_size (const ip_address_t * a);
extern u16 ip_version_to_size (ip_address_family_t af);
extern u8 *format_ip_address (u8 * s, va_list * args);
extern uword unformat_ip_address (unformat_input_t * input, va_list * args);
extern fib_protocol_t ip_address_to_46 (const ip_address_t * addr,
					ip46_address_t * a);
extern void ip_address_from_46 (const ip46_address_t * a,
				fib_protocol_t fproto, ip_address_t * addr);
extern void ip_address_increment (ip_address_t * ip);
extern void ip_address_reset (ip_address_t * ip);

/* *INDENT-OFF* */
typedef struct ip_prefix
{
  ip_address_t addr;
  u8 len;
} __clib_packed ip_prefix_t;
/* *INDENT-ON* */

#define ip_prefix_addr(_a) (_a)->addr
#define ip_prefix_version(_a) ip_addr_version(&ip_prefix_addr(_a))
#define ip_prefix_len(_a) (_a)->len
#define ip_prefix_v4(_a) ip_addr_v4(&ip_prefix_addr(_a))
#define ip_prefix_v6(_a) ip_addr_v6(&ip_prefix_addr(_a))

extern int ip_prefix_cmp (ip_prefix_t * p1, ip_prefix_t * p2);
extern void ip_prefix_normalize (ip_prefix_t * a);

extern void ip_address_to_fib_prefix (const ip_address_t * addr,
				      fib_prefix_t * prefix);
extern void ip_prefix_to_fib_prefix (const ip_prefix_t * ipp,
				     fib_prefix_t * fibp);
extern u8 *format_ip_prefix (u8 * s, va_list * args);
extern uword unformat_ip_prefix (unformat_input_t * input, va_list * args);

extern bool ip_prefix_validate (const ip_prefix_t * ip);
extern void ip4_address_normalize (ip4_address_t * ip4, u8 preflen);
extern void ip6_address_normalize (ip6_address_t * ip6, u8 preflen);
extern void ip4_preflen_to_mask (u8 pref_len, ip4_address_t * ip);
extern u32 ip4_mask_to_preflen (ip4_address_t * mask);
extern void ip4_prefix_max_address_host_order (ip4_address_t * ip, u8 plen,
					       ip4_address_t * res);
extern void ip6_prefix_max_address_host_order (ip6_address_t * ip, u8 plen,
					       ip6_address_t * res);
extern void ip6_preflen_to_mask (u8 pref_len, ip6_address_t * mask);
extern u32 ip6_mask_to_preflen (ip6_address_t * mask);

#endif /* __IP_TYPES_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
