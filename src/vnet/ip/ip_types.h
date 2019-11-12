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
} ip_address_family_t;

extern uword unformat_ip_address_family (unformat_input_t * input,
					 va_list * args);
extern u8 *format_ip_address_family (u8 * s, va_list * args);

#define FOR_EACH_IP_ADDRESS_FAMILY(_af) \
  for (_af = AF_IP4; _af <= AF_IP6; _af++)

#define u8_ptr_add(ptr, index) (((u8 *)ptr) + index)
#define u16_net_add(u, val) clib_host_to_net_u16(clib_net_to_host_u16(u) + (val))

/* *INDENT-OFF* */
typedef struct ip_address
{
  union
  {
    ip4_address_t v4;
    ip6_address_t v6;
  } ip;
  ip_address_family_t version;
} __clib_packed ip_address_t;
/* *INDENT-ON* */

#define ip_addr_addr(_a) (_a)->ip
#define ip_addr_v4(_a) (_a)->ip.v4
#define ip_addr_v6(_a) (_a)->ip.v6
#define ip_addr_version(_a) (_a)->version

extern int ip_address_cmp (const ip_address_t * ip1,
			   const ip_address_t * ip2);
extern void ip_address_copy (ip_address_t * dst, const ip_address_t * src);
extern void ip_address_copy_addr (void *dst, const ip_address_t * src);
extern void ip_address_set (ip_address_t * dst, const void *src, u8 version);
extern u16 ip_address_size (const ip_address_t * a);
extern u16 ip_version_to_size (u8 ver);
extern u8 *format_ip_address (u8 * s, va_list * args);
extern uword unformat_ip_address (unformat_input_t * input, va_list * args);
extern void ip_address_to_46 (const ip_address_t * addr,
			      ip46_address_t * a, fib_protocol_t * proto);

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

#endif /* __IP_TYPES_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
