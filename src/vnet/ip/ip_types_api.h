/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __IP_TYPES_API_H__
#define __IP_TYPES_API_H__

/**
 * Conversion functions to/from (decode/encode) API types to VPP internal types
 */

#include <vnet/ip/ip.h>
#include <vnet/fib/fib_types.h>
#include <vnet/mfib/mfib_types.h>
#include <vlibapi/api_types.h>
#include <vnet/ip/ip.api_types.h>

/**
 * These enum decode/encodes use 'int' as the type for the enum because
 * one cannot forward declare an enum
 */
extern int ip_address_family_decode (int _af, ip_address_family_t * out);
extern int ip_address_family_encode (ip_address_family_t af);
extern int ip_proto_decode (int _af, ip_protocol_t * out);
extern int ip_proto_encode (ip_protocol_t af);
extern ip_dscp_t ip_dscp_decode (u8 _dscp);
extern u8 ip_dscp_encode (ip_dscp_t dscp);

/**
 * Decode/Encode for struct/union types
 */
extern ip46_type_t ip_address_decode (const struct _vl_api_address *in,
				      ip46_address_t * out);
extern void ip_address_encode (const ip46_address_t * in,
			       ip46_type_t type, struct _vl_api_address *out);
extern void ip6_address_encode (const ip6_address_t * in,
				vl_api_ip6_address_t out);
extern void ip6_address_decode (const vl_api_ip6_address_t in,
				ip6_address_t * out);
extern void ip4_address_encode (const ip4_address_t * in,
				vl_api_ip4_address_t out);
extern void ip4_address_decode (const vl_api_ip4_address_t in,
				ip4_address_t * out);

extern void ip_prefix_decode (const struct _vl_api_prefix *in,
			      fib_prefix_t * out);
extern void ip_prefix_encode (const fib_prefix_t * in,
			      struct _vl_api_prefix *out);

extern void ip_mprefix_decode (const struct _vl_api_mprefix *in,
			       mfib_prefix_t * out);
extern void ip_mprefix_encode (const mfib_prefix_t * in,
			       struct _vl_api_mprefix *out);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
