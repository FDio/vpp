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
extern int ip_address_family_decode (vl_api_address_family_t af,
				     ip_address_family_t * out);
extern vl_api_address_family_t ip_address_family_encode (ip_address_family_t
							 af);
extern int ip_proto_decode (vl_api_ip_proto_t ipp, ip_protocol_t * out);
extern vl_api_ip_proto_t ip_proto_encode (ip_protocol_t ipp);
extern ip_dscp_t ip_dscp_decode (vl_api_ip_dscp_t _dscp);
extern vl_api_ip_dscp_t ip_dscp_encode (ip_dscp_t dscp);
extern int ip_feature_location_decode (vl_api_ip_feature_location_t in,
				       ip_feature_location_t * out);
extern vl_api_ip_feature_location_t
ip_feature_location_encode (ip_feature_location_t f);

/**
 * Decode/Encode for struct/union types
 */
extern ip46_type_t ip_address_decode (const vl_api_address_t * in,
				      ip46_address_t * out);
extern void ip_address_decode2 (const vl_api_address_t * in,
				ip_address_t * out);
extern void ip_address_encode (const ip46_address_t * in,
			       ip46_type_t type, vl_api_address_t * out);
extern void ip_address_encode2 (const ip_address_t * in,
				vl_api_address_t * out);

extern void ip6_address_encode (const ip6_address_t * in,
				vl_api_ip6_address_t out);
extern void ip6_address_decode (const vl_api_ip6_address_t in,
				ip6_address_t * out);
extern void ip4_address_encode (const ip4_address_t * in,
				vl_api_ip4_address_t out);
extern void ip4_address_decode (const vl_api_ip4_address_t in,
				ip4_address_t * out);

extern void ip_prefix_decode (const vl_api_prefix_t * in, fib_prefix_t * out);
extern void ip_prefix_encode (const fib_prefix_t * in, vl_api_prefix_t * out);
extern int ip_prefix_decode2 (const vl_api_prefix_t * in, ip_prefix_t * out);
extern void ip_prefix_encode2 (const ip_prefix_t * in, vl_api_prefix_t * out);

extern void ip_mprefix_decode (const vl_api_mprefix_t * in,
			       mfib_prefix_t * out);
extern void ip_mprefix_encode (const mfib_prefix_t * in,
			       vl_api_mprefix_t * out);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
