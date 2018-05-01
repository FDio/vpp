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

#ifndef __IP_TYPES_H__
#define __IP_TYPES_H__

#include <vnet/ip/ip6_packet.h>

union _vl_api_address_union;
struct _vl_api_address;

extern void ip_api_address_decode (const struct _vl_api_address *in,
				   ip46_address_t * out);
extern void ip_api_address_union_decode (const union _vl_api_address_union
					 *in, int address_family,
					 ip46_address_t * out);

extern void ip_api_address_encode (const ip46_address_t * in,
				   int address_family,
				   struct _vl_api_address *out);
extern void ip_api_address_union_encode (const ip46_address_t * in,
					 int address_family,
					 union _vl_api_address_union *out);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
