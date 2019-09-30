/*
 *
 * ip6_neighboor.h: ip6 neighbor structures
 *
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

#ifndef __IP6_ND_H__
#define __IP6_ND_H__

#include <vnet/ip/ip6_packet.h>

extern int ip6_nd_proxy_add (u32 sw_if_index, const ip6_address_t * addr);
extern int ip6_nd_proxy_del (u32 sw_if_index, const ip6_address_t * addr);

#endif /* included_ip6_neighbor_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
