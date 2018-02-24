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

#ifndef __IP6_LL_TYPES_H__
#define __IP6_LL_TYPES_H__

#include <vnet/ip/ip6_packet.h>

/**
 * Aggregrate type for a prefix in the IPv6 Link-local table
 */
typedef struct ip6_ll_prefix_t_
{
  /**
   * The interface
   */
  u32 ilp_sw_if_index;

  /**
   * the IP6 address
   */
  ip6_address_t ilp_addr;
} ip6_ll_prefix_t;

extern u8 *format_ip6_ll_prefix (u8 * s, va_list * args);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
