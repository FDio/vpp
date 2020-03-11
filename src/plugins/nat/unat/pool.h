/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef included_unat_pool_h
#define included_unat_pool_h

#include <vnet/ip/ip4_packet.h>

typedef struct {
  u32 count;
  u32 vrf_id;
  ip4_address_t prefix;
  u8 prefixlen;
  u32 thread_index;

  /* shared IPv4 address */
  u16 psid;
  u16 psid_length;
  u16 psid_mask;
} unat_pool_t;

u32 pool_add_addr_pool (ip4_address_t * prefix, u8 prefixlen, u8 psid_length, u16 psid, u32 vrf_id, u32 thread_index);
unat_pool_t *unat_pool_get(u32 index);
u32 unat_pool_len (void);
u8 *format_unat_pool (u8 * s, va_list * args);

#endif
