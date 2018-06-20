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
#ifndef included_acl_types_h
#define included_acl_types_h

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

typedef struct
{
  u8 is_permit;
  u8 is_ipv6;
  ip46_address_t src;
  u8 src_prefixlen;
  ip46_address_t dst;
  u8 dst_prefixlen;
  u8 proto;
  u16 src_port_or_type_first;
  u16 src_port_or_type_last;
  u16 dst_port_or_code_first;
  u16 dst_port_or_code_last;
  u8 tcp_flags_value;
  u8 tcp_flags_mask;
} acl_rule_t;


#endif // included_acl_types_h

