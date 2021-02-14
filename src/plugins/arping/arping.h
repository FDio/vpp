/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef included_arping_arping_h
#define included_arping_arping_h

#define ARPING_DEFAULT_INTERVAL 1.0
#define ARPING_DEFAULT_REPEAT	1

typedef struct arping6_ip6_reply_t
{
  mac_address_t mac;
  ip6_address_t ip6;
} arping6_ip6_reply_t;

typedef struct arping_intf_t
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 interval;
  u32 repeat;
  ip_address_t ip_address;

  ethernet_arp_ip4_over_ethernet_address_t recv_from4;
  arping6_ip6_reply_t recv_from6;
  u32 reply_count;
} arping_intf_t;

typedef struct arping_main_t
{
  arping_intf_t *arping_interfaces;
  arping_intf_t **interfaces;
} arping_main_t;

#endif /* included_arping_arping_h */
