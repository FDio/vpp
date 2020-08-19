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

#ifndef included_capo_ipset_h
#define included_capo_ipset_h

#include <capo/capo.h>

typedef enum
{
  IPSET_TYPE_IP = 0,
  IPSET_TYPE_IPPORT = 1,
  IPSET_TYPE_NET = 2
} capo_ipset_type_t;

typedef struct
{
  ip_address_t addr;
  u16 port;
  u8 l4proto;
} capo_ipport_t;

typedef union
{
  ip_address_t address;
  capo_ipport_t ipport;
  ip_prefix_t prefix;
} capo_ipset_member_t;

typedef struct
{
  capo_ipset_type_t type;
  capo_ipset_member_t *members;
} capo_ipset_t;


u32 capo_ipset_create (capo_ipset_type_t type);
int capo_ipset_delete (u32 id);

int capo_ipset_add_member (u32 ipset_id, capo_ipset_member_t * member);
int capo_ipset_del_member (u32 ipset_id, capo_ipset_member_t * member);

int capo_ipset_get_type (u32 id, capo_ipset_type_t * type);

extern capo_ipset_t *capo_ipsets;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
