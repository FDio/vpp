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

#ifndef included_npol_ipset_h
#define included_npol_ipset_h

#include <npol/npol.h>

typedef enum
{
  IPSET_TYPE_IP = 0,
  IPSET_TYPE_IPPORT = 1,
  IPSET_TYPE_NET = 2
} npol_ipset_type_t;

typedef struct
{
  ip_address_t addr;
  u16 port;
  u8 l4proto;
} npol_ipport_t;

typedef union
{
  ip_address_t address;
  npol_ipport_t ipport;
  ip_prefix_t prefix;
} npol_ipset_member_t;

typedef struct
{
  npol_ipset_type_t type;
  npol_ipset_member_t *members;
} npol_ipset_t;

u32 npol_ipset_create (npol_ipset_type_t type);
int npol_ipset_delete (u32 id);

int npol_ipset_add_member (u32 ipset_id, npol_ipset_member_t *member);
int npol_ipset_del_member (u32 ipset_id, npol_ipset_member_t *member);

int npol_ipset_get_type (u32 id, npol_ipset_type_t *type);
u8 *format_npol_ipset (u8 *s, va_list *args);
npol_ipset_t *npol_ipsets_get_if_exists (u32 index);

extern npol_ipset_t *npol_ipsets;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
