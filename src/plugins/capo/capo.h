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

#ifndef included_capo_h
#define included_capo_h

#include <vnet/ip/ip.h>
#include <vnet/ip/ip_types_api.h>

#include <capo/capo.api_enum.h>
#include <capo/capo.api_types.h>


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

typedef struct
{
  capo_ipset_t *ipsets;


  /* API message ID base */
  u16 msg_id_base;

} capo_main_t;


extern capo_main_t capo_main;


u32 capo_ipset_create (capo_ipset_type_t type);
int capo_ipset_delete (u32 ipset_id);
int capo_ipset_member_from_api (u32 ipset_id, vl_api_capo_ipset_member_t * m,
				capo_ipset_member_t * dest);
int capo_ipset_add_member (u32 ipset_id, capo_ipset_member_t * new_member);
int capo_ipset_del_member (u32 ipset_id, capo_ipset_member_t * to_delete);


#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
