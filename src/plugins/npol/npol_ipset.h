/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
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
npol_ipset_t *npol_ipsets_get_if_exists (u32 index);

extern npol_ipset_t *npol_ipsets;

#endif
