/*
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

#ifndef VNET_LISP_GPE_LISP_TYPES_H_
#define VNET_LISP_GPE_LISP_TYPES_H_

#include <vnet/ip/ip.h>
#include <vnet/lisp-cp/lisp_cp_messages.h>

typedef enum
{
  IP4,
  IP6
} ip_address_type_t;

typedef struct
{
  union
  {
    ip4_address_t v4;
    ip6_address_t v6;
  } ip;
  ip_address_type_t version;
} ip_address_t;

typedef struct
{
  ip_address_t addr;
  u8 len;
} ip_prefix_t;

#define ip_addr_addr(_a) (_a)->ip
#define ip_addr_v4(_a) (_a)->ip.v4
#define ip_addr_v6(_a) (_a)->ip.v6
#define ip_addr_version(_a) (_a)->version

#define ip_prefix_addr(_a) (_a)->addr
#define ip_prefix_version(_a) ip_addr_version(&ip_prefix_addr(_a))
#define ip_prefix_len(_a) (_a)->len
#define ip_prefix_v4(_a) ip_addr_v4(&ip_prefix_addr(_a))
#define ip_prefix_v6(_a) ip_addr_v6(&ip_prefix_addr(_a))

typedef enum
{
  /* NOTE: ip addresses are left out on purpose. Use max masked ip-prefixes
   * instead */
  IP_PREFIX,
  NO_ADDRESS,
  GID_ADDR_TYPES
} gid_address_type_t;

/* might want to expand this in the future :) */
typedef struct
{
  union
  {
    ip_prefix_t ippref;
  };
  u8 type;
} gid_address_t;

u8 * format_ip_address (u8 * s, va_list * args);
uword unformat_ip_address (unformat_input_t * input, va_list * args);
u8 * format_ip_prefix (u8 * s, va_list * args);
uword unformat_ip_prefix (unformat_input_t * input, va_list * args);

u16 ip4_address_size_to_put ();
u16 ip6_address_size_to_put ();
u32 ip4_address_put (u8 * b, ip4_address_t * a);
u32 ip6_address_put (u8 * b, ip6_address_t * a);

u16 ip_address_size_to_write (ip_address_t * a);
u16 ip_address_iana_afi(ip_address_t *a);
u8 ip_address_max_len (u8 ver);
u32 ip_address_put (u8 * b, ip_address_t * a);

/* LISP AFI codes  */
typedef enum {
    LISP_AFI_NO_ADDR,
    LISP_AFI_IP,
    LISP_AFI_IP6,
    LISP_AFI_LCAF = 16387
} lisp_afi_e;

u8 *format_gid_address (u8 * s, va_list * args);
uword unformat_gid_address (unformat_input_t * input, va_list * args);

u16 gid_address_size_to_put (gid_address_t * a);
u16 gid_address_put (u8 * b, gid_address_t * gid);
u8 gid_address_len (gid_address_t *a);
void * gid_address_cast (gid_address_t * gid, gid_address_type_t type);
void gid_address_copy(gid_address_t * dst, gid_address_t * src);
u32 gid_address_parse (u8 * offset, gid_address_t *a);

#define gid_address_type(_a) (_a)->type
#define gid_address_ippref(_a) (_a)->ippref
#define gid_address_ippref_len(_a) (_a)->ippref.len
#define gid_address_ip(_a) ip_prefix_addr(&gid_address_ippref(_a))

/* 'sub'address functions */
int ip_address_cmp (ip_address_t * ip1, ip_address_t * ip2);
u16 ip_prefix_size_to_write (void * pref);
u16 ip_prefix_write (u8 * p, void * pref);
u8 ip_prefix_length (void *a);
void *ip_prefix_cast (gid_address_t * a);
void ip_prefix_copy (void * dst , void * src);

typedef struct
{
  /* mark locator as local as opposed to remote */
  u8 local;
  u8 state;
  union {
    u32 sw_if_index;
    gid_address_t address;
  };
  u8 priority;
  u8 weight;
  u8 mpriority;
  u8 mweight;
} locator_t;

u32 locator_parse (void * ptr, locator_t * loc);
void locator_copy (locator_t * dst, locator_t * src);
u32 locator_cmp (locator_t * l1, locator_t * l2);

typedef struct
{
  /* locator-set name */
  u8 * name;

  /* vector of locator indices */
  u32 * locator_indices;
  u8 local;
} locator_set_t;

typedef struct
{
  gid_address_t eid;

  /* index of local locator set */
  u32 locator_set_index;

  u32 ttl;
  u8 action;
  u8 authoritative;

  u8 local;
} mapping_t;

#endif /* VNET_LISP_GPE_LISP_TYPES_H_ */
