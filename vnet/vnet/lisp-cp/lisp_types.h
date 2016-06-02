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

typedef CLIB_PACKED(struct ip_address
{
  union
  {
    ip4_address_t v4;
    ip6_address_t v6;
  } ip;
  u8 version;
}) ip_address_t;

#define ip_addr_addr(_a) (_a)->ip
#define ip_addr_v4(_a) (_a)->ip.v4
#define ip_addr_v6(_a) (_a)->ip.v6
#define ip_addr_version(_a) (_a)->version

int ip_address_cmp (ip_address_t * ip1, ip_address_t * ip2);
void ip_address_copy (ip_address_t * dst , ip_address_t * src);
void ip_address_copy_addr (void * dst , ip_address_t * src);
void ip_address_set(ip_address_t * dst, void * src, u8 version);

typedef CLIB_PACKED(struct ip_prefix
{
  ip_address_t addr;
  u8 len;
}) ip_prefix_t;

#define ip_prefix_addr(_a) (_a)->addr
#define ip_prefix_version(_a) ip_addr_version(&ip_prefix_addr(_a))
#define ip_prefix_len(_a) (_a)->len
#define ip_prefix_v4(_a) ip_addr_v4(&ip_prefix_addr(_a))
#define ip_prefix_v6(_a) ip_addr_v6(&ip_prefix_addr(_a))

typedef enum
{
  /* NOTE: ip addresses are left out on purpose. Use max masked ip-prefixes
   * instead */
  GID_ADDR_IP_PREFIX,
  GID_ADDR_LCAF,
  GID_ADDR_NO_ADDRESS,
  GID_ADDR_TYPES
} gid_address_type_t;

typedef enum
{
  /* make sure that values corresponds with RFC */
  LCAF_NULL_BODY = 0,
  LCAF_AFI_LIST_TYPE,
  LCAF_INSTANCE_ID,
  LCAF_TYPES
} lcaf_type_t;

struct _gid_address_t;

typedef struct
{
  u8 src_len;
  u8 dst_len;
  struct _gid_address_t *src;
  struct _gid_address_t *dst;
} source_dest_t;

typedef struct
{
  u8 vni_mask_len;
  u32 vni;
  struct _gid_address_t *gid_addr;
} vni_t;

#define vni_vni(_a) (_a)->vni
#define vni_mask_len(_a) (_a)->vni_mask_len
#define vni_gid(_a) (_a)->gid_addr

typedef struct
{
  /* the union needs to be at the beginning! */
  union
  {
    source_dest_t sd;
    vni_t uni;
  };
  u8 type;
} lcaf_t;

#define lcaf_type(_a) (_a)->type
#define lcaf_vni(_a) vni_vni(& (_a)->uni)
#define lcaf_vni_len(_a) vni_mask_len(& (_a)->uni)

/* might want to expand this in the future :) */
typedef struct _gid_address_t
{
  union
  {
    ip_prefix_t ippref;
    lcaf_t lcaf;
  };
  u8 type;
  u32 vni;
  u8 vni_mask;
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
int gid_address_cmp (gid_address_t * a1, gid_address_t * a2);
void gid_address_free (gid_address_t *a);

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
#define gid_address_ip_version(_a) ip_addr_version(&gid_address_ip(_a))
#define gid_address_lcaf(_a) (_a)->lcaf
#define gid_address_vni(_a) (_a)->vni
#define gid_address_vni_mask(_a) (_a)->vni_mask

/* 'sub'address functions */
u16 ip_prefix_size_to_write (void * pref);
u16 ip_prefix_write (u8 * p, void * pref);
u8 ip_prefix_length (void *a);
void *ip_prefix_cast (gid_address_t * a);
void ip_prefix_copy (void * dst , void * src);

int lcaf_cmp (lcaf_t * lcaf1, lcaf_t * lcaf2);
u16 lcaf_size_to_write (void * pref);
u16 lcaf_write (u8 * p, void * pref);
u8 lcaf_prefix_length (void *a);
void *lcaf_cast (gid_address_t * a);
void lcaf_copy (void * dst , void * src);

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
void locator_free (locator_t * l);

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

lcaf_t lcaf_iid_init (u32 vni);

#endif /* VNET_LISP_GPE_LISP_TYPES_H_ */
