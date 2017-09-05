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

#define SHA1_AUTH_DATA_LEN                  20
#define SHA256_AUTH_DATA_LEN                32

typedef enum
{
  HMAC_NO_KEY = 0,
  HMAC_SHA_1_96,
  HMAC_SHA_256_128
} lisp_key_type_t;

uword unformat_hmac_key_id (unformat_input_t * input, va_list * args);
u8 *format_hmac_key_id (u8 * s, va_list * args);

typedef enum
{
  IP4,
  IP6
} ip_address_type_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct ip_address
{
  union
  {
    ip4_address_t v4;
    ip6_address_t v6;
  } ip;
  u8 version;
}) ip_address_t;
/* *INDENT-ON* */

#define ip_addr_addr(_a) (_a)->ip
#define ip_addr_v4(_a) (_a)->ip.v4
#define ip_addr_v6(_a) (_a)->ip.v6
#define ip_addr_version(_a) (_a)->version

int ip_address_cmp (const ip_address_t * ip1, const ip_address_t * ip2);
void ip_address_copy (ip_address_t * dst, const ip_address_t * src);
void ip_address_copy_addr (void *dst, const ip_address_t * src);
void ip_address_set (ip_address_t * dst, const void *src, u8 version);

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct ip_prefix
{
  ip_address_t addr;
  u8 len;
}) ip_prefix_t;
/* *INDENT-ON* */

#define ip_prefix_addr(_a) (_a)->addr
#define ip_prefix_version(_a) ip_addr_version(&ip_prefix_addr(_a))
#define ip_prefix_len(_a) (_a)->len
#define ip_prefix_v4(_a) ip_addr_v4(&ip_prefix_addr(_a))
#define ip_prefix_v6(_a) ip_addr_v6(&ip_prefix_addr(_a))

void ip_prefix_normalize (ip_prefix_t * a);

extern void ip_address_to_fib_prefix (const ip_address_t * addr,
				      fib_prefix_t * prefix);
extern void ip_prefix_to_fib_prefix (const ip_prefix_t * ipp,
				     fib_prefix_t * fibp);

typedef enum
{
  /* NOTE: ip addresses are left out on purpose. Use max masked ip-prefixes
   * instead */
  GID_ADDR_IP_PREFIX,
  GID_ADDR_LCAF,
  GID_ADDR_MAC,
  GID_ADDR_SRC_DST,
  GID_ADDR_NSH,
  GID_ADDR_ARP,
  GID_ADDR_NDP,
  GID_ADDR_NO_ADDRESS,
  GID_ADDR_TYPES
} gid_address_type_t;

typedef enum
{
  /* make sure that values corresponds with RFC */
  LCAF_NULL_BODY = 0,
  LCAF_AFI_LIST_TYPE,
  LCAF_INSTANCE_ID,
  LCAF_SOURCE_DEST = 12,
  LCAF_NSH = 17,
  LCAF_TYPES
} lcaf_type_t;

typedef enum fid_addr_type_t_
{
  FID_ADDR_IP_PREF,
  FID_ADDR_MAC,
  FID_ADDR_NSH
} __attribute__ ((packed)) fid_addr_type_t;

/* flat address type */
typedef struct
{
  union
  {
    ip_prefix_t ippref;
    u8 mac[6];
    u32 nsh;
  };
  fid_addr_type_t type;
} fid_address_t;

typedef fid_address_t dp_address_t;

#define fid_addr_ippref(_a) (_a)->ippref
#define fid_addr_prefix_length(_a) ip_prefix_len(&fid_addr_ippref(_a))
#define fid_addr_ip_version(_a) ip_prefix_version(&fid_addr_ippref(_a))
#define fid_addr_mac(_a) (_a)->mac
#define fid_addr_nsh(_a) (_a)->nsh
#define fid_addr_type(_a) (_a)->type
u8 *format_fid_address (u8 * s, va_list * args);

typedef struct
{
  fid_address_t src;
  fid_address_t dst;
} source_dest_t;

#define sd_dst(_a) (_a)->dst
#define sd_src(_a) (_a)->src
#define sd_src_ippref(_a) fid_addr_ippref(&sd_src(_a))
#define sd_dst_ippref(_a) fid_addr_ippref(&sd_dst(_a))
#define sd_src_mac(_a) fid_addr_mac(&sd_src(_a))
#define sd_dst_mac(_a) fid_addr_mac(&sd_dst(_a))
#define sd_src_type(_a) fid_addr_type(&sd_src(_a))
#define sd_dst_type(_a) fid_addr_type(&sd_dst(_a))

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
  u32 spi;
  u8 si;
} nsh_t;

#define nsh_spi(_a) (_a)->spi
#define nsh_si(_a) (_a)->si

typedef struct
{
  ip_address_t addr;
  u32 bd;
} lcaf_arp_ndp_t;

#define lcaf_arp_ndp_ip(_a) (_a)->addr
#define lcaf_arp_ndp_ip_ver(_a) ip_addr_version(&lcaf_arp_ndp_ip(_a))
#define lcaf_arp_ndp_ip4(_a) ip_addr_v4(&lcaf_arp_ndp_ip(_a))
#define lcaf_arp_ndp_ip6(_a) ip_addr_v6(&lcaf_arp_ndp_ip(_a))
#define lcaf_arp_ndp_bd(_a) (_a)->bd

typedef struct
{
  /* the union needs to be at the beginning! */
  union
  {
    source_dest_t sd;
    lcaf_arp_ndp_t arp_ndp;
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
    u8 mac[6];
    source_dest_t sd;
    lcaf_arp_ndp_t arp_ndp;
    nsh_t nsh;
  };
  u8 type;
  u32 vni;
  u8 vni_mask;
} gid_address_t;

u8 *format_ip_address (u8 * s, va_list * args);
uword unformat_ip_address (unformat_input_t * input, va_list * args);
u8 *format_ip_prefix (u8 * s, va_list * args);
uword unformat_ip_prefix (unformat_input_t * input, va_list * args);
u8 *format_mac_address (u8 * s, va_list * args);
uword unformat_mac_address (unformat_input_t * input, va_list * args);

u16 ip4_address_size_to_put ();
u16 ip6_address_size_to_put ();
u32 ip4_address_put (u8 * b, ip4_address_t * a);
u32 ip6_address_put (u8 * b, ip6_address_t * a);

u16 ip_address_size_to_write (ip_address_t * a);
u16 ip_address_iana_afi (ip_address_t * a);
u8 ip_address_max_len (u8 ver);
u32 ip_address_put (u8 * b, ip_address_t * a);
void ip_address_to_46 (const ip_address_t * addr,
		       ip46_address_t * a, fib_protocol_t * proto);

/* LISP AFI codes  */
typedef enum
{
  LISP_AFI_NO_ADDR,
  LISP_AFI_IP,
  LISP_AFI_IP6,
  LISP_AFI_LCAF = 16387,
  LISP_AFI_MAC = 16389
} lisp_afi_e;

u8 *format_gid_address (u8 * s, va_list * args);
uword unformat_gid_address (unformat_input_t * input, va_list * args);
int gid_address_cmp (gid_address_t * a1, gid_address_t * a2);
void gid_address_free (gid_address_t * a);

u16 gid_address_size_to_put (gid_address_t * a);
u16 gid_address_put (u8 * b, gid_address_t * gid);
u8 gid_address_len (gid_address_t * a);
void *gid_address_cast (gid_address_t * gid, gid_address_type_t type);
void gid_address_copy (gid_address_t * dst, gid_address_t * src);
u32 gid_address_parse (u8 * offset, gid_address_t * a);
void gid_address_ip_set (gid_address_t * dst, void *src, u8 version);

#define gid_address_type(_a) (_a)->type
#define gid_address_ippref(_a) (_a)->ippref
#define gid_address_ippref_len(_a) (_a)->ippref.len
#define gid_address_ip(_a) ip_prefix_addr(&gid_address_ippref(_a))
#define gid_address_ip_version(_a) ip_addr_version(&gid_address_ip(_a))
#define gid_address_lcaf(_a) (_a)->lcaf
#define gid_address_mac(_a) (_a)->mac
#define gid_address_nsh(_a) (_a)->nsh
#define gid_address_nsh_spi(_a) nsh_spi(&gid_address_nsh(_a))
#define gid_address_nsh_si(_a) nsh_si(&gid_address_nsh(_a))
#define gid_address_vni(_a) (_a)->vni
#define gid_address_vni_mask(_a) (_a)->vni_mask
#define gid_address_sd_dst_ippref(_a) sd_dst_ippref(&(_a)->sd)
#define gid_address_sd_src_ippref(_a) sd_src_ippref(&(_a)->sd)
#define gid_address_sd_dst_mac(_a) sd_dst_mac(&(_a)->sd)
#define gid_address_sd_src_mac(_a) sd_src_mac(&(_a)->sd)
#define gid_address_sd(_a) (_a)->sd
#define gid_address_sd_src(_a) sd_src(&gid_address_sd(_a))
#define gid_address_sd_dst(_a) sd_dst(&gid_address_sd(_a))
#define gid_address_sd_src_type(_a) sd_src_type(&gid_address_sd(_a))
#define gid_address_sd_dst_type(_a) sd_dst_type(&gid_address_sd(_a))
#define gid_address_arp_ndp(_a) (_a)->arp_ndp
#define gid_address_arp_ndp_bd(_a) lcaf_arp_ndp_bd(&gid_address_arp_ndp(_a))
#define gid_address_arp_ndp_ip(_a) lcaf_arp_ndp_ip(&gid_address_arp_ndp(_a))
#define gid_address_arp_ip4(_a) lcaf_arp_ndp_ip4(&gid_address_arp_ndp(_a))
#define gid_address_ndp_ip6(_a) lcaf_arp_ndp_ip6(&gid_address_arp_ndp(_a))
#define gid_address_ndp_bd gid_address_arp_ndp_bd
#define gid_address_arp_bd gid_address_arp_ndp_bd

/* 'sub'address functions */
#define foreach_gid_address_type_fcns  \
  _(no_addr)                      \
  _(ip_prefix)                    \
  _(lcaf)                         \
  _(mac)                          \
  _(nsh)                          \
  _(sd)

/* *INDENT-OFF* */
#define _(_n)                                 \
u16    _n ## _size_to_write (void * pref);    \
u16    _n ## _write (u8 * p, void * pref);    \
u8     _n ## _length (void *a);               \
void * _n ## _cast (gid_address_t * a);       \
void   _n ## _copy (void * dst , void * src);

foreach_gid_address_type_fcns
#undef _
/* *INDENT-ON* */

always_inline u64
mac_to_u64 (u8 * m)
{
  return (*((u64 *) m) & 0xffffffffffff);
}

typedef struct
{
  /* mark locator as local as opposed to remote */
  u8 local;
  u8 state;
  union
  {
    u32 sw_if_index;
    gid_address_t address;
  };
  u8 priority;
  u8 weight;
  u8 mpriority;
  u8 mweight;
  u8 probed;
} locator_t;

u32 locator_parse (void *ptr, locator_t * loc);
void locator_copy (locator_t * dst, locator_t * src);
u32 locator_cmp (locator_t * l1, locator_t * l2);
void locator_free (locator_t * l);

typedef struct
{
  /* locator-set name */
  u8 *name;

  /* vector of locator indices */
  u32 *locator_indices;
  u8 local;
} locator_set_t;

typedef struct
{
  gid_address_t eid;

  /* index of local locator set */
  union
  {
    u32 locator_set_index;
    locator_t *locators;	/* used for map register message */
  };

  u32 ttl;
  u8 action;

  u8 authoritative:1;
  u8 local:1;
  /* valid only for remote mappings */
  u8 is_static:1;
  u8 pitr_set:1;
  u8 nsh_set:1;
  u8 almost_expired:1;
  u8 delete_after_expiration:1;
  u8 rsvd:1;

  u8 *key;
  lisp_key_type_t key_id;
  u8 timer_set;
  counter_t packets;
} mapping_t;

uword
unformat_negative_mapping_action (unformat_input_t * input, va_list * args);
u8 *format_negative_mapping_action (u8 *, va_list * args);

typedef struct locator_pair
{
  /* local and remote locators (underlay attachment points) */
  ip_address_t lcl_loc;
  ip_address_t rmt_loc;

  u8 priority;
  u8 weight;
} locator_pair_t;

void
build_src_dst (gid_address_t * sd, gid_address_t * src, gid_address_t * dst);

void gid_address_from_ip (gid_address_t * g, ip_address_t * ip);
void gid_to_dp_address (gid_address_t * g, dp_address_t * d);

#endif /* VNET_LISP_GPE_LISP_TYPES_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
