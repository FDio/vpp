/*
 * tunnel.h: shared definitions for tunnels.
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef __TUNNEL_H__
#define __TUNNEL_H__

#include <vnet/ip/ip_types.h>
#include <vnet/fib/fib_node.h>

#define foreach_tunnel_mode     \
  _(P2P, "point-to-point")      \
  _(MP, "multi-point")          \

typedef enum tunnel_mode_t_
{
#define _(n, s) TUNNEL_MODE_##n,
  foreach_tunnel_mode
#undef _
} __clib_packed tunnel_mode_t;

extern u8 *format_tunnel_mode (u8 * s, va_list * args);
extern uword unformat_tunnel_mode (unformat_input_t * input, va_list * args);

/**
 * Keep these idenitical to those in ipip.api
 */
#define foreach_tunnel_encap_decap_flag                                       \
  _ (NONE, "none", 0x0)                                                       \
  _ (ENCAP_COPY_DF, "encap-copy-df", 0x1)                                     \
  _ (ENCAP_SET_DF, "encap-set-df", 0x2)                                       \
  _ (ENCAP_COPY_DSCP, "encap-copy-dscp", 0x4)                                 \
  _ (ENCAP_COPY_ECN, "encap-copy-ecn", 0x8)                                   \
  _ (DECAP_COPY_ECN, "decap-copy-ecn", 0x10)                                  \
  _ (ENCAP_INNER_HASH, "encap-inner-hash", 0x20)                              \
  _ (ENCAP_COPY_HOP_LIMIT, "encap-copy-hop-limit", 0x40)                      \
  _ (ENCAP_COPY_FLOW_LABEL, "encap-copy-flow-label", 0x80)

typedef enum tunnel_encap_decap_flags_t_
{
#define _(a,b,c) TUNNEL_ENCAP_DECAP_FLAG_##a = c,
  foreach_tunnel_encap_decap_flag
#undef _
} __clib_packed tunnel_encap_decap_flags_t;

extern const u8 TUNNEL_ENCAP_DECAP_FLAG_MASK;

extern u8 *format_tunnel_encap_decap_flags (u8 * s, va_list * args);
extern uword unformat_tunnel_encap_decap_flags (unformat_input_t *input,
						va_list *args);

#define foreach_tunnel_flag                                                   \
  _ (RESOLVED, 0, "resolved")                                                 \
  _ (TRACK_MTU, 1, "track-mtu")

typedef enum tunnel_flags_t_
{
  TUNNEL_FLAG_NONE = 0,
#define _(n, b, s) TUNNEL_FLAG_##n = (1 << b),
  foreach_tunnel_flag
#undef _
} __clib_packed tunnel_flags_t;

extern const u8 TUNNEL_FLAG_MASK;

extern u8 *format_tunnel_flags (u8 *s, va_list *args);
extern uword unformat_tunnel_flags (unformat_input_t *input, va_list *args);

/**
 * A representation of an IP tunnel config
 */
typedef struct tunnel_t_
{
  ip_address_t t_src;
  ip_address_t t_dst;
  tunnel_encap_decap_flags_t t_encap_decap_flags;
  tunnel_flags_t t_flags;
  tunnel_mode_t t_mode;
  u32 t_table_id;
  ip_dscp_t t_dscp;
  u8 t_hop_limit;

  /**
   * derived data
   */
  u32 t_fib_index;

  fib_node_index_t t_fib_entry_index;
  u32 t_sibling;

} tunnel_t;

extern u8 *format_tunnel (u8 *s, va_list *args);
extern uword unformat_tunnel (unformat_input_t *input, va_list *args);

extern void tunnel_copy (const tunnel_t *src, tunnel_t *dst);
extern int tunnel_resolve (tunnel_t *t, fib_node_type_t child_type,
			   index_t child_index);
extern void tunnel_unresolve (tunnel_t *t);

extern ip_address_family_t tunnel_get_af (const tunnel_t *t);

extern void tunnel_contribute_forwarding (const tunnel_t *t, dpo_id_t *dpo);

extern void tunnel_build_v6_hdr (const tunnel_t *t, ip_protocol_t next_proto,
				 ip6_header_t *ip);
extern void tunnel_build_v4_hdr (const tunnel_t *t, ip_protocol_t next_proto,
				 ip4_header_t *ip);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
