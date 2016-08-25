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

#ifndef included_vnet_lisp_gpe_h
#define included_vnet_lisp_gpe_h

#include <vppinfra/error.h>
#include <vppinfra/mhash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/udp.h>
#include <vnet/lisp-cp/lisp_types.h>
#include <vnet/lisp-gpe/lisp_gpe_packet.h>
#include <vnet/adj/adj_types.h>

/* encap headers */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;             /* 20 bytes */
  udp_header_t udp;             /* 8 bytes */
  lisp_gpe_header_t lisp;       /* 8 bytes */
}) ip4_udp_lisp_gpe_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip6_header_t ip6;             /* 40 bytes */
  udp_header_t udp;             /* 8 bytes */
  lisp_gpe_header_t lisp;       /* 8 bytes */
}) ip6_udp_lisp_gpe_header_t;
/* *INDENT-ON* */

typedef struct
{
  union
  {
    struct
    {
      dp_address_t rmt;
      dp_address_t lcl;

      u32 vni;
    };
    u8 as_u8[40];
  };
} lisp_gpe_tunnel_key_t;

typedef struct lisp_gpe_sub_tunnel
{
  /* linkage into the FIB graph */
  fib_node_t fib_node;

  /* Rewrite string. $$$$ embed vnet_rewrite header */
  u8 *rewrite;
  u32 parent_index;
  u32 locator_pair_index;
  u8 weight;
  u8 is_ip4;
  /** the FIB entry through which this tunnel resolves */
  fib_node_index_t fib_entry_index;
  /** Index into the parent FIB entry's child list */
  u32 sibling;
  /** the midchain adjacency created for this tunnels */
  adj_index_t midchain[FIB_LINK_NUM];
} lisp_gpe_sub_tunnel_t;

typedef struct nomalized_sub_tunnel
{
  u32 sub_tunnel_index;
  u8 weight;
} normalized_sub_tunnel_weights_t;

typedef struct
{
  /* Rewrite string. $$$$ embed vnet_rewrite header */
  u8 *rewrite;

  /* tunnel src and dst addresses */
  locator_pair_t *locator_pairs;

  /* locator-pairs with best priority become sub-tunnels */
  u32 *sub_tunnels;

  /* decap next index */
  u32 decap_next_index;

  /* TODO remove */
  ip_address_t src, dst;

  /* FIB indices */
  u32 encap_fib_index;		/* tunnel partner lookup here */
  u32 decap_fib_index;		/* inner IP lookup here */

  /** index of the source address lookup FIB */
  u32 src_fib_index;

  /* vnet intfc hw/sw_if_index */
  u32 hw_if_index;
  u32 sw_if_index;

  /** L2 path-list */
  fib_node_index_t l2_path_list;

  /* action for 'negative' tunnels */
  u8 action;

  /* LISP header fields in HOST byte order */
  u8 flags;
  u8 ver_res;
  u8 res;
  u8 next_protocol;
  u32 vni;
} lisp_gpe_tunnel_t;

#define foreach_lisp_gpe_ip_input_next          \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")                       \
_(L2_INPUT, "l2-input")

typedef enum
{
#define _(s,n) LISP_GPE_INPUT_NEXT_##s,
  foreach_lisp_gpe_ip_input_next
#undef _
    LISP_GPE_INPUT_N_NEXT,
} lisp_gpe_input_next_t;

typedef enum
{
#define lisp_gpe_error(n,s) LISP_GPE_ERROR_##n,
#include <vnet/lisp-gpe/lisp_gpe_error.def>
#undef lisp_gpe_error
  LISP_GPE_N_ERROR,
} lisp_gpe_error_t;

typedef struct tunnel_lookup
{
  /* Lookup lisp-gpe interfaces by dp table (eg. vrf/bridge index) */
  uword *hw_if_index_by_dp_table;

  /* lookup decap tunnel termination sw_if_index by vni and vice versa */
  uword *sw_if_index_by_vni;
  uword *vni_by_sw_if_index;
} tunnel_lookup_t;

typedef struct lisp_gpe_main
{
  /* pool of encap tunnel instances */
  lisp_gpe_tunnel_t *tunnels;

  /* lookup tunnel by key */
  mhash_t lisp_gpe_tunnel_by_key;

  /* Free vlib hw_if_indices */
  u32 *free_tunnel_hw_if_indices;

  u8 is_en;

  /* L3 data structures
   * ================== */
  tunnel_lookup_t l3_ifaces;

  /* L2 data structures
   * ================== */

  /* l2 lisp fib */
    BVT (clib_bihash) l2_fib;

  tunnel_lookup_t l2_ifaces;

  /** Load-balance for a miss in the table */
  index_t l2_lb_miss;
  index_t l2_lb_cp_lkup;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ip4_main_t *im4;
  ip6_main_t *im6;
  ip_lookup_main_t *lm4;
  ip_lookup_main_t *lm6;
} lisp_gpe_main_t;

lisp_gpe_main_t lisp_gpe_main;

always_inline lisp_gpe_main_t *
vnet_lisp_gpe_get_main ()
{
  return &lisp_gpe_main;
}


extern vlib_node_registration_t lisp_gpe_ip4_input_node;
extern vlib_node_registration_t lisp_gpe_ip6_input_node;
extern vnet_hw_interface_class_t lisp_gpe_hw_class;

u8 *format_lisp_gpe_header_with_length (u8 * s, va_list * args);

typedef struct
{
  u8 is_add;
  union
  {
    /* vrf */
    u32 table_id;

    /* bridge domain */
    u16 bd_id;

    /* generic access */
    u32 dp_table;
  };
  u8 is_l2;
  u32 vni;			/* host byte order */
} vnet_lisp_gpe_add_del_iface_args_t;

u8 vnet_lisp_gpe_enable_disable_status (void);
int
vnet_lisp_gpe_add_del_iface (vnet_lisp_gpe_add_del_iface_args_t * a,
			     u32 * hw_if_indexp);

typedef struct
{
  u8 is_en;
} vnet_lisp_gpe_enable_disable_args_t;

clib_error_t
  * vnet_lisp_gpe_enable_disable (vnet_lisp_gpe_enable_disable_args_t * a);

typedef enum
{
  NO_ACTION,
  FORWARD_NATIVE,
  SEND_MAP_REQUEST,
  DROP
} negative_fwd_actions_e;
typedef struct
{
  u8 is_add;

  /* type of mapping */
  u8 is_negative;
  negative_fwd_actions_e action;

  /* local and remote eids */
  gid_address_t lcl_eid;
  gid_address_t rmt_eid;

  /* vector of locator pairs */
  locator_pair_t *locator_pairs;

  /* FIB indices to lookup remote locator at encap and inner IP at decap */
  u32 encap_fib_index;
  u32 decap_fib_index;

  u32 decap_next_index;		/* TODO is this really needed? */

  /* VNI/tenant id in HOST byte order */
  u32 vni;

  /* vrf or bd where fwd entry should be inserted */
  union
  {
    u32 table_id;
    u16 bd_id;

    /* generic access */
    u32 dp_table;
  };
} vnet_lisp_gpe_add_del_fwd_entry_args_t;

int
vnet_lisp_gpe_add_del_fwd_entry (vnet_lisp_gpe_add_del_fwd_entry_args_t * a,
				 u32 * hw_if_indexp);

extern void
ip_src_fib_add_route (u32 src_fib_index,
		      ip_prefix_t * src_prefix, lisp_gpe_tunnel_t * t);
extern void
ip_src_dst_fib_del_route (u32 src_fib_index,
			  ip_prefix_t * src_prefix,
			  u32 dst_table_id, ip_prefix_t * dst_prefix);
extern void
ip_src_fib_add_route_w_dpo (u32 src_fib_index,
			    ip_prefix_t * src_prefix,
			    const dpo_id_t * src_dpo);
extern void
ip_dst_fib_add_route (u32 dst_table_id,
		      ip_prefix_t * dst_prefix,
		      ip_prefix_t * src_prefix,
		      fib_node_index_t * src_fib_index);

extern fib_route_path_t *lisp_gpe_mk_paths_for_sub_tunnels (lisp_gpe_tunnel_t
							    * t);

#define foreach_lgpe_ip4_lookup_next    \
  _(DROP, "error-drop")                 \
  _(LISP_CP_LOOKUP, "lisp-cp-lookup")

typedef enum lgpe_ip4_lookup_next
{
#define _(sym,str) LGPE_IP4_LOOKUP_NEXT_##sym,
  foreach_lgpe_ip4_lookup_next
#undef _
    LGPE_IP4_LOOKUP_N_NEXT,
} lgpe_ip4_lookup_next_t;

#define foreach_lgpe_ip6_lookup_next     \
  _(DROP, "error-drop")                 \
  _(LISP_CP_LOOKUP, "lisp-cp-lookup")

typedef enum lgpe_ip6_lookup_next
{
#define _(sym,str) LGPE_IP6_LOOKUP_NEXT_##sym,
  foreach_lgpe_ip6_lookup_next
#undef _
    LGPE_IP6_LOOKUP_N_NEXT,
} lgpe_ip6_lookup_next_t;

u8 *format_vnet_lisp_gpe_status (u8 * s, va_list * args);

#define L2_FIB_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define L2_FIB_DEFAULT_HASH_MEMORY_SIZE (32<<20)

u32
lisp_l2_fib_lookup (lisp_gpe_main_t * lgm, u16 bd_index, u8 src_mac[8],
		    u8 dst_mac[8]);

#endif /* included_vnet_lisp_gpe_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
