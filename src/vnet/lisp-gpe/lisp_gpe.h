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
/**
 * @file
 * @brief LISP-GPE definitions.
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
#include <vnet/udp/udp.h>
#include <vnet/lisp-cp/lisp_types.h>
#include <vnet/lisp-gpe/lisp_gpe_packet.h>
#include <vnet/adj/adj_types.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.h>

/** IP4-UDP-LISP encap header */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;             /* 20 bytes */
  udp_header_t udp;             /* 8 bytes */
  lisp_gpe_header_t lisp;       /* 8 bytes */
}) ip4_udp_lisp_gpe_header_t;
/* *INDENT-ON* */

/** IP6-UDP-LISP encap header */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip6_header_t ip6;             /* 40 bytes */
  udp_header_t udp;             /* 8 bytes */
  lisp_gpe_header_t lisp;       /* 8 bytes */
}) ip6_udp_lisp_gpe_header_t;
/* *INDENT-ON* */

#define foreach_lisp_gpe_ip_input_next          \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")                       \
_(L2_INPUT, "l2-input")

/** Enum of possible next nodes post LISP-GPE decap */
typedef enum
{
#define _(s,n) LISP_GPE_INPUT_NEXT_##s,
  foreach_lisp_gpe_ip_input_next
#undef _
    LISP_GPE_INPUT_N_NEXT,
} lisp_gpe_input_next_t;

/* Arc to nsh-input added only if nsh-input exists */
#define LISP_GPE_INPUT_NEXT_NSH_INPUT 4

typedef enum
{
#define lisp_gpe_error(n,s) LISP_GPE_ERROR_##n,
#include <vnet/lisp-gpe/lisp_gpe_error.def>
#undef lisp_gpe_error
  LISP_GPE_N_ERROR,
} lisp_gpe_error_t;

typedef struct tunnel_lookup
{
  /** Lookup lisp-gpe interfaces by dp table (eg. vrf/bridge index) */
  uword *hw_if_index_by_dp_table;

  /** lookup decap tunnel termination sw_if_index by vni and vice versa */
  uword *sw_if_index_by_vni;

  // FIXME - Need this?
  uword *vni_by_sw_if_index;
} tunnel_lookup_t;

typedef struct
{
  u32 fwd_entry_index;
  u32 tunnel_index;
} lisp_stats_key_t;

typedef struct
{
  u32 vni;
  dp_address_t deid;
  dp_address_t seid;
  ip_address_t loc_rloc;
  ip_address_t rmt_rloc;

  vlib_counter_t counters;
} lisp_api_stats_t;

typedef enum gpe_encap_mode_e
{
  GPE_ENCAP_LISP,
  GPE_ENCAP_VXLAN,
  GPE_ENCAP_COUNT
} gpe_encap_mode_t;

/** LISP-GPE global state*/
typedef struct lisp_gpe_main
{
  /**
   * @brief DB of all forwarding entries. The Key is:{l-EID,r-EID,vni}
   * where the EID encodes L2 or L3
   */
  uword *lisp_gpe_fwd_entries;

  /**
   * @brief A Pool of all LISP forwarding entries
   */
  struct lisp_gpe_fwd_entry_t_ *lisp_fwd_entry_pool;

  /** Free vlib hw_if_indices */
  u32 *free_tunnel_hw_if_indices;

  u8 is_en;

  /* L3 data structures
   * ================== */
  tunnel_lookup_t l3_ifaces;

  /* L2 data structures
   * ================== */

  /** L2 LISP FIB */
    BVT (clib_bihash) l2_fib;

  tunnel_lookup_t l2_ifaces;

  /** Load-balance for a miss in the table */
  dpo_id_t l2_lb_cp_lkup;

  /* NSH data structures
   * ================== */

    BVT (clib_bihash) nsh_fib;

  tunnel_lookup_t nsh_ifaces;

  const dpo_id_t *nsh_cp_lkup;

  gpe_encap_mode_t encap_mode;

  u8 *dummy_stats_pool;
  uword *lisp_stats_index_by_key;
  vlib_combined_counter_main_t counters;

  /** Native fwd data structures */
  fib_route_path_t *native_fwd_rpath[2];
  u32 *native_fwd_lfes[2];

  /** convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ip4_main_t *im4;
  ip6_main_t *im6;
  ip_lookup_main_t *lm4;
  ip_lookup_main_t *lm6;
} lisp_gpe_main_t;

/** LISP-GPE global state*/
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

/** Read LISP-GPE status */
u8 vnet_lisp_gpe_enable_disable_status (void);

u32
lisp_gpe_l3_iface_find_or_create (lisp_gpe_main_t * lgm,
				  u32 overlay_table_id, u32 vni);

/** Add/del LISP-GPE interface. */
extern void lisp_gpe_del_l2_iface (lisp_gpe_main_t * lgm, u32 vni, u32 bd_id);
extern u32 lisp_gpe_add_l2_iface (lisp_gpe_main_t * lgm, u32 vni, u32 bd_id);
extern void lisp_gpe_del_l3_iface (lisp_gpe_main_t * lgm, u32 vni, u32 bd_id);
extern u32 lisp_gpe_add_l3_iface (lisp_gpe_main_t * lgm, u32 vni, u32 bd_id);


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

/** */
typedef struct
{
  /** forwarding entry index of */
  u32 fwd_entry_index;

  u8 is_src_dst;

  u8 is_add;

  /** type of mapping */
  u8 is_negative;

  /** action for negative mappings */
  negative_fwd_actions_e action;

  /** local eid */
  gid_address_t lcl_eid;

  /** remote eid */
  gid_address_t rmt_eid;

  /** vector of locator pairs */
  locator_pair_t *locator_pairs;

  /** FIB index to lookup remote locator at encap */
  u32 encap_fib_index;

  /** FIB index to lookup inner IP at decap */
  u32 decap_fib_index;

  /* TODO remove */
  u32 decap_next_index;

  /** VNI/tenant id in HOST byte order */
  u32 vni;

  /** vrf or bd where fwd entry should be inserted */
  union
  {
    /** table (vrf) id */
    u32 table_id;

    /** bridge domain id */
    u32 bd_id;

    /** generic access */
    u32 dp_table;
  };
} vnet_lisp_gpe_add_del_fwd_entry_args_t;

typedef struct
{
  fib_route_path_t rpath;
  u8 is_add;
} vnet_gpe_native_fwd_rpath_args_t;

typedef struct
{
  u32 fwd_entry_index;
  u32 dp_table;
  u32 vni;
  u8 action;
  dp_address_t leid;
  dp_address_t reid;
} lisp_api_gpe_fwd_entry_t;

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

#define foreach_lgpe_ip6_lookup_next    \
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

lisp_api_gpe_fwd_entry_t *vnet_lisp_gpe_fwd_entries_get_by_vni (u32 vni);
gpe_encap_mode_t vnet_gpe_get_encap_mode (void);
int vnet_gpe_set_encap_mode (gpe_encap_mode_t mode);

u8 vnet_lisp_stats_enable_disable_state (void);
vnet_api_error_t vnet_lisp_stats_enable_disable (u8 enable);
lisp_api_stats_t *vnet_lisp_get_stats (void);
int vnet_lisp_flush_stats (void);
int vnet_gpe_add_del_native_fwd_rpath (vnet_gpe_native_fwd_rpath_args_t * a);
u32 vnet_lisp_gpe_add_nsh_iface (lisp_gpe_main_t * lgm);
void vnet_lisp_gpe_del_nsh_iface (lisp_gpe_main_t * lgm);

#endif /* included_vnet_lisp_gpe_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
