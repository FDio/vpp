/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 *  @file
 *  @brief VXLAN GPE definitions
 *
*/
#ifndef included_vnet_vxlan_gpe_h
#define included_vnet_vxlan_gpe_h

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vxlan-gpe/vxlan_gpe_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/udp.h>

/**
 * @brief VXLAN GPE header struct
 *
 */
typedef CLIB_PACKED (struct {
  /** 20 bytes */
  ip4_header_t ip4;
  /** 8 bytes */
  udp_header_t udp;
  /** 8 bytes */
  vxlan_gpe_header_t vxlan;
}) ip4_vxlan_gpe_header_t;

typedef CLIB_PACKED (struct {
  /** 40 bytes */
  ip6_header_t ip6;
  /** 8 bytes */
  udp_header_t udp;
  /** 8 bytes */
  vxlan_gpe_header_t vxlan;
}) ip6_vxlan_gpe_header_t;

/**
 * @brief Key struct for IPv4 VXLAN GPE tunnel.
 * Key fields: local remote, vni
 * all fields in NET byte order
 * VNI shifted 8 bits
 */
typedef CLIB_PACKED(struct {
  union {
    struct {
      u32 local;
      u32 remote;

      u32 vni;
      u32 pad;
    };
    u64 as_u64[2];
  };
}) vxlan4_gpe_tunnel_key_t;

/**
 * @brief Key struct for IPv6 VXLAN GPE tunnel.
 * Key fields: local remote, vni
 * all fields in NET byte order
 * VNI shifted 8 bits
 */
typedef CLIB_PACKED(struct {
  ip6_address_t local;
  ip6_address_t remote;
  u32 vni;
}) vxlan6_gpe_tunnel_key_t;

/**
 * @brief Struct for VXLAN GPE tunnel
 */
typedef struct {
  /** Rewrite string. $$$$ embed vnet_rewrite header */
  u8 * rewrite;

  /** encapsulated protocol */
  u8 protocol;

  /** tunnel local address */
  ip46_address_t local;
  /** tunnel remote address */
  ip46_address_t remote;

  /** FIB indices - tunnel partner lookup here */
  u32 encap_fib_index;
  /** FIB indices - inner IP packet lookup here */
  u32 decap_fib_index;

  /** VXLAN GPE VNI in HOST byte order, shifted left 8 bits */
  u32 vni;

  /** vnet intfc hw_if_index */
  u32 hw_if_index;
  /** vnet intfc sw_if_index */
  u32 sw_if_index;

  /** flags */
  u32 flags;

  /** rewrite size for dynamic plugins like iOAM */
  u8  rewrite_size;

  /** Next node after VxLAN-GPE encap */
  uword encap_next_node;
} vxlan_gpe_tunnel_t;

/** Flags for vxlan_gpe_tunnel_t */
#define VXLAN_GPE_TUNNEL_IS_IPV4	1
#define VXLAN_GPE_TUNNEL_IS_IOAM_CAPABLE 0x2

/** next nodes for VXLAN GPE input */
#define foreach_vxlan_gpe_input_next        \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")                       \
_(ETHERNET_INPUT, "ethernet-input")             \
_(NSH_INPUT, "ip4-load-balance")                      \
_(IOAM_INPUT, "vxlan-gpe-decap-ioam-v4")

/** struct for next nodes for VXLAN GPE input */
typedef enum {
#define _(s,n) VXLAN_GPE_INPUT_NEXT_##s,
  foreach_vxlan_gpe_input_next
#undef _
  VXLAN_GPE_INPUT_N_NEXT,
} vxlan_gpe_input_next_t;

/** struct for VXLAN GPE errors */
typedef enum {
#define vxlan_gpe_error(n,s) VXLAN_GPE_ERROR_##n,
#include <vnet/vxlan-gpe/vxlan_gpe_error.def>
#undef vxlan_gpe_error
  VXLAN_GPE_N_ERROR,
} vxlan_gpe_input_error_t;

/** Struct for VXLAN GPE node state */
typedef struct {
  /** vector of encap tunnel instances */
  vxlan_gpe_tunnel_t *tunnels;

  /** lookup IPv4 VXLAN GPE tunnel by key */
  uword * vxlan4_gpe_tunnel_by_key;
  /** lookup IPv6 VXLAN GPE tunnel by key */
  uword * vxlan6_gpe_tunnel_by_key;

  /** Free vlib hw_if_indices */
  u32 * free_vxlan_gpe_tunnel_hw_if_indices;

  /** Mapping from sw_if_index to tunnel index */
  u32 * tunnel_index_by_sw_if_index;


  /** State convenience vlib_main_t */
  vlib_main_t * vlib_main;
  /** State convenience vnet_main_t */
  vnet_main_t * vnet_main;

  /** Whether iOAM enabled ? */
  u8            ioam_enabled;
} vxlan_gpe_main_t;

vxlan_gpe_main_t vxlan_gpe_main;

extern vlib_node_registration_t vxlan_gpe_encap_node;
extern vlib_node_registration_t vxlan4_gpe_input_node;
extern vlib_node_registration_t vxlan6_gpe_input_node;

u8 * format_vxlan_gpe_encap_trace (u8 * s, va_list * args);

/** Struct for VXLAN GPE add/del args */
typedef struct {
  u8 is_add;
  u8 is_ip6;
  ip46_address_t local, remote;
  u8 protocol;
  u32 encap_fib_index;
  u32 decap_fib_index;
  u32 vni;
} vnet_vxlan_gpe_add_del_tunnel_args_t;


int vnet_vxlan_gpe_add_del_tunnel
(vnet_vxlan_gpe_add_del_tunnel_args_t *a, u32 * sw_if_indexp);

int vxlan4_gpe_rewrite (vxlan_gpe_tunnel_t * t, u32 extension_size, u8 protocol_override);
int vxlan6_gpe_rewrite (vxlan_gpe_tunnel_t * t, u32 extension_size, u8 protocol_override);

/*
 * iOAM handling
 */
typedef struct {
  /* Option Type */
  u8 type;
  /* Length in octets of the option data field */
  u8 length;
} vxlan_gpe_ioam_option_t;


/*
 * Primary h-b-h handler trace support
 * We work pretty hard on the problem for obvious reasons
 */
typedef struct {
  u32 next_index;
  u32 trace_len;
  u8 option_data[256];
} ioam_hop_by_hop_trace_t;


typedef struct vxlan_gpe_ioam_main_  {
  /* The current rewrite we're using */
  u8 * rewrite;

  /* Trace data processing callback */
  void *ioam_end_of_path_cb;
  /* Configuration data */
  /* Adjacency */
  ip6_address_t adj;
#define IOAM_HBYH_ADD  0
#define IOAM_HBYH_MOD  1
#define IOAM_HBYH_POP  2
  u8 ioam_flag;
  /* time scale transform. Joy. */
  u32 unix_time_0;
  f64 vlib_time_0;


  /* Trace option */
  u8 has_trace_option;

  /* Pot option */
  u8 has_pot_option;

#define PPC_NONE  0
#define PPC_ENCAP 1
#define PPC_DECAP 2
  u8 has_ppc_option;

#define TSP_SECONDS              0
#define TSP_MILLISECONDS         1
#define TSP_MICROSECONDS         2
#define TSP_NANOSECONDS          3

  /* Array of function pointers to ADD and POP HBH option handling routines */
  u8 options_size[256];
  int (*add_options[256])(u8 *rewrite_string, u8 *rewrite_size);
  int (*pop_options[256])(ip4_header_t *ip, vxlan_gpe_ioam_option_t *opt);

  /* Array of function pointers to HBH option handling routines */
  int (*options[256])(vlib_buffer_t *b, vxlan_gpe_tunnel_t *ip, vxlan_gpe_ioam_option_t *opt, u8 is_ipv4);
  u8 *(*trace[256])(u8 *s, vxlan_gpe_ioam_option_t *opt);

  /* API message ID base */
  u16 msg_id_base;

  /* Override to export for iOAM */
  uword decap_next_override;

  /* sequence of node graph for encap */
  uword encap_v4_next_node;
  uword encap_v6_next_node;

  /** State convenience vlib_main_t */
  vlib_main_t * vlib_main;
  /** State convenience vnet_main_t */
  vnet_main_t * vnet_main;


} vxlan_gpe_ioam_main_t;
extern vxlan_gpe_ioam_main_t vxlan_gpe_ioam_main;

typedef enum
{
  VXLAN_GPE_DECAP_IOAM_V4_NEXT_POP,
  VXLAN_GPE_DECAP_IOAM_V4_NEXT_DROP,
  VXLAN_GPE_DECAP_IOAM_V4_N_NEXT
} vxlan_gpe_decap_ioam_v4_next_t;

typedef enum
{
  VXLAN_GPE_POP_IOAM_V4_NEXT_ETHER,
  VXLAN_GPE_POP_IOAM_V4_NEXT_DROP,
  VXLAN_GPE_POP_IOAM_V4_N_NEXT
} vxlan_gpe_pop_ioam_v4_next_t;


/**
 * @brief Struct for defining VXLAN GPE next nodes
 */
typedef enum {
  VXLAN_GPE_ENCAP_NEXT_IP4_LOOKUP,
  VXLAN_GPE_ENCAP_NEXT_IP6_LOOKUP,
  VXLAN_GPE_ENCAP_NEXT_DROP,
  VXLAN_GPE_ENCAP_N_NEXT
} vxlan_gpe_encap_next_t;


#endif /* included_vnet_vxlan_gpe_h */
