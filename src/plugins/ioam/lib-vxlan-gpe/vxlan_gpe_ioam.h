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
#ifndef __included_vxlan_gpe_ioam_h__
#define __included_vxlan_gpe_ioam_h__

#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/vxlan-gpe/vxlan_gpe_packet.h>
#include <ioam/lib-vxlan-gpe/vxlan_gpe_ioam_packet.h>
#include <vnet/ip/ip.h>


typedef struct vxlan_gpe_sw_interface_
{
  u32 sw_if_index;
} vxlan_gpe_ioam_sw_interface_t;

typedef struct vxlan_gpe_dest_tunnels_
{
  ip46_address_t dst_addr;
  u32 fp_proto;
  u32 sibling_index;
  fib_node_index_t fib_entry_index;
  u32 outer_fib_index;
} vxlan_gpe_ioam_dest_tunnels_t;

typedef struct vxlan_gpe_ioam_main_
{
  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

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

  /* Array of function pointers to ADD and POP VxLAN-GPE iOAM option handling routines */
  u8 options_size[256];
  int (*add_options[256]) (u8 * rewrite_string, u8 * rewrite_size);
  int (*pop_options[256]) (ip4_header_t * ip, vxlan_gpe_ioam_option_t * opt);

  /* Array of function pointers to iOAM option handling routines */
  int (*options[256]) (vlib_buffer_t * b, vxlan_gpe_ioam_option_t * opt,
		       u8 is_ipv4, u8 use_adj);
  u8 *(*trace[256]) (u8 * s, vxlan_gpe_ioam_option_t * opt);

  /* API message ID base */
  u16 msg_id_base;

  /* Override to export for iOAM */
  uword decap_v4_next_override;
  uword decap_v6_next_override;

  /* sequence of node graph for encap */
  uword encap_v4_next_node;
  uword encap_v6_next_node;

  /* Software interfaces. */
  vxlan_gpe_ioam_sw_interface_t *sw_interfaces;

  /* hash ip4/ip6 -> list of destinations for doing transit iOAM operation */
  vxlan_gpe_ioam_dest_tunnels_t *dst_tunnels;
  uword *dst_by_ip4;
  uword *dst_by_ip6;

  /** per sw_if_index, to maintain bitmap */
  u8 *bool_ref_by_sw_if_index;
  fib_node_type_t fib_entry_type;

  /** State convenience vlib_main_t */
  vlib_main_t *vlib_main;
  /** State convenience vnet_main_t */
  vnet_main_t *vnet_main;


} vxlan_gpe_ioam_main_t;
extern vxlan_gpe_ioam_main_t vxlan_gpe_ioam_main;

/*
 * Primary h-b-h handler trace support
 */
typedef struct
{
  u32 next_index;
  u32 trace_len;
  u8 option_data[256];
} ioam_trace_t;


extern vlib_node_registration_t vxlan_gpe_encap_ioam_v4_node;
extern vlib_node_registration_t vxlan_gpe_decap_ioam_v4_node;
extern vlib_node_registration_t vxlan_gpe_transit_ioam_v4_node;

clib_error_t *vxlan_gpe_ioam_enable (int has_trace_option, int has_pot_option,
				     int has_ppc_option);

clib_error_t *vxlan_gpe_ioam_disable (int has_trace_option,
				      int has_pot_option, int has_ppc_option);

clib_error_t *vxlan_gpe_ioam_set (vxlan_gpe_tunnel_t * t,
				  int has_trace_option,
				  int has_pot_option,
				  int has_ppc_option, u8 ipv6_set);
clib_error_t *vxlan_gpe_ioam_clear (vxlan_gpe_tunnel_t * t,
				    int has_trace_option, int has_pot_option,
				    int has_ppc_option, u8 ipv6_set);

int vxlan_gpe_ioam_add_register_option (u8 option,
					u8 size,
					int rewrite_options (u8 *
							     rewrite_string,
							     u8 *
							     rewrite_size));

int vxlan_gpe_add_unregister_option (u8 option);

int vxlan_gpe_ioam_register_option (u8 option,
				    int options (vlib_buffer_t * b,
						 vxlan_gpe_ioam_option_t *
						 opt, u8 is_ipv4, u8 use_adj),
				    u8 * trace (u8 * s,
						vxlan_gpe_ioam_option_t *
						opt));
int vxlan_gpe_ioam_unregister_option (u8 option);

int vxlan_gpe_trace_profile_setup (void);

int vxlan_gpe_trace_profile_cleanup (void);
extern void vxlan_gpe_ioam_interface_init (void);
int
vxlan_gpe_enable_disable_ioam_for_dest (vlib_main_t * vm,
					ip46_address_t dst_addr,
					u32 outer_fib_index,
					u8 is_ipv4, u8 is_add);
int vxlan_gpe_ioam_disable_for_dest
  (vlib_main_t * vm, ip46_address_t dst_addr, u32 outer_fib_index,
   u8 ipv4_set);

typedef enum
{
  VXLAN_GPE_DECAP_IOAM_V4_NEXT_POP,
  VXLAN_GPE_DECAP_IOAM_V4_NEXT_DROP,
  VXLAN_GPE_DECAP_IOAM_V4_N_NEXT
} vxlan_gpe_decap_ioam_v4_next_t;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
