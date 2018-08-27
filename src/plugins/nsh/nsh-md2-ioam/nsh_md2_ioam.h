/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#ifndef __included_nsh_md2_ioam_h__
#define __included_nsh_md2_ioam_h__

#include <nsh/nsh.h>
#include <nsh/nsh_packet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>


typedef struct nsh_md2_ioam_sw_interface_
{
  u32 sw_if_index;
} nsh_md2_ioam_sw_interface_t;

typedef struct nsh_md2_ioam_dest_tunnels_
{
  ip46_address_t dst_addr;
  u32 fp_proto;
  u32 sibling_index;
  fib_node_index_t fib_entry_index;
  u32 outer_fib_index;
} nsh_md2_ioam_dest_tunnels_t;

typedef struct nsh_md2_ioam_main_
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


  /* API message ID base */
  u16 msg_id_base;

  /* Override to export for iOAM */
  uword decap_v4_next_override;
  uword decap_v6_next_override;

  /* sequence of node graph for encap */
  uword encap_v4_next_node;
  uword encap_v6_next_node;

  /* Software interfaces. */
  nsh_md2_ioam_sw_interface_t *sw_interfaces;

  /* hash ip4/ip6 -> list of destinations for doing transit iOAM operation */
  nsh_md2_ioam_dest_tunnels_t *dst_tunnels;
  uword *dst_by_ip4;
  uword *dst_by_ip6;

  /** per sw_if_index, to maintain bitmap */
  u8 *bool_ref_by_sw_if_index;
  fib_node_type_t fib_entry_type;


} nsh_md2_ioam_main_t;
extern nsh_md2_ioam_main_t nsh_md2_ioam_main;

/*
 * Primary h-b-h handler trace support
 */
typedef struct
{
  u32 next_index;
  u32 trace_len;
  u8 option_data[256];
} ioam_trace_t;


clib_error_t *nsh_md2_ioam_enable_disable (int has_trace_option,
						int has_pot_option,
						int has_ppc_option);



int nsh_md2_ioam_trace_profile_setup (void);

int nsh_md2_ioam_trace_profile_cleanup (void);
extern void nsh_md2_ioam_interface_init (void);



#endif
