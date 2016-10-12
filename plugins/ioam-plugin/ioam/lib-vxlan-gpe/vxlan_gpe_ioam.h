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
#include <vnet/ip/ip.h>



#define VXLAN_GPE_OPTION_TYPE_IOAM_TRACE   59
#define VXLAN_GPE_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT 60

extern  vxlan_gpe_ioam_main_t vxlan_gpe_ioam_main;
vlib_node_registration_t vxlan_gpe_encap_ioam_v4_node;

clib_error_t *
vxlan_gpe_ioam_enable (int has_trace_option, int has_pot_option, int has_ppc_option);

clib_error_t *
vxlan_gpe_ioam_disable (int has_trace_option, int has_pot_option, int has_ppc_option);
clib_error_t *
vxlan_gpe_ioam_set (vxlan_gpe_tunnel_t * t,
				int has_trace_option,
				int has_pot_option,
				int has_ppc_option,
				u8 ipv6_set);
clib_error_t *
vxlan_gpe_ioam_clear (vxlan_gpe_tunnel_t * t,
				    int has_trace_option, int has_pot_option,
				    int has_ppc_option, u8 ipv6_set);

int vxlan_gpe_ioam_add_register_option (u8 option,
				    u8 size,
				    int rewrite_options (u8 * rewrite_string,
							 u8 * rewrite_size));

int
vxlan_gpe_add_unregister_option (u8 option);
int vxlan_gpe_ioam_register_option (u8 option,
				int options (vlib_buffer_t * b,
					     vxlan_gpe_tunnel_t *
					     vxlan_gpe_tunnel,
					     vxlan_gpe_ioam_option_t * opt,
					     u8 is_ipv4), u8 * trace (u8 * s,
								      vxlan_gpe_ioam_option_t
								      * opt));
int vxlan_gpe_ioam_unregister_option (u8 option);



#endif
