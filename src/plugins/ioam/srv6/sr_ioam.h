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
#ifndef __included_sr_ioam_h__
#define __included_sr_ioam_h__

#include <vnet/ip/ip.h>
#include <vnet/srv6/sr_packet.h>

#define MAX_IP6_SRH_TLV_OPTION                            256
#define SRH_OPTION_TYPE_IOAM_TRACE_DATA_LIST               59

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* time scale transform. Joy. */
  u32 unix_time_0;
  f64 vlib_time_0;
  /* Array of function pointers to ADD and POP SRH option handling routines */
  u8 options_size[MAX_IP6_SRH_TLV_OPTION];
  int (*add_options[MAX_IP6_SRH_TLV_OPTION]) (u8 * rewrite_string,
					      u8 * rewrite_size);
  int (*pop_options[MAX_IP6_SRH_TLV_OPTION]) (vlib_buffer_t * b,
					      ip6_header_t * ip,
					      ip6_sr_tlv_header_t * opt);
  int (*get_sizeof_options[MAX_IP6_SRH_TLV_OPTION]) (u32 * rewrite_size);
  /* Array of function pointers to SRH option handling routines */
  int (*options[MAX_IP6_SRH_TLV_OPTION]) (vlib_buffer_t * b,
					  ip6_header_t * ip,
					  ip6_sr_tlv_header_t * opt);
  u8 *(*trace[MAX_IP6_SRH_TLV_OPTION]) (u8 * s, ip6_sr_tlv_header_t * opt);
  int (*config_handler[MAX_IP6_SRH_TLV_OPTION]) (void *data, u8 disable);

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  /* Trace option */
  u8 has_trace_option;

  /* Pot option */
  u8 has_pot_option;

#define PPC_NONE  0
#define PPC_ENCAP 1
#define PPC_DECAP 2
  u8 has_ppc_option;

  uword sid_next_node;
  uword policy_next_node;
  uword decap_sr_next_override;

} ip6_sr_tlv_main_t;

extern ip6_sr_tlv_main_t ip6_sr_tlv_main;

int sr_tlv_add_register_option (u8 option, u8 size,
				/* Array of function pointers to SRH TLV option handling routines */
				int rewrite_options (u8 * rewrite_string,
						     u8 * rewrite_size),
				int pop_options (vlib_buffer_t * b,
						 ip6_header_t * ip,
						 ip6_sr_tlv_header_t * opt),
				int get_sizeof_options (u32 * rewrite_size),
				int options (vlib_buffer_t * b,
					     ip6_header_t * ip,
					     ip6_sr_tlv_header_t * opt),
				u8 *
				sr_tlv_trace_data_list_trace_handler (u8 * s,
								      ip6_sr_tlv_header_t
								      * opt));

clib_error_t *sr_ioam_enable (int has_trace_option,
			      int has_pot_option, int has_ppc_option);
clib_error_t *sr_ioam_disable (int
			       has_trace_option,
			       int has_pot_option, int has_ppc_option);
int sr_ioam_trace_profile_setup (void);
int sr_ioam_trace_profile_cleanup (void);
void sr_ioam_interface_init (void);

extern vlib_node_registration_t sr_ioam_localsid_node;
extern vlib_node_registration_t sr_ioam_policy_rewrite_insert_node;
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
