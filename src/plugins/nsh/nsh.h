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
#ifndef included_nsh_h
#define included_nsh_h

#include <vnet/vnet.h>
#include <nsh/nsh_packet.h>
#include <vnet/ip/ip4_packet.h>

typedef struct {
  u16 class;
  u8 type;
  u8 pad;
} nsh_option_map_by_key_t;

typedef struct {
  u32 option_id;
} nsh_option_map_t;

#define MAX_METADATA_LEN 62
/** Note:
 * rewrite and rewrite_size used to support varied nsh header
 */
typedef struct {
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  nsh_base_header_t nsh_base;
  union {
     nsh_md1_data_t md1_data;
     nsh_md2_data_t md2_data;
   } md;
  u8 tlvs_len;    /* configured md2 metadata's length, unit: byte */
  u8 * tlvs_data; /* configured md2 metadata, network order */

  /** Rewrite string. network order
   * contains base header and metadata */
  u8 * rewrite;
  u8  rewrite_size; /* unit: byte */
} nsh_entry_t;

typedef struct {
  u8 is_add;
  nsh_entry_t nsh_entry;
} nsh_add_del_entry_args_t;

typedef struct {
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /** Key for nsh_header_t entry: 24bit NSP 8bit NSI */
  u32 nsp_nsi;
  /** Key for nsh_header_t entry to map to. : 24bit NSP 8bit NSI
   *  This may be ~0 if next action is to decap to NSH next protocol
   *  Note the following heuristic:
   *  if nsp_nsi == mapped_nsp_nsi then use-case is like SFC SFF
   *  if nsp_nsi != mapped_nsp_nsi then use-case is like SFC SF
   *  Note: these are heuristics. Rules about NSI decrement are out of scope
   */
  u32 mapped_nsp_nsi;
  /* NSH Header action: swap, push and pop */
  u32 nsh_action;

  /** vnet intfc hw_if_index */
  u32 nsh_hw_if;
  /* vnet intfc sw_if_index */
  u32 nsh_sw_if;

  /* encap if index */
  u32 sw_if_index;
  u32 rx_sw_if_index;
  u32 next_node;
  u32 adj_index;
} nsh_map_t;

typedef struct {
  u8 is_add;
  nsh_map_t map;
} nsh_add_del_map_args_t;

typedef struct {
  u32 transport_type; /* 1:vxlan; */
  u32 transport_index; /* transport's sw_if_index */
} nsh_proxy_session_by_key_t;

typedef struct {
  /* 24bit NSP 8bit NSI */
  u32 nsp_nsi;
} nsh_proxy_session_t;

#define MAX_MD2_OPTIONS 256

typedef struct {
  /* API message ID base */
  u16 msg_id_base;

  /* vector of nsh_header entry instances */
  nsh_entry_t *nsh_entries;

  /* hash lookup nsh header by key: {u32: nsp_nsi} */
  uword * nsh_entry_by_key;

  /* vector of nsh_mappings */
  nsh_map_t *nsh_mappings;

  /* hash lookup nsh mapping by key: {u32: nsp_nsi} */
  uword * nsh_mapping_by_key;
  uword * nsh_mapping_by_mapped_key; // for use in NSHSFC

  /* vector of nsh_proxy */
  nsh_proxy_session_t *nsh_proxy_sessions;

  /* hash lookup nsh_proxy by key */
  uword * nsh_proxy_session_by_key;

  /** Free vlib hw_if_indices */
  u32 * free_nsh_tunnel_hw_if_indices;
  /** Mapping from sw_if_index to tunnel index */
  u32 * tunnel_index_by_sw_if_index;

  /* vector of nsh_option_map */
  nsh_option_map_t * nsh_option_mappings;
  /* hash lookup nsh_option_map by key */
  uword * nsh_option_map_by_key;

  /* Array of function pointers to process MD-Type 2 handling routines */
  /*
   * For API or CLI configuration and construct the rewrite buffer, invokes add_options() function.
   * In the encap node, i.e. when performing PUSH nsh header, invokes options() function.
   * In the swap node, i.e. when performing SWAP nsh header, invokes swap_options() function.
   * In the decap node, i.e. when performing POP nsh header, invokes pop_options() function.
   */
  u8 options_size[MAX_MD2_OPTIONS];  /* sum of header and metadata */
  int (*add_options[MAX_MD2_OPTIONS]) (u8 * opt,
					   u8 * opt_size);
  int (*options[MAX_MD2_OPTIONS]) (vlib_buffer_t * b,
                                   nsh_tlv_header_t * opt);
  int (*swap_options[MAX_MD2_OPTIONS]) (vlib_buffer_t * b,
                                        nsh_tlv_header_t * old_opt,
					nsh_tlv_header_t * new_opt);
  int (*pop_options[MAX_MD2_OPTIONS]) (vlib_buffer_t * b,
				       nsh_tlv_header_t * opt);
  u8 *(*trace[MAX_MD2_OPTIONS]) (u8 * s, nsh_tlv_header_t * opt);
  uword decap_v4_next_override;

  /* Feature arc indices */
  u8 input_feature_arc_index;
  u8 output_feature_arc_index;

  u32 nsh_input_node_index;
  u32 nsh_proxy_node_index;
  u32 nsh_classifier_node_index;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} nsh_main_t;

extern nsh_main_t nsh_main;
extern vlib_node_registration_t nsh_aware_vnf_proxy_node;
extern vlib_node_registration_t nsh_eth_output_node;

typedef struct {
   u8 trace_data[256];
} nsh_input_trace_t;

u8 * format_nsh_input_map_trace (u8 * s, va_list * args);
u8 * format_nsh_header_with_length (u8 * s, va_list * args);

/* Helper macros used in nsh.c and nsh_test.c */
#define foreach_copy_nsh_base_hdr_field         \
_(ver_o_c)					\
_(length)					\
_(md_type)					\
_(next_protocol)				\
_(nsp_nsi)

/* Statistics (not really errors) */
#define foreach_nsh_node_error    \
_(MAPPED, "NSH header found and mapped") \
_(NO_MAPPING, "no mapping for nsh key") \
_(NO_ENTRY, "no entry for nsh key") \
_(NO_PROXY, "no proxy for transport key") \
_(INVALID_NEXT_PROTOCOL, "invalid next protocol") \
_(INVALID_OPTIONS, "invalid md2 options") \
_(INVALID_TTL, "ttl equals zero") \

typedef enum {
#define _(sym,str) NSH_NODE_ERROR_##sym,
  foreach_nsh_node_error
#undef _
  NSH_NODE_N_ERROR,

} nsh_input_error_t;

#define foreach_nsh_node_next        \
  _(DROP, "error-drop")			\
  _(ENCAP_GRE4, "gre4-input" )		\
  _(ENCAP_GRE6, "gre6-input" )		\
  _(ENCAP_VXLANGPE, "vxlan-gpe-encap" ) \
  _(ENCAP_VXLAN4, "vxlan4-encap" )  \
  _(ENCAP_VXLAN6, "vxlan6-encap" )  \
  _(DECAP_ETH_INPUT, "ethernet-input" ) \
  _(ENCAP_LISP_GPE, "interface-output" )  \
  _(ENCAP_ETHERNET, "nsh-eth-output")   \
/*   _(DECAP_IP4_INPUT,  "ip4-input") \ */
/*   _(DECAP_IP6_INPUT,  "ip6-input" ) \  */

typedef enum {
#define _(s,n) NSH_NODE_NEXT_##s,
  foreach_nsh_node_next
#undef _
  NSH_NODE_N_NEXT,
} nsh_node_next_t;

typedef enum {
  NSH_ACTION_SWAP,
  NSH_ACTION_PUSH,
  NSH_ACTION_POP,
} nsh_action_type;

typedef enum {
  NSH_INPUT_TYPE,
  NSH_PROXY_TYPE,
  NSH_CLASSIFIER_TYPE,
  NSH_AWARE_VNF_PROXY_TYPE,
} nsh_entity_type;

#define VNET_SW_INTERFACE_FLAG_ADMIN_DOWN 0

/* md2 class and type definition */
#define NSH_MD2_IOAM_CLASS 0x9
#define NSH_MD2_IOAM_OPTION_TYPE_TRACE   0x3B
#define NSH_MD2_IOAM_OPTION_TYPE_PROOF_OF_TRANSIT 0x3C

#define NSH_MD2_IOAM_TRACE_DUMMY_LEN 0x8

#define MAX_NSH_HEADER_LEN  256
#define MAX_NSH_OPTION_LEN  128

int
nsh_md2_register_option (u16 class,
                      u8 type,
                      u8 option_size,
                      int add_options (u8 * opt,
                                       u8 * opt_size),
                      int options(vlib_buffer_t * b,
                                  nsh_tlv_header_t * opt),
                      int swap_options (vlib_buffer_t * b,
				        nsh_tlv_header_t * old_opt,
		                        nsh_tlv_header_t * new_opt),
                      int pop_options (vlib_buffer_t * b,
                                       nsh_tlv_header_t * opt),
                      u8 * trace (u8 * s,
                                  nsh_tlv_header_t * opt));

typedef struct _nsh_main_dummy
{
  u8 output_feature_arc_index;
} nsh_main_dummy_t;

int
nsh_add_del_map (nsh_add_del_map_args_t * a, u32 * map_indexp);

int
nsh_add_del_proxy_session (nsh_add_del_map_args_t * a);

nsh_option_map_t *
nsh_md2_lookup_option (u16 class, u8 type);

int
nsh_add_del_entry (nsh_add_del_entry_args_t * a, u32 * entry_indexp);

u8 *
format_nsh_node_map_trace (u8 * s, va_list * args);

u8 *
format_nsh_header (u8 * s, va_list * args);

clib_error_t *
nsh_api_init (vlib_main_t * vm, nsh_main_t * nm);

#endif /* included_nsh_h */
