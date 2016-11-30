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
#ifndef included_vnet_mpls_h
#define included_vnet_mpls_h

#include <vnet/vnet.h>
#include <vnet/mpls/packet.h>
#include <vnet/mpls/mpls_types.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_node.h>
#include <vnet/adj/adj.h>

typedef enum {
#define mpls_error(n,s) MPLS_ERROR_##n,
#include <vnet/mpls/error.def>
#undef mpls_error
  MPLS_N_ERROR,
} mpls_error_t;

#define MPLS_FIB_DEFAULT_TABLE_ID 0

/**
 * Type exposure is to allow the DP fast/inlined access
 */
#define MPLS_FIB_KEY_SIZE 21
#define MPLS_FIB_DB_SIZE (1 << (MPLS_FIB_KEY_SIZE-1))

typedef struct mpls_fib_t_
{
  /**
   * A hash table of entries. 21 bit key
   * Hash table for reduced memory footprint
   */
  uword * mf_entries;

  /**
   * The load-balance indeices keyed by 21 bit label+eos bit.
   * A flat array for maximum lookup performace.
   */
  index_t mf_lbs[MPLS_FIB_DB_SIZE];
} mpls_fib_t;

/**
 * @brief Definition of a callback for receiving MPLS interface state change
 * notifications
 */
typedef void (*mpls_interface_state_change_callback_t)(u32 sw_if_index,
                                                       u32 is_enable);

typedef struct {
  /* MPLS FIB index for each software interface */
  u32 *fib_index_by_sw_if_index;

  /**  A pool of all the MPLS FIBs */
  struct fib_table_t_ *fibs;

  /** A hash table to lookup the mpls_fib by table ID */
  uword *fib_index_by_table_id;

  /* Feature arc indices */
  u8 input_feature_arc_index;
  u8 output_feature_arc_index;

  /* IP4 enabled count by software interface */
  u8 * mpls_enabled_by_sw_if_index;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} mpls_main_t;

extern mpls_main_t mpls_main;

extern clib_error_t * mpls_feature_init(vlib_main_t * vm);

format_function_t format_mpls_protocol;
format_function_t format_mpls_encap_index;

format_function_t format_mpls_eos_bit;
format_function_t format_mpls_unicast_header_net_byte_order;
format_function_t format_mpls_unicast_label;
format_function_t format_mpls_header;

extern vlib_node_registration_t mpls_input_node;
extern vlib_node_registration_t mpls_policy_encap_node;
extern vlib_node_registration_t mpls_output_node;
extern vlib_node_registration_t mpls_midchain_node;

/* Parse mpls protocol as 0xXXXX or protocol name.
   In either host or network byte order. */
unformat_function_t unformat_mpls_protocol_host_byte_order;
unformat_function_t unformat_mpls_protocol_net_byte_order;
unformat_function_t unformat_mpls_label_net_byte_order;
unformat_function_t unformat_mpls_unicast_label;

/* Parse mpls header. */
unformat_function_t unformat_mpls_header;
unformat_function_t unformat_pg_mpls_header;

void mpls_sw_interface_enable_disable (mpls_main_t * mm,
				       u32 sw_if_index,
				       u8 is_enable);

u8 mpls_sw_interface_is_enabled (u32 sw_if_index);

int mpls_fib_reset_labels (u32 fib_id);

#define foreach_mpls_input_next			\
_(DROP, "error-drop")                           \
_(LOOKUP, "mpls-lookup")

typedef enum {
#define _(s,n) MPLS_INPUT_NEXT_##s,
  foreach_mpls_input_next
#undef _
  MPLS_INPUT_N_NEXT,
} mpls_input_next_t;

#define foreach_mpls_lookup_next        	\
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(L2_OUTPUT, "l2-output")

// FIXME remove.
typedef enum {
#define _(s,n) MPLS_LOOKUP_NEXT_##s,
  foreach_mpls_lookup_next
#undef _
  MPLS_LOOKUP_N_NEXT,
} mpls_lookup_next_t;

#define foreach_mpls_output_next        	\
_(DROP, "error-drop")

typedef enum {
#define _(s,n) MPLS_OUTPUT_NEXT_##s,
  foreach_mpls_output_next
#undef _
  MPLS_OUTPUT_N_NEXT,
} mpls_output_next_t;

typedef struct {
  u32 fib_index;
  u32 entry_index;
  u32 dest;
  u32 s_bit;
  u32 label;
} show_mpls_fib_t;

int
mpls_dest_cmp(void * a1, void * a2);

int
mpls_fib_index_cmp(void * a1, void * a2);

int
mpls_label_cmp(void * a1, void * a2);

#endif /* included_vnet_mpls_h */
