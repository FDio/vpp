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

  /**  A pool of all the MPLS FIBs */
  struct mpls_fib_t_ *mpls_fibs;

  /** A hash table to lookup the mpls_fib by table ID */
  uword *fib_index_by_table_id;

  /* Feature arc indices */
  u8 input_feature_arc_index;
  u8 output_feature_arc_index;

  /* IP4 enabled count by software interface */
  u8 * mpls_enabled_by_sw_if_index;
} mpls_main_t;

extern mpls_main_t mpls_main;

extern clib_error_t * mpls_feature_init(vlib_main_t * vm);

format_function_t format_mpls_eos_bit;
format_function_t format_mpls_unicast_header_net_byte_order;
format_function_t format_mpls_unicast_label;
format_function_t format_mpls_header;

extern vlib_node_registration_t mpls_input_node;
extern vlib_node_registration_t mpls_output_node;
extern vlib_node_registration_t mpls_midchain_node;

/* Parse mpls protocol as 0xXXXX or protocol name.
   In either host or network byte order. */
unformat_function_t unformat_mpls_label_net_byte_order;
unformat_function_t unformat_mpls_unicast_label;

/* Parse mpls header. */
unformat_function_t unformat_mpls_header;
unformat_function_t unformat_pg_mpls_header;

int mpls_sw_interface_enable_disable (mpls_main_t * mm,
                                      u32 sw_if_index,
                                      u8 is_enable,
                                      u8 is_api);

u8 mpls_sw_interface_is_enabled (u32 sw_if_index);

int mpls_fib_reset_labels (u32 fib_id);

int
mpls_dest_cmp(void * a1, void * a2);

int
mpls_fib_index_cmp(void * a1, void * a2);

int
mpls_label_cmp(void * a1, void * a2);

void mpls_table_create(u32 table_id, u8 is_api);
void mpls_table_delete(u32 table_id, u8 is_api);

#endif /* included_vnet_mpls_h */
