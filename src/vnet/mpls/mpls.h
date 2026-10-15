/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

struct mpls_main_t;

/**
 * @brief Definition of a callback for receiving MPLS interface state change
 * notifications
 */
typedef void (mpls_interface_state_change_function_t) (struct mpls_main_t *mm,
						       uword opaque,
						       u32 sw_if_index,
						       u32 is_enable);

typedef struct mpls_main_t
{
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
  u8 *mpls_enabled_by_sw_if_index;

  u32 mpls_lookup_node_index;
  u16 msg_id_base;
} mpls_main_t;

__clib_export extern mpls_main_t mpls_main;

extern clib_error_t *mpls_feature_init (vlib_main_t * vm);

__clib_export format_function_t format_mpls_eos_bit;
format_function_t format_mpls_unicast_header_net_byte_order;
__clib_export format_function_t format_mpls_unicast_label;
format_function_t format_mpls_header;

extern vlib_node_registration_t mpls_input_node;
extern vlib_node_registration_t mpls_output_node;
extern vlib_node_registration_t mpls_midchain_node;

/* Parse mpls protocol as 0xXXXX or protocol name.
   In either host or network byte order. */
unformat_function_t unformat_mpls_label_net_byte_order;
__clib_export unformat_function_t unformat_mpls_unicast_label;

/* Parse mpls header. */
unformat_function_t unformat_mpls_header;
unformat_function_t unformat_pg_mpls_header;

__clib_export u8 mpls_sw_interface_is_enabled (u32 sw_if_index);

__clib_export void
mpls_interface_state_change_add_callback (mpls_interface_state_change_function_t *function,
					  uword opaque);

__clib_export int mpls_sw_interface_enable_disable (mpls_main_t *mm, u32 sw_if_index, u8 is_enable);

int mpls_dest_cmp (void *a1, void *a2);

int mpls_fib_index_cmp (void *a1, void *a2);

int mpls_label_cmp (void *a1, void *a2);

__clib_export void mpls_table_create (u32 table_id, u8 is_api, const u8 *name);
__clib_export void mpls_table_delete (u32 table_id, u8 is_api);

#endif /* included_vnet_mpls_h */
