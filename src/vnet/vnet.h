/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2011 Eliot Dresselhaus
 */

/* vnet.h: general networking definitions */

#ifndef included_vnet_vnet_h
#define included_vnet_vnet_h

#include <stddef.h>

#include <vppinfra/types.h>

#include <vppinfra/pcap.h>
#include <vnet/error.h>
#include <vnet/buffer.h>
#include <vnet/config.h>
#include <vnet/interface.h>
#include <vnet/api_errno.h>

/* ip table add delete callback */
typedef struct _vnet_ip_table_function_list_elt
{
  struct _vnet_ip_table_function_list_elt *next_ip_table_function;
  clib_error_t *(*fp) (struct vnet_main_t * vnm, u32 table_id, u32 flags);
} _vnet_ip_table_function_list_elt_t;

typedef struct
{
  /* Trace RX pkts */
  u8 pcap_rx_enable;
  /* Trace TX pkts */
  u8 pcap_tx_enable;
  /* Trace drop pkts */
  u8 pcap_drop_enable;
  u8 pcap_filter_enable;
  u32 max_bytes_per_pkt;
  u32 pcap_sw_if_index;
  pcap_main_t pcap_main;
  u32 filter_classify_table_index;
  vlib_is_packet_traced_fn_t *current_filter_function;
  vlib_error_t pcap_error_index;
} vnet_pcap_t;

typedef struct vnet_main_t
{
  u32 local_interface_hw_if_index;
  u32 local_interface_sw_if_index;

  vnet_interface_main_t interface_main;

  /* set up by constructors */
  vnet_device_class_t *device_class_registrations;
  vnet_hw_interface_class_t *hw_interface_class_registrations;
    _vnet_interface_function_list_elt_t
    * hw_interface_add_del_functions[VNET_ITF_FUNC_N_PRIO];
    _vnet_interface_function_list_elt_t
    * hw_interface_link_up_down_functions[VNET_ITF_FUNC_N_PRIO];
    _vnet_interface_function_list_elt_t
    * sw_interface_add_del_functions[VNET_ITF_FUNC_N_PRIO];
    _vnet_interface_function_list_elt_t
    * sw_interface_admin_up_down_functions[VNET_ITF_FUNC_N_PRIO];
    _vnet_interface_function_list_elt_t
    * sw_interface_mtu_change_functions[VNET_ITF_FUNC_N_PRIO];

  uword *interface_tag_by_sw_if_index;

    _vnet_ip_table_function_list_elt_t
    * ip_table_add_del_functions[VNET_ITF_FUNC_N_PRIO];

    /* pcap rx / tx tracing */
    vnet_pcap_t pcap;

    /*
     * Last "api" error, preserved so we can issue reasonable diagnostics
     * at or near the top of the food chain
     */
    vnet_api_error_t api_errno;

    vlib_main_t *vlib_main;
} vnet_main_t;

extern vnet_main_t vnet_main;

#include <vppinfra/pcap_funcs.h>
#include <vnet/interface_funcs.h>
#include <vnet/global_funcs.h>

#endif /* included_vnet_vnet_h */
