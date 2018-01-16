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
#ifndef __included_vnet_bonding_node_h__
#define __included_vnet_bonding_node_h__

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/format.h>
#include <vppinfra/hash.h>
#include <vnet/bonding/lacp/node.h>

#define BOND_MODE_LACP 4

typedef struct
{
  u8 hw_addr_set;
  u8 hw_addr[6];
  u8 mode;
  u32 group;
  /* return */
  u32 sw_if_index;
  int rv;
  clib_error_t *error;
} bond_create_if_args_t;

typedef struct
{
  u32 slave;
  u32 group;
  u8 is_passive;
  u8 is_long_timeout;
  /* return */
  int rv;
  clib_error_t *error;
} bond_create_slave_args_t;

typedef struct
{
  u32 flags;
  u8 admin_up;
  u32 dev_instance;
  u32 hw_if_index;
  u32 sw_if_index;

  /* Configured slaves */
  u32 *slaves;

  /* Slaves that are in DISTRIBUTING state */
  u32 *active_slaves;

  /* rapidly find an active slave */
  uword *active_slave_by_sw_if_index;

  lacp_port_info_t partner;
  lacp_port_info_t actor;
  u8 individual_aggregator;
  u8 receive_state;
  u8 transmit_state;
  u32 group;
  uword *port_number_bitmap;
  u8 hw_address[6];
} bond_if_t;

typedef struct
{
  /* pool of bonding interfaces */
  bond_if_t *interfaces;

  /* pool of lacp neighbors */
  slave_if_t *neighbors;

  /* tx pcap debug enable */
  u8 tx_pcap_debug;

  /* rapidly find a neighbor by vlib software interface index */
  uword *neighbor_by_sw_if_index;

  /* Background process node index */
  u32 lacp_process_node_index;

  /* Packet templates for different encap types */
  vlib_packet_template_t packet_templates[LACP_N_PACKET_TEMPLATES];

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* debug is on or off */
  u8 debug;

  /* rapidly find a bond interface group id */
  uword *dev_instance_by_group_id;
} bond_main_t;

/* bond packet trace capture */
typedef struct
{
  ethernet_header_t ethernet;
  u32 sw_if_index;
  u32 bond_sw_if_index;
} bond_packet_trace_t;

extern vlib_node_registration_t bond_input_node;
extern vlib_node_registration_t bond_output_node;
extern vnet_device_class_t bond_dev_class;
extern bond_main_t bond_main;

void lacp_send_lacp_pdu (bond_main_t * bm, slave_if_t * sif, int count);
u8 *format_bond_interface_name (u8 * s, va_list * args);

#endif /* __included_vnet_bonding_node_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
