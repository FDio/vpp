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

#define foreach_bond_mode \
  _ (0, ROUND_ROBIN, "round-robin") \
  _ (1, ACTIVE_BACKUP, "active-backup") \
  _ (2, XOR, "xor") \
  _ (3, BROADCAST, "broadcast") \
  _ (4, LACP, "lacp")

typedef enum
{
#define _(v, f, s) BOND_MODE_##f = v,
  foreach_bond_mode
#undef _
} bond_mode_t;

/* configurable load-balances */
#define foreach_bond_lb	  \
  _ (2, L23, "l23", l23)  \
  _ (1, l34 , "l34", l34) \
  _ (0, L2, "l2", l2)

/* load-balance functions implemented in bond-output */
#define foreach_bond_lb_algo			 \
  foreach_bond_lb                                \
  _ (3, RR, "round-robin", round_robin)          \
  _ (4, BC, "broadcast", broadcast)              \
  _ (5, AB, "active-backup", active_backup)

typedef enum
{
#define _(v, f, s, p) BOND_LB_##f = v,
  foreach_bond_lb_algo
#undef _
} bond_load_balance_t;

typedef struct
{
  u8 hw_addr_set;
  u8 hw_addr[6];
  u8 mode;
  u8 lb;
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
} bond_enslave_args_t;

typedef struct
{
  u32 slave;
  /* return */
  int rv;
  clib_error_t *error;
} bond_detach_slave_args_t;

typedef struct
{
  u32 flags;
  u8 admin_up;
  u8 mode;
  u8 lb;

  /* the last slave index for the rr lb */
  u32 lb_rr_last_index;

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
  u8 use_custom_mac;
  u8 hw_address[6];
} bond_if_t;

typedef struct
{
  /* pool of bonding interfaces */
  bond_if_t *interfaces;

  /* pool of lacp neighbors */
  slave_if_t *neighbors;

  /* rapidly find a neighbor by vlib software interface index */
  uword *neighbor_by_sw_if_index;

  /* rapidly find a bond by vlib software interface index */
  uword *bond_by_sw_if_index;

  /* Background process node index */
  u32 lacp_process_node_index;

  /* Packet templates for different encap types */
  vlib_packet_template_t packet_templates[LACP_N_PACKET_TEMPLATES];

  /* Packet templates for different encap types */
  vlib_packet_template_t marker_packet_templates[MARKER_N_PACKET_TEMPLATES];

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


typedef u32 (*load_balance_func) (vlib_main_t * vm,
				  vlib_node_runtime_t * node, bond_if_t * bif,
				  vlib_buffer_t * b0);

typedef struct
{
  load_balance_func load_balance;
} bond_load_balance_func_t;

extern vlib_node_registration_t bond_input_node;
extern vlib_node_registration_t bond_output_node;
extern vnet_device_class_t bond_dev_class;
extern bond_main_t bond_main;

u8 *format_bond_interface_name (u8 * s, va_list * args);

void bond_create_if (vlib_main_t * vm, bond_create_if_args_t * args);
int bond_delete_if (vlib_main_t * vm, u32 sw_if_index);
void bond_enslave (vlib_main_t * vm, bond_enslave_args_t * args);
void bond_detach_slave (vlib_main_t * vm, bond_detach_slave_args_t * args);

static inline uword
unformat_bond_mode (unformat_input_t * input, va_list * args)
{
  u8 *r = va_arg (*args, u8 *);

  if (0);
#define _(v, f, s) else if (unformat (input, s)) *r = BOND_MODE_##f;
  foreach_bond_mode
#undef _
    else
    return 0;

  return 1;
}

static inline u8 *
format_bond_mode (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v, f, s) case BOND_MODE_##f: t = (u8 *) s; break;
      foreach_bond_mode
#undef _
    default:
      return format (s, "unknown");
    }
  return format (s, "%s", t);
}

static inline uword
unformat_bond_load_balance (unformat_input_t * input, va_list * args)
{
  u8 *r = va_arg (*args, u8 *);

  if (0);
#define _(v, f, s, p) else if (unformat (input, s)) *r = BOND_LB_##f;
  foreach_bond_lb
#undef _
    else
    return 0;

  return 1;
}

static inline u8 *
format_bond_load_balance (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v, f, s, p) case BOND_LB_##f: t = (u8 *) s; break;
      foreach_bond_lb_algo
#undef _
    default:
      return format (s, "unknown");
    }
  return format (s, "%s", t);
}

#endif /* __included_vnet_bonding_node_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
