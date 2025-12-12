/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef __included_srv6_am_h__
#define __included_srv6_am_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/srv6/sr.h>
#include <vnet/srv6/sr_packet.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

typedef struct
{
  u16 msg_id_base;		  /**< API message ID base */

  vlib_main_t *vlib_main;	  /**< [convenience] vlib main */
  vnet_main_t *vnet_main;	  /**< [convenience] vnet main */

  dpo_type_t srv6_am_dpo_type;	  /**< DPO type */

  u32 srv6_localsid_behavior_id;  /**< SRv6 LocalSID behavior number */
} srv6_am_main_t;

/*
 * This is the memory that will be stored per each localsid
 * the user instantiates
 */
typedef struct
{
  ip46_address_t nh_addr;		/**< Proxied device address */
  u32 sw_if_index_out;					    /**< Outgoing iface to proxied device */
  u32 sw_if_index_in;					    /**< Incoming iface from proxied device */
} srv6_am_localsid_t;

extern srv6_am_main_t srv6_am_main;

format_function_t format_srv6_am_localsid;
unformat_function_t unformat_srv6_am_localsid;

void srv6_am_dpo_lock (dpo_id_t * dpo);
void srv6_am_dpo_unlock (dpo_id_t * dpo);

extern vlib_node_registration_t srv6_am_localsid_node;

#endif /* __included_srv6_am_h__ */
