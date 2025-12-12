
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 by Cisco and/or its affiliates.
 */

/* oddbuf.h - awkward chained buffer geometry test tool */

#ifndef __included_oddbuf_h__
#define __included_oddbuf_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* on/off switch for the periodic function */
  u8 periodic_timer_enabled;

  /* config parameters */
  int n_to_copy;
  int second_chunk_offset;
  int first_chunk_offset;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} oddbuf_main_t;

extern oddbuf_main_t oddbuf_main;

extern vlib_node_registration_t oddbuf_node;

#endif /* __included_oddbuf_h__ */
