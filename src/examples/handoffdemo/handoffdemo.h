
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) <current-year> <your-organization>
 */

/* handoffdemo.h - skeleton vpp engine plug-in header file */

#ifndef __included_handoffdemo_h__
#define __included_handoffdemo_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

typedef struct
{
  u32 frame_queue_index;


  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} handoffdemo_main_t;

extern handoffdemo_main_t handoffdemo_main;

extern vlib_node_registration_t handoffdemo_node_1, handoffdemo_node_2;

#endif /* __included_handoffdemo_h__ */
