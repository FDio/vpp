/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __click_click_h__
#define __click_click_h__

#include <vlib/vlib.h>
#include <click/vppclick.h>

typedef struct
{
  vppclick_ctx_t *ctx;
  f64 last_run;
  u32 internal_node_index;
  u32 input_node_index;
} click_instance_t;

typedef struct
{
  vppclick_pkt_queue_t *to_vpp;
  vppclick_pkt_queue_t *from_vpp;
  u32 instance_index;
} click_interface_t;

typedef struct
{
  click_instance_t *instances;
  click_interface_t *interfaces;
} click_main_t;

extern click_main_t click_main;
extern vlib_node_registration_t click_node;
extern vlib_node_registration_t click_input_node;

typedef struct
{
  u8 *name;
  u8 *router_file;

  /* return */
  u32 index;
} click_instance_create_args_t;

clib_error_t *click_instance_create (vlib_main_t *,
				     click_instance_create_args_t *);

#endif /* __click_click_h__ */
