/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef __PIPE_H__
#define __PIPE_H__

#include <vnet/ethernet/ethernet.h>

/**
 * representation of a pipe interface
 */
typedef struct pipe_t_
{
  /** the SW if_index of the other end of the pipe */
  u32 sw_if_index;

  /** Sub-interface config */
  subint_config_t subint;
} pipe_t;

/**
 * Create a new pipe interface
 *
 * @param is_specified Has the user speficied a desired instance number
 * @param user_instance The user's desired instnace
 * @param parent_sw_index OUT the created parent interface
 * @param pipe_sw_if_index OUT the ends of the pipe
 */
extern int vnet_create_pipe_interface (u8 is_specified,
				       u32 user_instance,
				       u32 * parent_sw_if_index,
				       u32 pipe_sw_if_index[2]);
extern int vnet_delete_pipe_interface (u32 parent_sw_if_index);

/**
 * Get the pipe instnace based on one end
 */
extern pipe_t *pipe_get (u32 sw_if_index);

/**
 * Call back function when walking all the pipes
 */
typedef walk_rc_t (*pipe_cb_fn_t) (u32 parent_sw_if_index,
				   u32 pipe_sw_if_index[2],
				   u32 instance, void *ctx);

/**
 * Walk all the of pipe interfaces
 */
extern void pipe_walk (pipe_cb_fn_t fn, void *ctx);

#endif
