/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 * @param is_specified Has the user specified a desired instance number
 * @param user_instance The user's desired instance
 * @param parent_sw_index OUT the created parent interface
 * @param pipe_sw_if_index OUT the ends of the pipe
 */
extern int vnet_create_pipe_interface (u8 is_specified,
				       u32 user_instance,
				       u32 * parent_sw_if_index,
				       u32 pipe_sw_if_index[2]);
extern int vnet_delete_pipe_interface (u32 parent_sw_if_index);

/**
 * Get the pipe instance based on one end
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
