/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#ifndef _vnet_tcp_sdl_h_
#define _vnet_tcp_sdl_h_

typedef struct _auto_sdl_track_prefix_args
{
  fib_prefix_t prefix;
  u8 *tag;
  u32 action_index;
  u32 fib_index;
} auto_sdl_track_prefix_args_t;

typedef int (*tcp_sdl_cb_fn_t) (auto_sdl_track_prefix_args_t *args);
extern void tcp_sdl_enable_disable (tcp_sdl_cb_fn_t fp);

#endif /* _vnet_tcp_sdl_h_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
