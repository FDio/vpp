/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco and/or its affiliates.
 */

#ifndef SRC_VNET_SESSION_SESSION_SDL_H_
#define SRC_VNET_SESSION_SESSION_SDL_H_

#include <vnet/fib/fib_types.h>
#include <vnet/fib/fib_source.h>
#include <vnet/dpo/dpo.h>

typedef enum
{
  SESSION_SDL_CALLBACK_TABLE_CLEAN_UP,
  SESSION_SDL_CALLBACK_CONFIG_DISABLE,
} session_sdl_callback_event_t;

typedef struct session_sdl_callback_
{
  union
  {
    /* For table clean up */
    struct
    {
      u32 fib_proto;
      u32 fib_index;
    };
  };
} session_sdl_callback_t;

typedef void (*session_sdl_callback_fn_t) (int which,
					   session_sdl_callback_t *args);
typedef struct session_sdl_main
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  fib_source_t fib_src;
  dpo_type_t dpo_type;
  u8 sdl_inited;
  session_sdl_callback_fn_t *sdl_callbacks;
} session_sdl_main_t;

clib_error_t *session_sdl_enable_disable (int enable);

typedef void (*session_sdl_table_walk_fn_t) (u32 fei, ip46_address_t *lcl_ip,
					     u16 fp_len, u32 action_index,
					     u32 fb_proto, u8 *tag, void *ctx);
void session_sdl_table_walk4 (u32 srtg_handle, session_sdl_table_walk_fn_t fn,
			      void *args);
void session_sdl_table_walk6 (u32 srtg_handle, session_sdl_table_walk_fn_t fn,
			      void *args);
int session_sdl_register_callbacks (session_sdl_callback_fn_t cb);
void session_sdl_deregister_callbacks (session_sdl_callback_fn_t cb);

#endif /* SRC_VNET_SESSION_SESSION_SDL_H_ */
