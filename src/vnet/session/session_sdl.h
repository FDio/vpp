/*
 * Copyright (c) 2024 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_SESSION_SESSION_SDL_H_
#define SRC_VNET_SESSION_SESSION_SDL_H_

#include <vnet/fib/fib_types.h>
#include <vnet/fib/fib_source.h>
#include <vnet/dpo/dpo.h>
#include <vppinfra/tw_timer_4t_3w_256sl.h>
#include <vnet/tcp/tcp_sdl.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  fib_prefix_t prefix;
  u32 action_index;
  u32 fib_index;
  u8 *tag;

  u32 last_updated;
  u32 tw_handle;
  u32 counter;
  u8 sdl_added;
} auto_sdl_mapping_t;

#define SESSION_AUTO_SDL_REMOVE_TIMEOUT 300 /* 5 minutes */
#define SESSION_AUTO_SDL_THRESHOLD	5   /* 5 times */

typedef struct session_asdl_per_fib_
{
  uword *auto_sdl_fib_pool;
} session_asdl_per_fib_t;

typedef struct session_auto_sdl_block
{
  u32 remove_timeout;
  u32 threshold;
  auto_sdl_mapping_t *auto_sdl_pool;
  clib_spinlock_t spinlock;
  TWT (tw_timer_wheel) tw_wheel;
  u32 pid;
  u8 auto_sdl_enable;
  session_asdl_per_fib_t *asdl_pool;
} session_auto_sdl_block_t;

typedef struct session_sdl_main
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  fib_source_t fib_src;
  dpo_type_t dpo_type;
  u8 sdl_inited;
  session_auto_sdl_block_t auto_sdl;
} session_sdl_main_t;

typedef struct _session_auto_sdl_config_args_t
{
  u32 threshold;
  u32 remove_timeout;
  i8 enable;
} session_auto_sdl_config_args_t;

u32 session_auto_sdl_pool_size (void);
clib_error_t *session_auto_sdl_config (session_auto_sdl_config_args_t *args);
clib_error_t *session_sdl_enable_disable (int enable);

typedef void (*session_sdl_table_walk_fn_t) (u32 fei, ip46_address_t *lcl_ip,
					     u16 fp_len, u32 action_index,
					     u32 fb_proto, u8 *tag, void *ctx);
void session_sdl_table_walk4 (u32 srtg_handle, session_sdl_table_walk_fn_t fn,
			      void *args);
void session_sdl_table_walk6 (u32 srtg_handle, session_sdl_table_walk_fn_t fn,
			      void *args);
int session_auto_sdl_track_prefix (session_auto_sdl_track_prefix_args_t *args);

#endif /* SRC_VNET_SESSION_SESSION_SDL_H_ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
