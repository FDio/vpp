/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#ifndef __AUTO_SDL_H__
#define __AUTO_SDL_H__

#include <vlib/unix/plugin.h>
#include <vnet/fib/fib_types.h>
#include <vnet/dpo/dpo.h>
#include <vppinfra/tw_timer_4t_3w_256sl.h>

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

#define AUTO_SDL_REMOVE_TIMEOUT 300 /* 5 minutes */
#define AUTO_SDL_THRESHOLD	5   /* 5 times */

typedef struct auto_sdl_per_fib_
{
  uword *auto_sdl_fib_pool;
} auto_sdl_per_fib_t;

typedef struct auto_sdl_main
{
  u32 remove_timeout;
  u32 threshold;
  auto_sdl_mapping_t *auto_sdl_pool;
  clib_spinlock_t spinlock;
  TWT (tw_timer_wheel) tw_wheel;
  u32 pid;
  auto_sdl_per_fib_t *asdl_pool;
  u8 inited;
  u8 auto_sdl_enable;
} auto_sdl_main_t;

typedef struct _auto_sdl_config_args_t
{
  u32 threshold;
  u32 remove_timeout;
  i8 enable;
} auto_sdl_config_args_t;

clib_error_t *auto_sdl_config (auto_sdl_config_args_t *args);

typedef uword (*auto_sdl_pool_size_fn_t) (void);
typedef int (*auto_sdl_track_prefix_fn_t) (auto_sdl_track_prefix_args_t *args);
typedef clib_error_t *(*auto_sdl_config_fn_t) (auto_sdl_config_args_t *args);

#define foreach_auto_sdl_plugin_exported_method_name                          \
  _ (track_prefix)                                                            \
  _ (pool_size)                                                               \
  _ (config)

#define _(name) auto_sdl_##name##_fn_t name;
typedef struct
{
  void *p_asdl_main;
  foreach_auto_sdl_plugin_exported_method_name
} auto_sdl_plugin_methods_t;
#undef _

#define AUTO_SDL_LOAD_SYMBOL_FROM_PLUGIN_TO(p, s, st)                         \
  ({                                                                          \
    st = vlib_get_plugin_symbol (p, #s);                                      \
    if (!st)                                                                  \
      return clib_error_return (0, "Plugin %s and/or symbol %s not found.",   \
				p, #s);                                       \
  })

typedef clib_error_t *(*auto_sdl_plugin_methods_vtable_init_fn_t) (
  auto_sdl_plugin_methods_t *m);

__clib_export clib_error_t *
auto_sdl_plugin_methods_vtable_init (auto_sdl_plugin_methods_t *m);

static inline clib_error_t *
auto_sdl_plugin_exports_init (auto_sdl_plugin_methods_t *m)
{
  auto_sdl_plugin_methods_vtable_init_fn_t mvi;

  AUTO_SDL_LOAD_SYMBOL_FROM_PLUGIN_TO (
    "auto_sdl_plugin.so", auto_sdl_plugin_methods_vtable_init, mvi);

  return (mvi (m));
}

#endif /* __AUTO_SDL_H__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
