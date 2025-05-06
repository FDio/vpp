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

#ifndef included_gpcapng_inlines_h
#define included_gpcapng_inlines_h

#include <stdint.h>
#include <vlib/unix/plugin.h>
#include "gpcapng_filter_api.h"

/* Method vtable */
typedef struct
{
  /* Filter registration functions */
  int (*register_filter_impl) (gpcapng_filter_impl_t *impl);
  int (*unregister_filter_impl) (const char *name);
  gpcapng_filter_impl_t *(*get_active_filter_impl) (void);
  int (*set_active_filter_impl) (const char *name);
  gpcapng_filter_impl_t *(*get_filter_impl_by_name) (const char *name);
  void (*list_filter_impls) (vlib_main_t *vm);

  /* Destination management functions */
  u32 (*find_destination_by_name) (const char *name);

  /* Interface management functions */
  uword *(*get_capture_enabled_bitmap) (void);
} gpcapng_plugin_methods_t;

typedef clib_error_t *(*gpcapng_plugin_methods_vtable_init_fn_t) (
  gpcapng_plugin_methods_t *);

#define LOAD_SYMBOL_FROM_PLUGIN_TO(p, s, st)                                  \
  ({                                                                          \
    st = vlib_get_plugin_symbol (p, #s);                                      \
    if (!st)                                                                  \
      return clib_error_return (0, "Plugin %s and/or symbol %s not found.",   \
				p, #s);                                       \
  })

#define LOAD_SYMBOL(s) LOAD_SYMBOL_FROM_PLUGIN_TO ("gpcapng_plugin.so", s, s)

static inline clib_error_t *
gpcapng_plugin_exports_init (gpcapng_plugin_methods_t *m)
{
  gpcapng_plugin_methods_vtable_init_fn_t mvi;

  LOAD_SYMBOL_FROM_PLUGIN_TO ("gpcapng_plugin.so",
			      gpcapng_plugin_methods_vtable_init, mvi);
  return (mvi (m));
}

#endif /* included_gpcapng_inlines_h */