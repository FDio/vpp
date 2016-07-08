/*
 * plugin.h: plugin handling
 *
 * Copyright (c) 2011 Cisco and/or its affiliates.
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

#ifndef __included_plugin_h__
#define __included_plugin_h__

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * vlib plugin scheme
 *
 * Almost anything which can be made to work in a vlib unix
 * application will also work in a vlib plugin.
 *
 * The elf-section magic which registers static objects
 * works so long as plugins are preset when the vlib unix process
 * starts. But wait: there's more...
 *
 * If an application calls vlib_load_new_plugins() -- possibly after
 * changing vlib_plugin_main.plugin_path / vlib_plugin_main.plugin_name_filter,
 * -- new plugins will be loaded. That, in turn, allows considerable
 * flexibility in terms of adding feature code or fixing bugs without
 * requiring the data-plane process to restart.
 *
 * When the plugin mechanism loads a plugin, it uses dlsym to locate
 * and call the plugin's function vlib_plugin_register() if it exists.
 * A plugin which expects to be loaded after the vlib application
 * starts uses this callback to modify the application. If vlib_plugin_register
 * returns non-zero, the plugin mechanism dlclose()'s the plugin.
 *
 * Applications control the plugin search path and name filter by
 * declaring the variables vlib_plugin_path and vlib_plugin_name_filter.
 * libvlib_unix.la supplies weak references for these symbols which
 * effectively disable the scheme. In order for the elf-section magic to
 * work, static plugins must be loaded at the earliest possible moment.
 *
 * An application can change these parameters at any time and call
 * vlib_load_new_plugins().
 */



typedef struct
{
  u8 *name;
  struct stat file_info;
  void *handle;
} plugin_info_t;

typedef struct
{
  /* loaded plugin info */
  plugin_info_t *plugin_info;
  uword *plugin_by_name_hash;

  /* path and name filter */
  u8 *plugin_path;
  u8 *plugin_name_filter;

  /* handoff structure get callback */
  void *handoff_structure_get_cb;

  /* usual */
  vlib_main_t *vlib_main;
} plugin_main_t;

plugin_main_t vlib_plugin_main;

int vlib_plugin_early_init (vlib_main_t * vm);
int vlib_load_new_plugins (plugin_main_t * pm, int from_early_init);

#endif /* __included_plugin_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
