/*
 * plugin.h: plugin handling
 *
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

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

  /* paths and name filters */
  u8 *plugin_path;
  u8 *plugin_name_filter;
  u8 *vat_plugin_path;
  u8 *vat_plugin_name_filter;

  /* plugin configs and hash by name */
  plugin_config_t *configs;
  uword *config_index_by_name;

  /* usual */
  vlib_main_t *vlib_main;
} plugin_main_t;

extern plugin_main_t vat_plugin_main;

int vat_plugin_init (vat_main_t * vam);
int vat_load_new_plugins (plugin_main_t * pm);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
