/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

/* plugin.h: plugin handling */

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
