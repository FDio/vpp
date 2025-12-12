/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <dlfcn.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vlib/vlib.h>
#include "vat2.h"

typedef struct
{
  u8 *name;
  u8 *filename;
  struct stat file_info;
  void *handle;
} plugin_info_t;

/* loaded plugin info */
plugin_info_t *plugin_info;

static int
load_one_plugin (plugin_info_t * pi)
{
  void *handle, *register_handle;
  clib_error_t *(*fp) (void);
  clib_error_t *error;

  handle = dlopen ((char *) pi->name, RTLD_LAZY);

  /*
   * Note: this can happen if the plugin has an undefined symbol reference,
   * so print a warning. Otherwise, the poor slob won't know what happened.
   * Ask me how I know that...
   */
  if (handle == 0)
    {
      clib_warning ("%s", dlerror ());
      return -1;
    }

  pi->handle = handle;

  register_handle = dlsym (pi->handle, "vat2_register_plugin");
  if (register_handle == 0)
    {
      clib_warning ("%s: symbol vat2_register_plugin not found", pi->name);
      dlclose (handle);
      return -1;
    }

  fp = register_handle;

  error = (*fp) ();

  if (error)
    {
      clib_error_report (error);
      dlclose (handle);
      return -1;
    }

  return 0;
}

/* Takes a vector as argument */
static u8 **
split_plugin_path (u8 *plugin_path)
{
  int i;
  u8 **rv = 0;
  u8 *path = (u8 *) plugin_path;
  u8 *this = 0;

  for (i = 0; i < vec_len (plugin_path); i++)
    {
      if (path[i] != ':')
	{
	  vec_add1 (this, path[i]);
	  continue;
	}
      vec_add1 (this, 0);
      vec_add1 (rv, this);
      this = 0;
    }
  if (this)
    {
      vec_add1 (this, 0);
      vec_add1 (rv, this);
    }
  return rv;
}

int
vat2_load_plugins (u8 *path, char *filter, int *loaded)
{
  DIR *dp;
  struct dirent *entry;
  struct stat statb;
  uword *p;
  plugin_info_t *pi;
  u8 **plugin_path;
  int i;
  int res = 0;
  uword *plugin_by_name_hash = hash_create_string (0, sizeof (uword));

  *loaded = 0;
  plugin_path = split_plugin_path (path);

  for (i = 0; i < vec_len (plugin_path); i++)
    {
      DBG ("Opening path: %s\n", plugin_path[i]);
      dp = opendir ((char *) plugin_path[i]);

      if (dp == 0)
	continue;

      while ((entry = readdir (dp)))
	{
	  u8 *plugin_name;

	  if (filter)
	    {
	      int j;
	      for (j = 0; j < vec_len (filter); j++)
		if (entry->d_name[j] != filter[j])
		  goto next;
	    }

	  plugin_name = format (0, "%s/%s%c", plugin_path[i],
				entry->d_name, 0);

	  /* unreadable */
	  if (stat ((char *) plugin_name, &statb) < 0)
	    {
	    ignore:
	      vec_free (plugin_name);
	      continue;
	    }

	  /* a dir or other things which aren't plugins */
	  if (!S_ISREG (statb.st_mode))
	    goto ignore;

	  p = hash_get_mem (plugin_by_name_hash, plugin_name);
	  if (p == 0)
	    {
	      vec_add2 (plugin_info, pi, 1);
	      pi->name = plugin_name;
	      pi->file_info = statb;

	      if (load_one_plugin (pi))
		{
		  res = -1;
		  vec_free (plugin_name);
		  vec_set_len (plugin_info, vec_len (plugin_info) - 1);
		  continue;
		}
	      clib_memset (pi, 0, sizeof (*pi));
	      hash_set_mem (plugin_by_name_hash, plugin_name,
			    pi - plugin_info);
	      *loaded = *loaded + 1;
	    }
	next:
	  ;
	}
      closedir (dp);
      vec_free (plugin_path[i]);
    }
  vec_free (plugin_path);
  return res;
}

#define QUOTE_(x) #x
#define QUOTE(x)  QUOTE_ (x)
