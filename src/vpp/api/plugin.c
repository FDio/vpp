/*
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
/*
 * plugin.c: plugin handling
 */

#include <vat/vat.h>
#include <vat/plugin.h>
#include <dlfcn.h>
#include <dirent.h>

plugin_main_t vat_plugin_main;

static int
load_one_vat_plugin (plugin_main_t * pm, plugin_info_t * pi)
{
  void *handle, *register_handle;
  clib_error_t *(*fp) (vat_main_t *);
  clib_error_t *error;

  handle = dlopen ((char *) pi->filename, RTLD_LAZY);

  /*
   * Note: this can happen if the plugin has an undefined symbol reference,
   * so print a warning. Otherwise, the poor slob won't know what happened.
   * Ask me how I know that...
   */
  if (handle == 0)
    {
      clib_warning ("%s", dlerror ());
      return 0;
    }

  pi->handle = handle;

  register_handle = dlsym (pi->handle, "vat_plugin_register");
  if (register_handle == 0)
    {
      clib_warning ("%s: symbol vat_plugin_register not found", pi->name);
      dlclose (handle);
      return 0;
    }

  fp = register_handle;

  error = (*fp) (pm->vat_main);

  if (error)
    {
      clib_error_report (error);
      dlclose (handle);
      return 1;
    }

  clib_warning ("Loaded plugin: %s", pi->name);

  return 0;
}

static u8 **
split_plugin_path (plugin_main_t * pm)
{
  int i;
  u8 **rv = 0;
  u8 *path = pm->plugin_path;
  u8 *this = 0;

  for (i = 0; i < vec_len (pm->plugin_path); i++)
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
vat_load_new_plugins (plugin_main_t * pm)
{
  DIR *dp;
  struct dirent *entry;
  struct stat statb;
  uword *p;
  plugin_info_t *pi;
  u8 **plugin_path;
  int i;

  plugin_path = split_plugin_path (pm);

  for (i = 0; i < vec_len (plugin_path); i++)
    {
      dp = opendir ((char *) plugin_path[i]);

      if (dp == 0)
	continue;

      while ((entry = readdir (dp)))
	{
	  u8 *plugin_name;
	  u8 *file_name;

	  if (pm->plugin_name_filter)
	    {
	      int j;
	      for (j = 0; j < vec_len (pm->plugin_name_filter); j++)
		if (entry->d_name[j] != pm->plugin_name_filter[j])
		  goto next;
	    }

	  file_name = format (0, "%s/%s%c", plugin_path[i], entry->d_name, 0);
	  plugin_name = format (0, "%s%c", entry->d_name, 0);

	  /* unreadable */
	  if (stat ((char *) file_name, &statb) < 0)
	    {
	    ignore:
	      vec_free (file_name);
	      vec_free (plugin_name);
	      continue;
	    }

	  /* a dir or other things which aren't plugins */
	  if (!S_ISREG (statb.st_mode))
	    goto ignore;

	  p = hash_get_mem (pm->plugin_by_name_hash, plugin_name);
	  if (p == 0)
	    {
	      vec_add2 (pm->plugin_info, pi, 1);
	      pi->name = plugin_name;
	      pi->filename = file_name;
	      pi->file_info = statb;

	      if (load_one_vat_plugin (pm, pi))
		{
		  vec_free (file_name);
		  vec_free (plugin_name);
		  _vec_len (pm->plugin_info) = vec_len (pm->plugin_info) - 1;
		  continue;
		}
	      memset (pi, 0, sizeof (*pi));
	      hash_set_mem (pm->plugin_by_name_hash, plugin_name,
			    pi - pm->plugin_info);
	    }
	next:
	  ;
	}
      closedir (dp);
      vec_free (plugin_path[i]);
    }
  vec_free (plugin_path);
  return 0;
}

#define QUOTE_(x) #x
#define QUOTE(x) QUOTE_(x)

/*
 * Load plugins from /usr/lib/vpp_api_test_plugins by default
 */
char *vat_plugin_path = "/usr/lib/vpp_api_test_plugins";

char *vat_plugin_name_filter = 0;

int
vat_plugin_init (vat_main_t * vam)
{
  plugin_main_t *pm = &vat_plugin_main;
  u8 *vlib_get_vat_plugin_path (void);
  u8 *vlib_get_vat_plugin_name_filter (void);
  u8 *plugin_path;
  u8 *plugin_name_filter;

  plugin_path = vlib_get_vat_plugin_path ();
  plugin_name_filter = vlib_get_vat_plugin_name_filter ();

  if (plugin_path)
    vat_plugin_path = (char *) plugin_path;

  if (plugin_name_filter)
    vat_plugin_name_filter = (char *) plugin_name_filter;

  pm->plugin_path = format (0, "%s%c", vat_plugin_path, 0);

  if (vat_plugin_name_filter)
    pm->plugin_name_filter = format (0, "%s%c", vat_plugin_name_filter, 0);

  pm->plugin_by_name_hash = hash_create_string (0, sizeof (uword));
  pm->vat_main = vam;

  return vat_load_new_plugins (pm);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
