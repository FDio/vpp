/*
 * plugin.c: plugin handling
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

#include <vlib/unix/plugin.h>
#include <dlfcn.h>
#include <dirent.h>

plugin_main_t vlib_plugin_main;

void
vlib_set_get_handoff_structure_cb (void *cb)
{
  plugin_main_t *pm = &vlib_plugin_main;
  pm->handoff_structure_get_cb = cb;
}

static void *
vnet_get_handoff_structure (void)
{
  void *(*fp) (void);

  fp = vlib_plugin_main.handoff_structure_get_cb;
  if (fp == 0)
    return 0;
  else
    return (*fp) ();
}

static int
load_one_plugin (plugin_main_t * pm, plugin_info_t * pi, int from_early_init)
{
  void *handle, *register_handle;
  clib_error_t *(*fp) (vlib_main_t *, void *, int);
  clib_error_t *error;
  void *handoff_structure;

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


  register_handle = dlsym (pi->handle, "vlib_plugin_register");
  if (register_handle == 0)
    {
      dlclose (handle);
      clib_warning ("Plugin missing vlib_plugin_register: %s\n",
		    (char *) pi->name);
      return 1;
    }

  fp = register_handle;

  handoff_structure = vnet_get_handoff_structure ();

  if (handoff_structure == 0)
    error = clib_error_return (0, "handoff structure callback returned 0");
  else
    error = (*fp) (pm->vlib_main, handoff_structure, from_early_init);

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
vlib_load_new_plugins (plugin_main_t * pm, int from_early_init)
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

	  if (pm->plugin_name_filter)
	    {
	      int j;
	      for (j = 0; j < vec_len (pm->plugin_name_filter); j++)
		if (entry->d_name[j] != pm->plugin_name_filter[j])
		  goto next;
	    }

	  plugin_name = format (0, "%s/%s%c", plugin_path[i],
				entry->d_name, 0);

	  /* Only accept .so */
	  char *ext = strrchr ((const char *) plugin_name, '.');
	  /* unreadable */
	  if (!ext || (strcmp (ext, ".so") != 0) ||
	      stat ((char *) plugin_name, &statb) < 0)
	    {
	    ignore:
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
	      pi->file_info = statb;

	      if (load_one_plugin (pm, pi, from_early_init))
		{
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

char *vlib_plugin_path __attribute__ ((weak));
char *vlib_plugin_path = "";
char *vlib_plugin_name_filter __attribute__ ((weak));
char *vlib_plugin_name_filter = 0;

int
vlib_plugin_early_init (vlib_main_t * vm)
{
  plugin_main_t *pm = &vlib_plugin_main;

  pm->plugin_path = format (0, "%s%c", vlib_plugin_path, 0);

  clib_warning ("plugin path %s", pm->plugin_path);

  if (vlib_plugin_name_filter)
    pm->plugin_name_filter = format (0, "%s%c", vlib_plugin_name_filter, 0);

  pm->plugin_by_name_hash = hash_create_string (0, sizeof (uword));
  pm->vlib_main = vm;

  return vlib_load_new_plugins (pm, 1 /* from_early_init */ );
}

static clib_error_t *
vlib_plugins_show_cmd_fn (vlib_main_t * vm,
                      unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  plugin_main_t *pm = &vlib_plugin_main;
  u8 *s = 0;
  u8 *key = 0;
  uword *value = 0;
  int index = 1;

  s = format(s, " Plugin path is: %s\n",pm->plugin_path);
  if (vlib_plugin_name_filter)
    s = format(s," Plugin filter: %s\n",vlib_plugin_name_filter);

  s = format(s, " Plugins loaded: \n");
  hash_foreach_mem (key, value, pm->plugin_by_name_hash, {
      if (key != 0)
        s = format(s, "  %d.%s\n",index, key);
      index++;
    });

  vlib_cli_output(vm, "%v", s);
  vec_free(s);
  return 0;
}

VLIB_CLI_COMMAND (plugins_show_cmd, static) = {
  .path = "show plugins",
  .short_help = "show loaded plugins",
  .function = vlib_plugins_show_cmd_fn,
};
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
