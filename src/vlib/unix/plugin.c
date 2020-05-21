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
#include <vppinfra/elf.h>
#include <dlfcn.h>
#include <dirent.h>

plugin_main_t vlib_plugin_main;

#define PLUGIN_LOG_DBG(...) \
  do {vlib_log_debug (vlib_plugin_main.logger, __VA_ARGS__);} while(0)
#define PLUGIN_LOG_ERR(...) \
  do {vlib_log_err (vlib_plugin_main.logger, __VA_ARGS__);} while(0)
#define PLUGIN_LOG_NOTICE(...) \
  do {vlib_log_notice (vlib_plugin_main.logger, __VA_ARGS__);} while(0)

char *vlib_plugin_path __attribute__ ((weak));
char *vlib_plugin_path = "";
char *vlib_plugin_app_version __attribute__ ((weak));
char *vlib_plugin_app_version = "";

void *
vlib_get_plugin_symbol (char *plugin_name, char *symbol_name)
{
  plugin_main_t *pm = &vlib_plugin_main;
  uword *p;
  plugin_info_t *pi;

  if ((p = hash_get_mem (pm->plugin_by_name_hash, plugin_name)) == 0)
    return 0;

  pi = vec_elt_at_index (pm->plugin_info, p[0]);
  return dlsym (pi->handle, symbol_name);
}

static char *
str_array_to_vec (char *array, int len)
{
  char c, *r = 0;
  int n = 0;

  do
    {
      c = array[n];
      vec_add1 (r, c);
    }
  while (c && ++n < len);

  if (c)
    vec_add1 (r, 0);

  return r;
}

static u8 *
extract (u8 * sp, u8 * ep)
{
  u8 *rv = 0;

  while (sp <= ep)
    {
      vec_add1 (rv, *sp);
      sp++;
    }
  vec_add1 (rv, 0);
  return rv;
}

static int
load_one_plugin (plugin_main_t * pm, plugin_info_t * pi, int from_early_init)
{
  void *handle;
  clib_error_t *error;
  elf_main_t em = { 0 };
  elf_section_t *section;
  u8 *data;
  char *version_required;
  vlib_plugin_registration_t *reg;
  plugin_config_t *pc = 0;
  uword *p;

  if (elf_read_file (&em, (char *) pi->filename))
    return -1;

  error = elf_get_section_by_name (&em, ".vlib_plugin_registration",
				   &section);
  if (error)
    {
      PLUGIN_LOG_ERR ("Not a plugin: %s\n", (char *) pi->name);
      return -1;
    }

  data = elf_get_section_contents (&em, section->index, 1);
  reg = (vlib_plugin_registration_t *) data;

#ifndef CLIB_SANITIZE_ADDR
  if (vec_len (data) != sizeof (*reg))
    {
      PLUGIN_LOG_ERR ("vlib_plugin_registration size mismatch in plugin %s\n",
		      (char *) pi->name);
      goto error;
    }
#endif

  if (pm->plugins_default_disable)
    reg->default_disabled = 1;

  p = hash_get_mem (pm->config_index_by_name, pi->name);
  if (p)
    {
      pc = vec_elt_at_index (pm->configs, p[0]);
      if (pc->is_disabled)
	{
	  PLUGIN_LOG_NOTICE ("Plugin disabled: %s", pi->name);
	  goto error;
	}
      if (reg->default_disabled && pc->is_enabled == 0)
	{
	  PLUGIN_LOG_NOTICE ("Plugin disabled (default): %s", pi->name);
	  goto error;
	}
    }
  else if (reg->default_disabled)
    {
      PLUGIN_LOG_NOTICE ("Plugin disabled (default): %s", pi->name);
      goto error;
    }

  version_required = str_array_to_vec ((char *) &reg->version_required,
				       sizeof (reg->version_required));

  if ((strlen (version_required) > 0) &&
      (strncmp (vlib_plugin_app_version, version_required,
		strlen (version_required))))
    {
      PLUGIN_LOG_ERR ("Plugin %s version mismatch: %s != %s",
		      pi->name, vlib_plugin_app_version,
		      reg->version_required);
      if (!(pc && pc->skip_version_check == 1))
	{
	  vec_free (version_required);
	  goto error;
	}
    }

  /*
   * Collect names of plugins overridden (disabled) by the
   * current plugin.
   */
  if (reg->overrides[0])
    {
      const char *overrides = reg->overrides;
      u8 *override_name_copy, *overridden_by_name_copy;
      u8 *sp, *ep;
      uword *p;

      sp = ep = (u8 *) overrides;

      while (1)
	{
	  if (*sp == 0
	      || (sp >= (u8 *) overrides + ARRAY_LEN (reg->overrides)))
	    break;
	  if (*sp == ' ' || *sp == ',')
	    {
	      sp++;
	      continue;
	    }
	  ep = sp;
	  while (*ep && *ep != ' ' && *ep != ',' &&
		 ep < (u8 *) overrides + ARRAY_LEN (reg->overrides))
	    ep++;
	  if (*ep == ' ' || *ep == ',')
	    ep--;

	  override_name_copy = extract (sp, ep);


	  p = hash_get_mem (pm->plugin_overrides_by_name_hash,
			    override_name_copy);
	  /* Already overridden... */
	  if (p)
	    vec_free (override_name_copy);
	  else
	    {
	      overridden_by_name_copy = format (0, "%s%c", pi->name, 0);
	      hash_set_mem (pm->plugin_overrides_by_name_hash,
			    override_name_copy, overridden_by_name_copy);
	    }
	  sp = *ep ? ep + 1 : ep;
	}
    }
  vec_free (version_required);

  handle = dlopen ((char *) pi->filename, RTLD_LAZY);

  if (handle == 0)
    {
      PLUGIN_LOG_ERR ("%s", dlerror ());
      PLUGIN_LOG_ERR ("Failed to load plugin '%s'", pi->name);
      goto error;
    }

  pi->handle = handle;

  reg = dlsym (pi->handle, "vlib_plugin_registration");

  if (reg == 0)
    {
      /* This should never happen unless somebody changes registration macro */
      PLUGIN_LOG_ERR ("Missing plugin registration in plugin '%s'", pi->name);
      dlclose (pi->handle);
      goto error;
    }

  pi->reg = reg;
  pi->version = str_array_to_vec ((char *) &reg->version,
				  sizeof (reg->version));

  if (reg->early_init)
    {
      clib_error_t *(*ei) (vlib_main_t *);
      void *h;

      h = dlsym (pi->handle, reg->early_init);
      if (h)
	{
	  ei = h;
	  error = (*ei) (pm->vlib_main);
	  if (error)
	    {
	      u8 *err = format (0, "%s: %U%c", pi->name,
				format_clib_error, error, 0);
	      PLUGIN_LOG_ERR ((char *) err);
	      clib_error_free (error);
	      dlclose (pi->handle);
	      pi->handle = 0;
	      goto error;
	    }
	}
      else
	PLUGIN_LOG_ERR ("Plugin %s: early init function %s set but not found",
			(char *) pi->name, reg->early_init);
    }

  if (reg->description)
    PLUGIN_LOG_NOTICE ("Loaded plugin: %s (%s)", pi->name, reg->description);
  else
    PLUGIN_LOG_NOTICE ("Loaded plugin: %s", pi->name);

  vec_free (data);
  elf_main_free (&em);
  return 0;

error:
  vec_free (data);
  elf_main_free (&em);
  return -1;
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

static int
plugin_name_sort_cmp (void *a1, void *a2)
{
  plugin_info_t *p1 = a1;
  plugin_info_t *p2 = a2;

  return strcmp ((char *) p1->name, (char *) p2->name);
}

static int
index_cmp (void *a1, void *a2)
{
  uword *i1 = (uword *) a1, *i2 = (uword *) a2;

  if (*i1 < *i2)
    return -1;
  else if (*i1 > *i2)
    return 1;
  else
    return 0;
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
  uword *not_loaded_indices = 0;
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
	  u8 *filename;

	  if (pm->plugin_name_filter)
	    {
	      int j;
	      for (j = 0; j < vec_len (pm->plugin_name_filter); j++)
		if (entry->d_name[j] != pm->plugin_name_filter[j])
		  goto next;
	    }

	  filename = format (0, "%s/%s%c", plugin_path[i], entry->d_name, 0);

	  /* Only accept .so */
	  char *ext = strrchr ((const char *) filename, '.');
	  /* unreadable */
	  if (!ext || (strcmp (ext, ".so") != 0) ||
	      stat ((char *) filename, &statb) < 0)
	    {
	    ignore:
	      vec_free (filename);
	      continue;
	    }

	  /* a dir or other things which aren't plugins */
	  if (!S_ISREG (statb.st_mode))
	    goto ignore;

	  plugin_name = format (0, "%s%c", entry->d_name, 0);
	  /* Have we seen this plugin already? */
	  p = hash_get_mem (pm->plugin_by_name_hash, plugin_name);
	  if (p == 0)
	    {
	      /* No, add it to the plugin vector */
	      vec_add2 (pm->plugin_info, pi, 1);
	      pi->name = plugin_name;
	      pi->filename = filename;
	      pi->file_info = statb;
	      pi->handle = 0;
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


  /*
   * Sort the plugins by name. This is important.
   * API traces contain absolute message numbers.
   * Loading plugins in directory (vs. alphabetical) order
   * makes trace replay incredibly fragile.
   */
  vec_sort_with_function (pm->plugin_info, plugin_name_sort_cmp);

  /*
   * Attempt to load the plugins
   */
  for (i = 0; i < vec_len (pm->plugin_info); i++)
    {
      pi = vec_elt_at_index (pm->plugin_info, i);

      if (load_one_plugin (pm, pi, from_early_init))
	{
	  /* Make a note of any which fail to load */
	  vec_add1 (not_loaded_indices, i);
	}
    }

  /*
   * Honor override list
   */
  for (i = 0; i < vec_len (pm->plugin_info); i++)
    {
      uword *p;

      pi = vec_elt_at_index (pm->plugin_info, i);

      p = hash_get_mem (pm->plugin_overrides_by_name_hash, pi->name);

      /* Plugin overridden? */
      if (p)
	{
	  PLUGIN_LOG_NOTICE ("Plugin '%s' overridden by '%s'", pi->name,
			     p[0]);
	  vec_add1 (not_loaded_indices, i);
	}
    }

  /*
   * Sort the vector of indices to delete to avoid screwing up
   * the indices as we delete them.
   */
  vec_sort_with_function (not_loaded_indices, index_cmp);

  /*
   * Remove duplicates, which can happen if a plugin is
   * disabled from the command line and disabled by
   * a plugin which is loaded.
   */
  for (i = 0; i < vec_len (not_loaded_indices); i++)
    {
      if (i < vec_len (not_loaded_indices) - 1)
	{
	  if (not_loaded_indices[i + 1] == not_loaded_indices[i])
	    {
	      vec_delete (not_loaded_indices, 1, i);
	      i--;
	    }
	}
    }

  /* Remove plugin info vector elements corresponding to load failures */
  if (vec_len (not_loaded_indices) > 0)
    {
      for (i = vec_len (not_loaded_indices) - 1; i >= 0; i--)
	{
	  pi = vec_elt_at_index (pm->plugin_info, not_loaded_indices[i]);
	  hash_unset_mem (pm->plugin_by_name_hash, pi->name);
	  if (pi->handle)
	    {
	      dlclose (pi->handle);
	      PLUGIN_LOG_NOTICE ("Unloaded plugin: %s", pi->name);
	    }
	  vec_free (pi->name);
	  vec_free (pi->filename);
	  vec_delete (pm->plugin_info, 1, not_loaded_indices[i]);
	}
      vec_free (not_loaded_indices);
    }

  /* Recreate the plugin name hash */
  hash_free (pm->plugin_by_name_hash);
  pm->plugin_by_name_hash = hash_create_string (0, sizeof (uword));

  for (i = 0; i < vec_len (pm->plugin_info); i++)
    {
      pi = vec_elt_at_index (pm->plugin_info, i);
      hash_set_mem (pm->plugin_by_name_hash, pi->name, pi - pm->plugin_info);
    }

  return 0;
}

int
vlib_plugin_early_init (vlib_main_t * vm)
{
  plugin_main_t *pm = &vlib_plugin_main;

  pm->logger =
    vlib_log_register_class_rate_limit ("plugin", "load",
					0x7FFFFFFF /* aka no rate limit */ );

  if (pm->plugin_path == 0)
    pm->plugin_path = format (0, "%s%c", vlib_plugin_path, 0);

  PLUGIN_LOG_DBG ("plugin path %s", pm->plugin_path);

  pm->plugin_by_name_hash = hash_create_string (0, sizeof (uword));
  pm->plugin_overrides_by_name_hash = hash_create_string (0, sizeof (uword));
  pm->vlib_main = vm;

  return vlib_load_new_plugins (pm, 1 /* from_early_init */ );
}

u8 *
vlib_get_vat_plugin_path (void)
{
  plugin_main_t *pm = &vlib_plugin_main;
  return (pm->vat_plugin_path);
}

u8 *
vlib_get_vat_plugin_name_filter (void)
{
  plugin_main_t *pm = &vlib_plugin_main;
  return (pm->vat_plugin_name_filter);
}

static clib_error_t *
vlib_plugins_show_cmd_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  plugin_main_t *pm = &vlib_plugin_main;
  u8 *s = 0;
  u8 *key = 0;
  uword value = 0;
  int index = 1;
  plugin_info_t *pi;

  s = format (s, " Plugin path is: %s\n\n", pm->plugin_path);
  s = format (s, "     %-41s%-33s%s\n", "Plugin", "Version", "Description");

  /* *INDENT-OFF* */
  hash_foreach_mem (key, value, pm->plugin_by_name_hash,
    {
      if (key != 0)
        {
          pi = vec_elt_at_index (pm->plugin_info, value);
          s = format (s, "%3d. %-40s %-32s %s\n", index, key, pi->version,
		      (pi->reg && pi->reg->description) ?
                      pi->reg->description : "");
	  index++;
        }
    });
  /* *INDENT-ON* */

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (plugins_show_cmd, static) =
{
  .path = "show plugins",
  .short_help = "show loaded plugins",
  .function = vlib_plugins_show_cmd_fn,
};
/* *INDENT-ON* */

static clib_error_t *
config_one_plugin (vlib_main_t * vm, char *name, unformat_input_t * input)
{
  plugin_main_t *pm = &vlib_plugin_main;
  plugin_config_t *pc;
  clib_error_t *error = 0;
  uword *p;
  int is_enable = 0;
  int is_disable = 0;
  int skip_version_check = 0;

  if (pm->config_index_by_name == 0)
    pm->config_index_by_name = hash_create_string (0, sizeof (uword));

  p = hash_get_mem (pm->config_index_by_name, name);

  if (p)
    {
      error = clib_error_return (0, "plugin '%s' already configured", name);
      goto done;
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	is_enable = 1;
      else if (unformat (input, "disable"))
	is_disable = 1;
      else if (unformat (input, "skip-version-check"))
	skip_version_check = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (is_enable && is_disable)
    {
      error = clib_error_return (0, "please specify either enable or disable"
				 " for plugin '%s'", name);
      goto done;
    }

  vec_add2 (pm->configs, pc, 1);
  hash_set_mem (pm->config_index_by_name, name, pc - pm->configs);
  pc->is_enabled = is_enable;
  pc->is_disabled = is_disable;
  pc->skip_version_check = skip_version_check;
  pc->name = name;

done:
  return error;
}

clib_error_t *
vlib_plugin_config (vlib_main_t * vm, unformat_input_t * input)
{
  plugin_main_t *pm = &vlib_plugin_main;
  clib_error_t *error = 0;
  unformat_input_t in;

  unformat_init (&in, 0, 0);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      u8 *s, *v;
      if (unformat (input, "%s %v", &s, &v))
	{
	  if (strncmp ((const char *) s, "plugins", 8) == 0)
	    {
	      if (vec_len (in.buffer) > 0)
		vec_add1 (in.buffer, ' ');
	      vec_add (in.buffer, v, vec_len (v));
	    }
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, input);
	  goto done;
	}

      vec_free (v);
      vec_free (s);
    }
done:
  input = &in;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      unformat_input_t sub_input;
      u8 *s = 0;
      if (unformat (input, "path %s", &s))
	pm->plugin_path = s;
      else if (unformat (input, "name-filter %s", &s))
	pm->plugin_name_filter = s;
      else if (unformat (input, "vat-path %s", &s))
	pm->vat_plugin_path = s;
      else if (unformat (input, "vat-name-filter %s", &s))
	pm->vat_plugin_name_filter = s;
      else if (unformat (input, "plugin default %U",
			 unformat_vlib_cli_sub_input, &sub_input))
	{
	  pm->plugins_default_disable =
	    unformat (&sub_input, "disable") ? 1 : 0;
	  unformat_free (&sub_input);
	}
      else if (unformat (input, "plugin %s %U", &s,
			 unformat_vlib_cli_sub_input, &sub_input))
	{
	  error = config_one_plugin (vm, (char *) s, &sub_input);
	  unformat_free (&sub_input);
	  if (error)
	    goto done2;
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, input);
	  {
	    vec_free (s);
	    goto done2;
	  }
	}
    }

done2:
  unformat_free (&in);
  return error;
}

/* discard whole 'plugins' section, as it is already consumed prior to
   plugin load */
static clib_error_t *
plugins_config (vlib_main_t * vm, unformat_input_t * input)
{
  u8 *junk;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%s", &junk))
	{
	  vec_free (junk);
	  return 0;
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (plugins_config, "plugins");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
