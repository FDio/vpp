/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Intel, Travelping and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/dpo/dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <dpi/dpi.h>

dpi_main_t dpi_main;
dpi_entry_t *dpi_db = NULL;

#if CLIB_DEBUG > 0
#define dpi_debug clib_warning
#else
#define dpi_debug(...)              \
  do { } while (0)
#endif

int
dpi_get_db_ref_count (u32 db_index)
{
  if (db_index != ~0)
    {
      dpi_entry_t *entry = pool_elt_at_index (dpi_db, db_index);
      return entry->ref_cnt;
    }

  return 0;
}

void
dpi_cleanup_db_entry (dpi_entry_t * entry)
{
  regex_t *regex = NULL;

  vec_foreach (regex, entry->expressions)
  {
    vec_free (*regex);
  }

  hs_free_database (entry->database);
  hs_free_scratch (entry->scratch);
  vec_free (entry->expressions);
  vec_free (entry->flags);

  memset (entry, 0, sizeof (dpi_entry_t));
}

int
dpi_create_update_db (dpi_app_t * app)
{
  dpi_entry_t *entry = NULL;
  hs_compile_error_t *compile_err = NULL;
  int error = 0;
  u32 index = 0;
  u32 rule_index = 0;
  dpi_rule_t *rule = NULL;

  if (app->db_index != ~0)
    {
      entry = pool_elt_at_index (dpi_db, app->db_index);
      if (!entry)
	return -1;

      dpi_cleanup_db_entry (entry);
    }
  else
    {
      pool_get (dpi_db, entry);
      if (!entry)
	return -1;

      memset (entry, 0, sizeof (*entry));
      app->db_index = entry - dpi_db;
    }

  /* *INDENT-OFF* */
  hash_foreach(rule_index, index, app->rules_by_id,
  ({
     regex_t regex = NULL;
     rule = pool_elt_at_index(app->rules, index);

     vec_add(regex, ".*\\Q", 4);
     vec_append(regex, rule->host);
     vec_add(regex, "\\E.*\\Q", 6);
     vec_append(regex, rule->path);
     vec_add(regex, "\\E.*", 4);
     vec_add1(regex, 0);

     dpi_debug("app id: %u, regex: %s", app - dm->dpi_apps, regex);

     vec_add1(entry->expressions, regex);
     vec_add1(entry->flags, HS_FLAG_SINGLEMATCH);
  }));
  /* *INDENT-ON* */

  if (hs_compile_multi
      ((const char **) entry->expressions, entry->flags, NULL,
       vec_len (entry->expressions), HS_MODE_BLOCK, NULL, &entry->database,
       &compile_err) != HS_SUCCESS)
    {
      error = -1;
      goto done;
    }

  if (hs_alloc_scratch (entry->database, &entry->scratch) != HS_SUCCESS)
    {
      hs_free_database (entry->database);
      entry->database = NULL;
      error = -1;
      goto done;
    }

done:
  return error;
}



int
dpi_event_handler (unsigned int id, unsigned long long from,
		   unsigned long long to, unsigned int flags, void *ctx)
{
  (void) from;
  (void) to;
  (void) flags;

  dpi_cb_args_t *args = (dpi_cb_args_t *) ctx;

  args->res = 1;

  return 0;
}

int
dpi_db_lookup (u32 db_index, u8 * str, uint16_t length)
{
  dpi_entry_t *entry = NULL;
  int ret = 0;
  dpi_cb_args_t args = { };

  if (db_index == ~0)
    return -1;

  entry = pool_elt_at_index (dpi_db, db_index);
  if (!entry)
    return -1;

  ret = hs_scan (entry->database, (const char *) str, length, 0,
		 entry->scratch, dpi_event_handler, (void *) &args);
  if (ret != HS_SUCCESS)
    return -1;

  if (args.res == 0)
    return -1;

  return 0;
}

int
dpi_db_remove (u32 db_index)
{
  dpi_entry_t *entry = NULL;

  entry = pool_elt_at_index (dpi_db, db_index);
  if (!entry)
    return -1;

  dpi_cleanup_db_entry (entry);

  pool_put (dpi_db, entry);

  return 0;
}

int
dpi_app_add_del (u8 * name, u8 add)
{
  dpi_main_t *dm = &dpi_main;
  dpi_app_t *app = NULL;
  u32 index = 0;
  u32 rule_index = 0;
  uword *p = NULL;

  p = hash_get_mem (dm->dpi_app_by_name, name);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (dm->dpi_apps, app);
      memset (app, 0, sizeof (*app));

      app->name = vec_dup (name);
      app->rules_by_id = hash_create_mem (0, sizeof (u32), sizeof (uword));
      app->db_index = ~0;

      hash_set_mem (dm->dpi_app_by_name, app->name, app - dm->dpi_apps);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      hash_unset_mem (dm->dpi_app_by_name, name);
      app = pool_elt_at_index (dm->dpi_apps, p[0]);

      if (dpi_get_db_ref_count (app->db_index) != 0)
	return VNET_API_ERROR_INSTANCE_IN_USE;

      /* *INDENT-OFF* */
      hash_foreach(rule_index, index, app->rules_by_id,
      ({
         dpi_rule_t *rule = NULL;
         rule = pool_elt_at_index(app->rules, index);
         dpi_rule_add_del(app->name, rule->id, 0, NULL);
      }));
      /* *INDENT-ON* */

      dpi_db_remove (app->db_index);
      vec_free (app->name);
      hash_free (app->rules_by_id);
      pool_free (app->rules);
      pool_put (dm->dpi_apps, app);
    }

  return 0;
}


int
dpi_rule_add_del (u8 * app_name, u32 rule_index, u8 add,
		  dpi_rule_args_t * args)
{
  dpi_main_t *dm = &dpi_main;
  uword *p = NULL;
  dpi_app_t *app = NULL;
  dpi_rule_t *rule = NULL;
  int res = 0;

  p = hash_get_mem (dm->dpi_app_by_name, app_name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  app = pool_elt_at_index (dm->dpi_apps, p[0]);
  if (dpi_get_db_ref_count (app->db_index) != 0)
    return VNET_API_ERROR_INSTANCE_IN_USE;

  p = hash_get_mem (app->rules_by_id, &rule_index);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (app->rules, rule);
      memset (rule, 0, sizeof (*rule));
      rule->id = rule_index;
      rule->host = vec_dup (args->host);
      rule->path = vec_dup (args->path);

      hash_set_mem (app->rules_by_id, &rule_index, rule - app->rules);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      rule = pool_elt_at_index (app->rules, p[0]);
      vec_free (rule->host);
      vec_free (rule->path);
      hash_unset_mem (app->rules_by_id, &rule_index);
      pool_put (app->rules, rule);
    }

  res = dpi_create_update_db (app);
  if (res < 0)
    return res;

  return 0;
}

clib_error_t *
dpi_init (vlib_main_t * vm)
{
  dpi_main_t *dm = &dpi_main;

  dm->vnet_main = vnet_get_main ();
  dm->vlib_main = vm;

  dm->dpi_app_by_name = hash_create_vec ( /* initial length */ 32,
					 sizeof (u8), sizeof (uword));

  return 0;
}

VLIB_INIT_FUNCTION (dpi_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Deep Packet Inspection",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
