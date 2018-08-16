/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Intel and/or its affiliates.
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
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dpi/dpi.h>


extern dpi_main_t dpi_main;
extern dpi_entry_t *dpi_db;


u32
dpi_get_app_db (u32 app_id)
{
  dpi_main_t *dm = &dpi_main;
  dpi_app_t *app;

  app = pool_elt_at_index (dm->dpi_apps, app_id);
  if (app->db_index != ~0 && !pool_is_free_index (dpi_db, app->db_index))
    {
      dpi_entry_t *entry = pool_elt_at_index (dpi_db, app->db_index);
      clib_atomic_add_fetch (&entry->ref_cnt, 1);
    }

  return app->db_index;
}

void
dpi_put_app_db (u32 db_index)
{
  if (db_index != ~0)
    {
      dpi_entry_t *entry = pool_elt_at_index (dpi_db, db_index);
      clib_atomic_add_fetch (&entry->ref_cnt, -1);
    }
}

static clib_error_t *
dpi_url_test_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *url = NULL;
  clib_error_t *error = NULL;
  u32 id = 0;
  int r;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u url %_%v%_", &id, &url))
	{
	  break;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  r = dpi_db_lookup (id, url, vec_len (url));
  vlib_cli_output (vm, "Matched Result: %u", r);

done:
  vec_free (url);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_url_test_command, static) =
{
  .path = "dpi test db",
  .short_help = "dpi test db <id> url <url>",
  .function = dpi_url_test_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dpi_show_db_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *name = NULL;
  regex_t *expressions = NULL;
  dpi_entry_t *e;
  uword *p = NULL;

  dpi_app_t *app = NULL;
  dpi_main_t *dm = &dpi_main;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%_%v%_", &name))
	{
	  break;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  p = hash_get_mem (dm->dpi_app_by_name, name);
  if (!p)
    goto done;

  app = pool_elt_at_index (dm->dpi_apps, p[0]);
  if (app->db_index == ~0)
    {
      error = clib_error_return (0, "DB does not exist...");
      goto done;
    }

  e = pool_elt_at_index (dpi_db, app->db_index);
  for (int i = 0; i < vec_len (e->expressions); i++)
    {
      vlib_cli_output (vm, "regex: %v", expressions[i]);
    }

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_show_db_command, static) =
{
  .path = "dpi show db app",
  .short_help = "dpi show db app <name>",
  .function = dpi_show_db_command_fn,
};
/* *INDENT-ON* */

static u32
dpi_get_db_ref_count (u32 db_index)
{
  if (db_index != ~0)
    {
      dpi_entry_t *entry = pool_elt_at_index (dpi_db, db_index);
      return entry->ref_cnt;
    }

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

static clib_error_t *
dpi_create_app_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  clib_error_t *error = NULL;
  int rv = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%_%v%_", &name))
	break;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  rv = dpi_app_add_del (name, 1);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "application already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "application does not exist...");
      break;

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_create_app_command, static) =
{
  .path = "dpi create app",
  .short_help = "dpi create app <name>",
  .function = dpi_create_app_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dpi_delete_app_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  clib_error_t *error = NULL;
  int rv = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%_%v%_", &name))
	break;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  rv = dpi_app_add_del (name, 0);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "application already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "application does not exist...");
      break;

    case VNET_API_ERROR_INSTANCE_IN_USE:
      error = clib_error_return (0, "application is in use...");
      break;

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_delete_app_command, static) =
{
  .path = "dpi delete app",
  .short_help = "dpi delete app <name>",
  .function = dpi_delete_app_command_fn,
};
/* *INDENT-ON* */

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

static clib_error_t *
dpi_app_rule_add_del_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *app_name = NULL;
  ip46_address_t src_ip;
  ip46_address_t dst_ip;
  u8 *host = NULL;
  u8 *path = NULL;
  u32 rule_index = 0;
  clib_error_t *error = NULL;
  int rv = 0;
  u8 add = 1;
  dpi_rule_args_t rule_args = { };

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%_%v%_ rule %u", &app_name, &rule_index))
	{
	  if (unformat (line_input, "del"))
	    {
	      add = 0;
	      break;
	    }
	  else if (unformat (line_input, "add"))
	    {
	      add = 1;

	      if (unformat
		  (line_input, "ip dst %U", unformat_ip46_address, &dst_ip,
		   IP46_TYPE_ANY))
		break;
	      else
		if (unformat
		    (line_input, "ip src %U", unformat_ip46_address, &src_ip,
		     IP46_TYPE_ANY))
		break;
	      else if (unformat (line_input, "l7 http host %_%v%_", &host))
		{
		  if (unformat (line_input, "path %_%v%_", &path))
		    break;
		}
	      else
		{
		  error = clib_error_return (0, "unknown input `%U'",
					     format_unformat_error, input);
		  goto done;
		}
	    }
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, input);
	      goto done;
	    }
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  rule_args.host = host;
  rule_args.path = path;
  rule_args.src_ip = src_ip;
  rule_args.dst_ip = dst_ip;

  rv = dpi_rule_add_del (app_name, rule_index, add, &rule_args);
  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "rule already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "application or rule does not exist...");
      break;

    case VNET_API_ERROR_INSTANCE_IN_USE:
      error = clib_error_return (0, "application is in use...");
      break;

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

done:
  vec_free (host);
  vec_free (path);
  vec_free (app_name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_app_rule_add_del_command, static) =
{
  .path = "dpi app",
  .short_help = "dpi app <name> rule <id> "
      "(add | del) [ip src <ip> | dst <ip>] "
      "[l7 http host <regex> path <path>]",
  .function = dpi_app_rule_add_del_command_fn,
};
/* *INDENT-ON* */

static void
dpi_show_rules (vlib_main_t * vm, dpi_app_t * app)
{
  u32 index = 0;
  u32 rule_index = 0;
  dpi_rule_t *rule = NULL;

  /* *INDENT-OFF* */
  hash_foreach(rule_index, index, app->rules_by_id,
  ({
     rule = pool_elt_at_index(app->rules, index);
     vlib_cli_output (vm, "rule: %u", rule->id);

     if (rule->host)
       vlib_cli_output (vm, "host: %v", rule->host);

     if (rule->path)
       vlib_cli_output (vm, "path: %v", rule->path);
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
dpi_show_app_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  uword *p = NULL;
  clib_error_t *error = NULL;
  dpi_app_t *app = NULL;
  dpi_main_t *dm = &dpi_main;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%_%v%_", &name))
	{
	  break;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  p = hash_get_mem (dm->dpi_app_by_name, name);
  if (!p)
    {
      error = clib_error_return (0, "unknown application name");
      goto done;
    }

  app = pool_elt_at_index (dm->dpi_apps, p[0]);

  dpi_show_rules (vm, app);

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_show_app_command, static) =
{
  .path = "dpi show app",
  .short_help = "dpi show app <name>",
  .function = dpi_show_app_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dpi_show_apps_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  dpi_main_t *dm = &dpi_main;
  u8 *name = NULL;
  u32 index = 0;
  int verbose = 0;
  clib_error_t *error = NULL;
  unformat_input_t _line_input, *line_input = &_line_input;

  /* Get a line of input. */
  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "verbose"))
	    {
	      verbose = 1;
	      break;
	    }
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, input);
	      unformat_free (line_input);
	      return error;
	    }
	}

      unformat_free (line_input);
    }

  /* *INDENT-OFF* */
  hash_foreach(name, index, dm->dpi_app_by_name,
  ({
     dpi_app_t *app = NULL;
     app = pool_elt_at_index(dm->dpi_apps, index);
     vlib_cli_output (vm, "app: %v", app->name);

     if (verbose)
       {
         dpi_show_rules(vm, app);
       }
  }));
  /* *INDENT-ON* */

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_show_apps_command, static) =
{
  .path = "dpi show apps",
  .short_help = "dpi show apps [verbose]",
  .function = dpi_show_apps_command_fn,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
