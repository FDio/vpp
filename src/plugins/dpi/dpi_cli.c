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


dpi_main_t dpi_main;

static clib_error_t *
dpi_set_ip_dpi_bypass (u32 is_ip6,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index, is_enable;

  sw_if_index = ~0;
  is_enable = 1;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat_user
	  (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_enable = 0;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (~0 == sw_if_index)
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  vnet_int_dpi_bypass (sw_if_index, is_ip6, is_enable);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
dpi_set_interface_ip4_dpi_bypass_command_fn (vlib_main_t * vm,
					     unformat_input_t * input,
					     vlib_cli_command_t * cmd)
{
  return dpi_set_ip_dpi_bypass (0, input, cmd);
}

/*?
 * This command adds the 'ip4-dpi-bypass' graph node for a given interface.
 * By adding the IPv4 dpi graph node to an interface, the node checks
 *  for and validate input dpi packet and bypass ip4-lookup, ip4-local,
 * ip4-udp-lookup/ip4-tcp-lookup nodes to speedup dpi packet scan.
 *
 * Example of how to enable ip4-dpi-bypass on an interface:
 * @cliexcmd{dpi set interface ip4 dpi-bypass GigabitEthernet2/0/0}
 *
 * Example of how to disable ip4-dpi-bypass on an interface:
 * @cliexcmd{dpi set interface ip4 dpi-bypass GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_set_interface_ip4_dpi_bypass_command, static) = {
  .path = "dpi set interface ip4 dpi-bypass",
  .function = dpi_set_interface_ip4_dpi_bypass_command_fn,
  .short_help = "dpi set interface ip4 dpi-bypass <interface> [del]",
};
/* *INDENT-ON* */

static clib_error_t *
dpi_set_interface_ip6_dpi_bypass_command_fn (vlib_main_t * vm,
					     unformat_input_t * input,
					     vlib_cli_command_t * cmd)
{
  return dpi_set_ip_dpi_bypass (1, input, cmd);
}

/*?
 * This command adds the 'ip6-dpi-bypass' graph node for a given interface.
 * By adding the IPv6 dpi graph node to an interface, the node checks
 *  for and validate input dpi packet and bypass ip6-lookup, ip6-local,
 * ip6-udp-lookup/ip6-tcp-lookup nodes to speedup dpi packet scan.
 *
 * Example of how to enable ip6-dpi-bypass on an interface:
 * @cliexcmd{dpi set interface ip6 dpi-bypass GigabitEthernet2/0/0}
 *
 * Example of how to disable ip6-dpi-bypass on an interface:
 * @cliexcmd{dpi set interface ip6 dpi-bypass GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_set_interface_ip6_dpi_bypass_command, static) = {
  .path = "dpi set interface ip6 dpi-bypass",
  .function = dpi_set_interface_ip6_dpi_bypass_command_fn,
  .short_help = "dpi set interface ip6 dpi-bypass <interface> [del]",
};
/* *INDENT-ON* */

int
dpi_app_add_del(u8 * name, u8 add)
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
      memset(app, 0, sizeof(*app));

      app->name = vec_dup(name);
      app->rules_by_id = hash_create_mem (0, sizeof (u32), sizeof (uword));
      app->path_db_index = ~0;
      app->host_db_index = ~0;
      app->id = app - dm->dpi_apps;

      hash_set_mem (dm->dpi_app_by_name, app->name, app->id);
    }
  else
    {
      if (!p)
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      hash_unset_mem (dm->dpi_app_by_name, name);
      app = pool_elt_at_index (dm->dpi_apps, p[0]);

      /* *INDENT-OFF* */
      hash_foreach(rule_index, index, app->rules_by_id,
      ({
         dpi_rule_t *rule = NULL;
         rule = pool_elt_at_index(app->rules, index);
         dpi_rule_add_del(app->name, rule->id, 0, NULL);
      }));
      /* *INDENT-ON* */

      dpi_db_remove(app->path_db_index);
      dpi_db_remove(app->host_db_index);
      vec_free (app->name);
      hash_free(app->rules_by_id);
      pool_free(app->rules);
      pool_put (dm->dpi_apps, app);
    }

  return 0;
}

static clib_error_t *
dpi_create_app_command_fn (vlib_main_t * vm,
                           unformat_input_t * input,
                           vlib_cli_command_t * cmd)
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

  rv = dpi_app_add_del(name, 1);

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
                           unformat_input_t * input,
                           vlib_cli_command_t * cmd)
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

  rv = dpi_app_add_del(name, 0);

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
VLIB_CLI_COMMAND (dpi_delete_app_command, static) =
{
  .path = "dpi delete app",
  .short_help = "dpi delete app <name>",
  .function = dpi_delete_app_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dpi_show_db_command_fn (vlib_main_t * vm,
                            unformat_input_t * input,
                            vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *name = NULL;
  u32 path_id = 0;
  u32 host_id = 0;
  int res = 0;
  regex_t *regex = NULL;
  regex_t *expressions = NULL;
  u32 *ids = NULL;
  int i = 0;
  u32 app_id = 0;
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

  res = dpi_get_db_id(name, &path_id, &host_id);
  if (res < 0 || path_id == ~0)
    {
      error = clib_error_return (0, "DB does not exist...");
      goto done;
    }

  res = dpi_get_db_contents(path_id, &expressions, &ids);
  if (res == 0)
    {
      for (i = 0; i < vec_len(expressions); i++)
        {
          regex = &expressions[i];
          app_id = ids[i];

          if (app_id != ~0)
            {
              app = pool_elt_at_index (dm->dpi_apps, app_id);
            }

          vlib_cli_output (vm, "regex: %v, app: %v", *regex, app->name);
        }
    }
  else
    {
      error = clib_error_return (0, "DB does not exist...");
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


static clib_error_t *
dpi_url_test_command_fn (vlib_main_t * vm,
                             unformat_input_t * input,
                             vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *url = NULL;
  clib_error_t *error = NULL;
  u32 app_index = 0;
  u32 id = 0;
  dpi_app_t *app = NULL;
  dpi_main_t *dm = &dpi_main;

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

  dpi_db_lookup(id, url, vec_len(url), &app_index);
  if (app_index != ~0)
    {
      app = pool_elt_at_index (dm->dpi_apps, app_index);
      if (app)
        {
          vlib_cli_output (vm, "Matched app: %v", app->name);
        }
    }
  else
    {
      vlib_cli_output (vm, "No match found");
    }

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

int
dpi_rule_add_del(u8 * app_name, u32 rule_index, u8 add,
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

  p = hash_get_mem (app->rules_by_id, &rule_index);

  if (add)
    {
      if (p)
        return VNET_API_ERROR_VALUE_EXIST;

      pool_get (app->rules, rule);
      memset(rule, 0, sizeof(*rule));
      rule->id = rule_index;
      rule->host = vec_dup(args->host);
      rule->path = vec_dup(args->path);

      hash_set_mem (app->rules_by_id,
                    &rule_index, rule - app->rules);
    }
  else
    {
      if (!p)
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      rule = pool_elt_at_index (app->rules, p[0]);
      vec_free(rule->host);
      vec_free(rule->path);
      hash_unset_mem (app->rules_by_id, &rule_index);
      pool_put (app->rules, rule);
    }

  res = dpi_create_update_db(app_name, &app->path_db_index,
                             &app->host_db_index);
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
  u8 *src_ip = NULL;
  u8 *dst_ip = NULL;
  u8 *host = NULL;
  u8 *path = NULL;
  u32 rule_index = 0;
  clib_error_t *error = NULL;
  int rv = 0;
  int add = 1;
  dpi_rule_args_t rule_args = {};

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%_%v%_ rule %u",
                    &app_name, &rule_index))
        {
          if (unformat (line_input, "del"))
            {
              add = 0;
              break;
            }
          else if (unformat (line_input, "add"))
            {
              add = 1;

              if (unformat (line_input, "ip dst %s", &dst_ip))
                break;
              else if (unformat (line_input, "ip src %s", &src_ip))
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

  rv = dpi_rule_add_del(app_name, rule_index, add, &rule_args);
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

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

done:
  vec_free (dst_ip);
  vec_free (src_ip);
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
dpi_show_rules(vlib_main_t * vm, dpi_app_t * app)
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
                         unformat_input_t * input,
                         vlib_cli_command_t * cmd)
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

  dpi_show_rules(vm, app);

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
                          unformat_input_t * input,
                          vlib_cli_command_t * cmd)
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
