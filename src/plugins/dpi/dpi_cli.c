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
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vpp/app/version.h>
#include <dpi/dpi.h>


extern dpi_main_t dpi_main;
extern dpi_entry_t *dpi_dbs;


u32
dpi_get_app_db (u32 app_id)
{
  dpi_main_t *dm = &dpi_main;
  dpi_app_t *app;

  app = pool_elt_at_index (dm->dpi_apps, app_id);
  if (app->db_index != ~0 && !pool_is_free_index (dpi_dbs, app->db_index))
    {
      dpi_entry_t *entry = pool_elt_at_index (dpi_dbs, app->db_index);
      clib_atomic_add_fetch (&entry->ref_cnt, 1);
    }

  return app->db_index;
}

void
dpi_put_app_db (u32 db_index)
{
  if (db_index != ~0)
    {
      dpi_entry_t *entry = pool_elt_at_index (dpi_dbs, db_index);
      clib_atomic_add_fetch (&entry->ref_cnt, -1);
    }
}

static clib_error_t *
dpi_adr_app_add_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  clib_error_t *error = NULL;
  u8 add_flag = ~0;
  dpi_adr_t *adr;
  dpi_main_t *dm = &dpi_main;
  uword *p = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add app %_%v%_", &name))
	{
	  add_flag = 1;
	  break;
	}
      if (unformat (line_input, "del app %_%v%_", &name))
	{
	  add_flag = 0;
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
      goto done;
    }

  if (pool_is_free_index (dm->dpi_apps, p[0]))
    goto done;

  if (pool_is_free_index (dm->dpi_adrs, p[0]))
    {
      pool_get (dm->dpi_adrs, adr);
      memset (adr, 0, sizeof (*adr));
    }

  if (add_flag == 0)
    {
      dpi_put_app_db (adr->db_id);
      adr->app_id = ~0;
      adr->db_id = ~0;
    }
  else if (add_flag == 1)
    {
      adr->app_id = p[0];
      adr->db_id = dpi_get_app_db (p[0]);
    }

  vlib_cli_output (vm, "ADR DB id: %u", adr->db_id);

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_adr_app_add_command, static) =
{
  .path = "dpi adr",
  .short_help = "dpi adr <add|del> app <name>",
  .function = dpi_adr_app_add_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dpi_test_db_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  char *url = NULL;
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
  .short_help = "dpi test db <id> host host <regex> pattern <regex>",
  .function = dpi_test_db_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dpi_show_db_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *name = NULL;
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

  e = pool_elt_at_index (dpi_dbs, app->db_index);
  for (int i = 0; i < vec_len (e->expressions); i++)
    {
      vlib_cli_output (vm, "regex: %v", e->expressions[i]);
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
      error = clib_error_return (0, "Application already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "Application does not exist...");
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

static clib_error_t *
dpi_app_rule_add_del_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *app_name = NULL;
  u8 *host = NULL;
  u8 *pattern = NULL;
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

	      if (unformat (line_input, "host %_%v%_", &host))
		{
		  if (unformat (line_input, "pattern %_%v%_", &pattern))
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
  rule_args.pattern = pattern;

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
  vec_free (pattern);
  vec_free (app_name);
  unformat_free (line_input);

  return error;
}

/* Configure matched host and/or pattern for specific application
 * For example:
 * host ".intel.com" is used to match Intel Application.
 * Pattern "\\.intel(?i)(?:\\.co(?:m)?)?\\.[a-z]{2,63}$" does the same as host.
 * */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_app_rule_add_del_command, static) =
{
  .path = "dpi app",
  .short_help = "dpi app <name> rule <id> (add | del) "
                "[host <regex> pattern <regex>]",
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

     if (rule->pattern)
       vlib_cli_output (vm, "pattern: %v", rule->pattern);
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

static clib_error_t *
dpi_flow_add_del_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd_arg)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t src_ip = ip46_address_initializer;
  ip46_address_t dst_ip = ip46_address_initializer;
  u16 src_port, dst_port;
  u8 is_add = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  u32 tmp;
  int rv;
  u8 protocol;
  u32 table_id;
  u32 fib_index = 0;
  u32 dpi_flow_id;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "src-ip %U",
			 unformat_ip46_address, &src_ip, IP46_TYPE_ANY))
	{
	  ip46_address_is_ip4 (&src_ip) ? (ipv4_set = 1) : (ipv6_set = 1);
	}
      else if (unformat (line_input, "dst-ip %U",
			 unformat_ip46_address, &dst_ip, IP46_TYPE_ANY))
	{
	  ip46_address_is_ip4 (&dst_ip) ? (ipv4_set = 1) : (ipv6_set = 1);
	}
      else if (unformat (line_input, "src-port %d", &tmp))
	src_port = (u16) tmp;
      else if (unformat (line_input, "dst-port %d", &tmp))
	dst_port = (u16) tmp;
      else
	if (unformat (line_input, "protocol %U", unformat_ip_protocol, &tmp))
	protocol = (u8) tmp;
      else if (unformat (line_input, "protocol %u", &tmp))
	protocol = (u8) tmp;
      else if (unformat (line_input, "vrf-id %d", &table_id))
	{
	  fib_index = fib_table_find (fib_ip_proto (ipv6_set), table_id);
	}
      else
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (ipv4_set && ipv6_set)
    return clib_error_return (0, "both IPv4 and IPv6 addresses specified");

  dpi_add_del_flow_args_t a = {
    .is_add = is_add,
    .is_ipv6 = ipv6_set,
#define _(x) .x = x,
    foreach_copy_field
#undef _
  };

  /* Add normal flow */
  rv = dpi_flow_add_del (&a, &dpi_flow_id);
  if (rv < 0)
    return clib_error_return (0, "flow error: %d", rv);

  /* Add reverse flow */
  rv = dpi_reverse_flow_add_del (&a, dpi_flow_id);
  if (rv < 0)
    return clib_error_return (0, "reverse flow error: %d", rv);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_flow_add_del_command, static) = {
    .path = "dpi flow",
    .short_help = "dpi flow [add | del]  "
        "[src-ip <ip-addr>] [dst-ip <ip-addr>] "
        "[src-port <port>] [dst-port <port>] "
        "[protocol <protocol>] [vrf-id <nn>]",
    .function = dpi_flow_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dpi_flow_offload_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpi_main_t *dm = &dpi_main;
  vnet_main_t *vnm = dm->vnet_main;
  u32 rx_flow_id = ~0;
  u32 hw_if_index = ~0;
  int is_add = 1;
  u32 is_ipv6 = 0;
  dpi_flow_entry_t *flow;
  vnet_hw_interface_t *hw_if;
  u32 rx_fib_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "hw %U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
	continue;
      if (unformat (line_input, "rx %d", &rx_flow_id))
	continue;
      if (unformat (line_input, "del"))
	{
	  is_add = 0;
	  continue;
	}
      return clib_error_return (0, "unknown input `%U'",
				format_unformat_error, line_input);
    }

  if (rx_flow_id == ~0)
    return clib_error_return (0, "missing rx flow");
  if (hw_if_index == ~0)
    return clib_error_return (0, "missing hw interface");

  flow = pool_elt_at_index (dm->dpi_flows, rx_flow_id);

  hw_if = vnet_get_hw_interface (vnm, hw_if_index);

  is_ipv6 = ip46_address_is_ip4 (&(flow->key.src_ip)) ? 0 : 1;

  if (is_ipv6)
    {
      ip6_main_t *im6 = &ip6_main;
      rx_fib_index =
	vec_elt (im6->fib_index_by_sw_if_index, hw_if->sw_if_index);
    }
  else
    {
      ip4_main_t *im4 = &ip4_main;
      rx_fib_index =
	vec_elt (im4->fib_index_by_sw_if_index, hw_if->sw_if_index);
    }

  if (flow->key.fib_index != rx_fib_index)
    return clib_error_return (0, "interface/flow fib mismatch");

  if (dpi_add_del_rx_flow (hw_if_index, rx_flow_id, is_add, is_ipv6))
    return clib_error_return (0, "error %s flow",
			      is_add ? "enabling" : "disabling");

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_flow_offload_command, static) = {
    .path = "dpi set flow-offload",
    .short_help =
        "dpi set flow-offload hw <interface-name> rx <flow-id> [del]",
    .function = dpi_flow_offload_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dpi_set_flow_bypass (u32 is_ip6,
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
      if (unformat_user (line_input, unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
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

  dpi_flow_bypass_mode (sw_if_index, is_ip6, is_enable);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
dpi_set_ip4_flow_bypass_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  return dpi_set_flow_bypass (0, input, cmd);
}

VLIB_CLI_COMMAND (dpi_set_ip4_flow_bypass_command, static) =
{
.path = "dpi set ip4 flow-bypass",.short_help =
    "dpi set ip4 flow-bypass <interface> [del]",.function =
    dpi_set_ip4_flow_bypass_command_fn,};
/* *INDENT-ON* */

static clib_error_t *
dpi_set_ip6_flow_bypass_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  return dpi_set_flow_bypass (0, input, cmd);
}

VLIB_CLI_COMMAND (dpi_set_ip6_flow_bypass_command, static) =
{
.path = "dpi set ip6 flow-bypass",.short_help =
    "dpi set ip6 flow-bypass <interface> [del]",.function =
    dpi_set_ip6_flow_bypass_command_fn,};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
