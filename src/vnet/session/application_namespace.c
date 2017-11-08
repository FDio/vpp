/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vnet/session/application_namespace.h>
#include <vnet/session/session_table.h>
#include <vnet/session/session.h>
#include <vnet/fib/fib_table.h>

/**
 * Hash table of application namespaces by app ns ids
 */
uword *app_namespace_lookup_table;

/**
 * Pool of application namespaces
 */
static app_namespace_t *app_namespace_pool;

app_namespace_t *
app_namespace_get (u32 index)
{
  return pool_elt_at_index (app_namespace_pool, index);
}

app_namespace_t *
app_namespace_get_from_id (const u8 * ns_id)
{
  u32 index = app_namespace_index_from_id (ns_id);
  if (index == APP_NAMESPACE_INVALID_INDEX)
    return 0;
  return app_namespace_get (index);
}

u32
app_namespace_index (app_namespace_t * app_ns)
{
  return (app_ns - app_namespace_pool);
}

app_namespace_t *
app_namespace_alloc (u8 * ns_id)
{
  app_namespace_t *app_ns;
  pool_get (app_namespace_pool, app_ns);
  memset (app_ns, 0, sizeof (*app_ns));
  app_ns->ns_id = vec_dup (ns_id);
  hash_set_mem (app_namespace_lookup_table, app_ns->ns_id,
		app_ns - app_namespace_pool);
  return app_ns;
}

clib_error_t *
vnet_app_namespace_add_del (vnet_app_namespace_add_del_args_t * a)
{
  app_namespace_t *app_ns;
  session_table_t *st;

  if (a->is_add)
    {
      if (a->sw_if_index != APP_NAMESPACE_INVALID_INDEX
	  && !vnet_get_sw_interface_safe (vnet_get_main (), a->sw_if_index))
	return clib_error_return_code (0, VNET_API_ERROR_INVALID_SW_IF_INDEX,
				       0, "sw_if_index %u doesn't exist",
				       a->sw_if_index);

      if (a->sw_if_index != APP_NAMESPACE_INVALID_INDEX)
	{
	  a->ip4_fib_id =
	    fib_table_get_table_id_for_sw_if_index (FIB_PROTOCOL_IP4,
						    a->sw_if_index);
	  a->ip6_fib_id =
	    fib_table_get_table_id_for_sw_if_index (FIB_PROTOCOL_IP4,
						    a->sw_if_index);
	}
      if (a->sw_if_index == APP_NAMESPACE_INVALID_INDEX
	  && a->ip4_fib_id == APP_NAMESPACE_INVALID_INDEX)
	return clib_error_return_code (0, VNET_API_ERROR_INVALID_VALUE, 0,
				       "sw_if_index or fib_id must be "
				       "configured");
      app_ns = app_namespace_get_from_id (a->ns_id);
      if (!app_ns)
	{
	  app_ns = app_namespace_alloc (a->ns_id);
	  st = session_table_alloc ();
	  session_table_init (st, FIB_PROTOCOL_MAX);
	  st->is_local = 1;
	  st->appns_index = app_namespace_index (app_ns);
	  app_ns->local_table_index = session_table_index (st);
	}
      app_ns->ns_secret = a->secret;
      app_ns->sw_if_index = a->sw_if_index;
      app_ns->ip4_fib_index =
	fib_table_find (FIB_PROTOCOL_IP4, a->ip4_fib_id);
      app_ns->ip6_fib_index =
	fib_table_find (FIB_PROTOCOL_IP6, a->ip6_fib_id);
      session_lookup_set_tables_appns (app_ns);
    }
  else
    {
      return clib_error_return_code (0, VNET_API_ERROR_UNIMPLEMENTED, 0,
				     "namespace deletion not supported");
    }
  return 0;
}

const u8 *
app_namespace_id (app_namespace_t * app_ns)
{
  return app_ns->ns_id;
}

u32
app_namespace_index_from_id (const u8 * ns_id)
{
  uword *indexp;
  indexp = hash_get_mem (app_namespace_lookup_table, ns_id);
  if (!indexp)
    return APP_NAMESPACE_INVALID_INDEX;
  return *indexp;
}

const u8 *
app_namespace_id_from_index (u32 index)
{
  app_namespace_t *app_ns;

  app_ns = app_namespace_get (index);
  return app_namespace_id (app_ns);
}

u32
app_namespace_get_fib_index (app_namespace_t * app_ns, u8 fib_proto)
{
  return fib_proto == FIB_PROTOCOL_IP4 ?
    app_ns->ip4_fib_index : app_ns->ip6_fib_index;
}

session_table_t *
app_namespace_get_local_table (app_namespace_t * app_ns)
{
  return session_table_get (app_ns->local_table_index);
}

void
app_namespaces_init (void)
{
  u8 *ns_id = format (0, "default");

  if (!app_namespace_lookup_table)
    app_namespace_lookup_table =
      hash_create_vec (0, sizeof (u8), sizeof (uword));

  /*
   * Allocate default namespace
   */
  vnet_app_namespace_add_del_args_t a = {
    .ns_id = ns_id,
    .secret = 0,
    .sw_if_index = APP_NAMESPACE_INVALID_INDEX,
    .is_add = 1
  };
  vnet_app_namespace_add_del (&a);
  vec_free (ns_id);
}

static clib_error_t *
app_ns_fn (vlib_main_t * vm, unformat_input_t * input,
	   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 0, *ns_id = 0, secret_set = 0, sw_if_index_set = 0;
  u32 sw_if_index, fib_id = APP_NAMESPACE_INVALID_INDEX;
  u64 secret;
  clib_error_t *error = 0;

  session_cli_return_if_not_enabled ();

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "id %_%v%_", &ns_id))
	;
      else if (unformat (line_input, "secret %lu", &secret))
	secret_set = 1;
      else if (unformat (line_input, "sw_if_index %u", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (line_input, "fib_id", &fib_id))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  unformat_free (line_input);
	  return error;
	}
    }
  unformat_free (line_input);

  if (!ns_id || !secret_set || !sw_if_index_set)
    {
      vlib_cli_output (vm, "namespace-id, secret and sw_if_index must be "
		       "provided");
      return 0;
    }

  if (is_add)
    {
      vnet_app_namespace_add_del_args_t args = {
	.ns_id = ns_id,
	.secret = secret,
	.sw_if_index = sw_if_index,
	.ip4_fib_id = fib_id,
	.is_add = 1
      };
      error = vnet_app_namespace_add_del (&args);
    }

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (app_ns_command, static) =
{
  .path = "app ns",
  .short_help = "app ns [add] id <namespace-id> secret <secret> "
      "sw_if_index <sw_if_index>",
  .function = app_ns_fn,
};
/* *INDENT-ON* */

u8 *
format_app_namespace (u8 * s, va_list * args)
{
  app_namespace_t *app_ns = va_arg (*args, app_namespace_t *);
  s = format (s, "%-20v%-20lu%-20u", app_ns->ns_id, app_ns->ns_secret,
	      app_ns->sw_if_index);
  return s;
}

static clib_error_t *
show_app_ns_fn (vlib_main_t * vm, unformat_input_t * main_input,
		vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  app_namespace_t *app_ns;
  session_table_t *st;
  u8 *ns_id, do_table = 0;

  session_cli_return_if_not_enabled ();

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "table %_%v%_", &ns_id))
	do_table = 1;
      else
	{
	  vlib_cli_output (vm, "unknown input [%U]", format_unformat_error,
			   line_input);
	  goto done;
	}
    }

  if (do_table)
    {
      app_ns = app_namespace_get_from_id (ns_id);
      if (!app_ns)
	{
	  vlib_cli_output (vm, "ns %v not found", ns_id);
	  goto done;
	}
      st = session_table_get (app_ns->local_table_index);
      if (!st)
	{
	  vlib_cli_output (vm, "table for ns %v could not be found", ns_id);
	  goto done;
	}
      session_lookup_show_table_entries (vm, st, 0, 1);
      vec_free (ns_id);
      goto done;
    }

  vlib_cli_output (vm, "%-20s%-20s%-20s", "Namespace", "Secret",
		   "sw_if_index");

  /* *INDENT-OFF* */
  pool_foreach (app_ns, app_namespace_pool, ({
    vlib_cli_output (vm, "%U", format_app_namespace, app_ns);
  }));
  /* *INDENT-ON* */

done:
  unformat_free (line_input);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_app_ns_command, static) =
{
  .path = "show app ns",
  .short_help = "show app ns",
  .function = show_app_ns_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
