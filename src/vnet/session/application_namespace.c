/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
#include <vnet/session/application.h>
#include <vnet/session/session_table.h>
#include <vnet/session/session.h>
#include <vnet/fib/fib_table.h>
#include <vppinfra/file.h>
#include <vppinfra/format_table.h>
#include <vlib/unix/unix.h>

/**
 * Hash table of application namespaces by app ns ids
 */
uword *app_namespace_lookup_table;

/**
 * Pool of application namespaces
 */
static app_namespace_t *app_namespace_pool;

static u8 app_sapi_enabled;

app_namespace_t *
app_namespace_get (u32 index)
{
  return pool_elt_at_index (app_namespace_pool, index);
}

app_namespace_t *
app_namespace_get_from_id (const u8 *ns_id)
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

void
app_namespace_free (app_namespace_t *app_ns)
{
  hash_unset_mem (app_namespace_lookup_table, app_ns->ns_id);
  vec_free (app_ns->ns_id);

  pool_put (app_namespace_pool, app_ns);
}

app_namespace_t *
app_namespace_alloc (const u8 *ns_id)
{
  app_namespace_t *app_ns;

  pool_get (app_namespace_pool, app_ns);
  clib_memset (app_ns, 0, sizeof (*app_ns));

  app_ns->ns_id = vec_dup ((u8 *) ns_id);
  vec_terminate_c_string (app_ns->ns_id);

  hash_set_mem (app_namespace_lookup_table, app_ns->ns_id,
		app_ns - app_namespace_pool);

  return app_ns;
}

session_error_t
vnet_app_namespace_add_del (vnet_app_namespace_add_del_args_t *a)
{
  app_namespace_t *app_ns;
  session_table_t *st;
  u32 ns_index;
  session_error_t rv;

  if (a->is_add)
    {
      if (a->sw_if_index != APP_NAMESPACE_INVALID_INDEX
	  && !vnet_get_sw_interface_or_null (vnet_get_main (),
					     a->sw_if_index))
	return SESSION_E_INVALID;

      if (a->sw_if_index != APP_NAMESPACE_INVALID_INDEX)
	{
	  a->ip4_fib_id =
	    fib_table_get_table_id_for_sw_if_index (FIB_PROTOCOL_IP4,
						    a->sw_if_index);
	  a->ip6_fib_id =
	    fib_table_get_table_id_for_sw_if_index (FIB_PROTOCOL_IP6,
						    a->sw_if_index);
	}
      if (a->sw_if_index == APP_NAMESPACE_INVALID_INDEX
	  && a->ip4_fib_id == APP_NAMESPACE_INVALID_INDEX)
	return SESSION_E_INVALID;

      app_ns = app_namespace_get_from_id (a->ns_id);
      if (!app_ns)
	{
	  app_ns = app_namespace_alloc (a->ns_id);
	  st = session_table_alloc ();
	  session_table_init (st, FIB_PROTOCOL_MAX);
	  st->is_local = 1;
	  st->appns_index = app_namespace_index (app_ns);
	  app_ns->local_table_index = session_table_index (st);
	  if (a->sock_name)
	    {
	      app_ns->sock_name = vec_dup (a->sock_name);
	      vec_terminate_c_string (app_ns->sock_name);
	    }

	  /* Add socket for namespace,
	   * only at creation time */
	  if (app_sapi_enabled)
	    {
	      rv = appns_sapi_add_ns_socket (app_ns);
	      if (rv)
		return rv;
	    }
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
      ns_index = app_namespace_index_from_id (a->ns_id);
      if (ns_index == APP_NAMESPACE_INVALID_INDEX)
	return SESSION_E_INVALID;

      app_ns = app_namespace_get (ns_index);
      if (!app_ns)
	return SESSION_E_INVALID;

      application_namespace_cleanup (app_ns);

      if (app_sapi_enabled)
	appns_sapi_del_ns_socket (app_ns);

      st = session_table_get (app_ns->local_table_index);

      session_table_free (st, FIB_PROTOCOL_MAX);
      if (app_ns->sock_name)
	vec_free (app_ns->sock_name);

      app_namespace_free (app_ns);
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
  u8 *key;

  key = vec_dup ((u8 *) ns_id);
  vec_terminate_c_string (key);

  indexp = hash_get_mem (app_namespace_lookup_table, key);
  vec_free (key);
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

int
appns_sapi_enable_disable (int is_enable)
{
  /* This cannot be called with active sockets */
  if (pool_elts (app_namespace_pool))
    return -1;

  app_sapi_enabled = is_enable;
  return 0;
}

u8
appns_sapi_enabled (void)
{
  return app_sapi_enabled;
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

  /* clang-format off */
  vnet_app_namespace_add_del_args_t a = {
    .ns_id = ns_id,
    .sock_name = 0,
    .secret = 0,
    .sw_if_index = APP_NAMESPACE_INVALID_INDEX,
    .is_add = 1
  };
  /* clang-format on */

  vnet_app_namespace_add_del (&a);
  vec_free (ns_id);
}

static clib_error_t *
app_ns_fn (vlib_main_t * vm, unformat_input_t * input,
	   vlib_cli_command_t * cmd)
{
  u8 is_add = 0, *ns_id = 0, secret_set = 0, sw_if_index_set = 0;
  u8 *sock_name = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index, fib_id = APP_NAMESPACE_INVALID_INDEX;
  vnet_main_t *vnm = vnet_get_main ();
  u64 secret;
  clib_error_t *error = 0;
  int rv;

  session_cli_return_if_not_enabled ();

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "id %_%v%_", &ns_id))
	;
      else if (unformat (line_input, "secret %lu", &secret))
	secret_set = 1;
      else if (unformat (line_input, "sw_if_index %u", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (line_input, "if %U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (line_input, "fib_id", &fib_id))
	;
      else if (unformat (line_input, "sock-name %_%v%_", &sock_name))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!ns_id)
    {
      vlib_cli_output (vm, "namespace-id must be provided");
      goto done;
    }

  if (is_add && (!secret_set || !sw_if_index_set))
    {
      vlib_cli_output (vm, "secret and interface must be provided");
      goto done;
    }

  /* clang-format off */
  vnet_app_namespace_add_del_args_t args = {
    .ns_id = ns_id,
    .secret = secret,
    .sw_if_index = sw_if_index,
    .sock_name = sock_name,
    .ip4_fib_id = fib_id,
    .is_add = is_add,
  };
  /* clang-format on */

  if ((rv = vnet_app_namespace_add_del (&args)))
    error = clib_error_return (0, "app namespace add del returned %d", rv);

done:

  vec_free (ns_id);
  vec_free (sock_name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (app_ns_command, static) = {
  .path = "app ns",
  .short_help = "app ns [add|del] id <namespace-id> secret <secret> "
		"sw_if_index <sw_if_index> if <interface>",
  .function = app_ns_fn,
};
/* *INDENT-ON* */

u8 *
format_app_namespace (u8 * s, va_list * args)
{
  app_namespace_t *app_ns = va_arg (*args, app_namespace_t *);
  vnet_main_t *vnm = vnet_get_main ();

  s = format (s, "Application namespace [%u]\nid:        %s\nsecret:    %lu",
	      app_namespace_index (app_ns), app_ns->ns_id, app_ns->ns_secret);
  if (app_ns->sw_if_index != (u32) ~0)
    s = format (s, "\nInterface: %U", format_vnet_sw_if_index_name, vnm,
		app_ns->sw_if_index);
  if (app_ns->sock_name)
    s = format (s, "\nSocket:    %s", app_ns->sock_name);

  return s;
}

static void
app_namespace_show_api (vlib_main_t * vm, app_namespace_t * app_ns)
{
  app_ns_api_handle_t *handle;
  app_worker_t *app_wrk;
  clib_socket_t *cs;
  clib_file_t *cf;

  if (!app_sapi_enabled)
    {
      vlib_cli_output (vm, "app socket api not enabled!");
      return;
    }

  vlib_cli_output (vm, "socket: %v\n", app_ns->sock_name);

  if (!pool_elts (app_ns->app_sockets))
    return;

  vlib_cli_output (vm, "%12s%12s%5s", "app index", "wrk index", "fd");


  /* *INDENT-OFF* */
  pool_foreach (cs, app_ns->app_sockets)  {
    handle = (app_ns_api_handle_t *) &cs->private_data;
    cf = clib_file_get (&file_main, handle->aah_file_index);
    if (handle->aah_app_wrk_index == APP_INVALID_INDEX)
      {
	vlib_cli_output (vm, "%12d%12d%5u", -1, -1, cf->file_descriptor);
	continue;
      }
    app_wrk = app_worker_get (handle->aah_app_wrk_index);
    vlib_cli_output (vm, "%12d%12d%5u", app_wrk->app_index,
                     app_wrk->wrk_map_index, cf->file_descriptor);
  }
  /* *INDENT-ON* */
}

static clib_error_t *
show_app_ns_fn (vlib_main_t * vm, unformat_input_t * main_input,
		vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *ns_id = 0, do_table = 0, had_input = 1, do_api = 0;
  app_namespace_t *app_ns;
  vnet_main_t *vnm = vnet_get_main ();
  session_table_t *st;
  table_t table = {}, *t = &table;

  session_cli_return_if_not_enabled ();

  if (!unformat_user (main_input, unformat_line_input, line_input))
    {
      had_input = 0;
      goto do_ns_list;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "id %_%v%_", &ns_id))
	do_table = 1;
      else if (unformat (line_input, "api-clients"))
	do_api = 1;
      else
	{
	  vlib_cli_output (vm, "unknown input [%U]", format_unformat_error,
			   line_input);
	  goto done;
	}
    }

  if (do_api)
    {
      if (!do_table)
	{
	  vlib_cli_output (vm, "must specify a table for api");
	  goto done;
	}
      app_ns = app_namespace_get_from_id (ns_id);
      app_namespace_show_api (vm, app_ns);
      goto done;
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
      vlib_cli_output (vm, "%U", format_app_namespace, app_ns);
      session_lookup_show_table_entries (vm, st, 0, 1);
      vec_free (ns_id);
      goto done;
    }

do_ns_list:
  table_add_header_col (t, 5, "Index", "Secret", "Interface", "Id", "Socket");
  int i = 0;
  pool_foreach (app_ns, app_namespace_pool)
    {
      int j = 0;
      table_format_cell (t, i, j++, "%u", app_namespace_index (app_ns));
      table_format_cell (t, i, j++, "%lu", app_ns->ns_secret);
      table_format_cell (t, i, j++, "%U", format_vnet_sw_if_index_name, vnm,
			 app_ns->sw_if_index);
      table_format_cell (t, i, j++, "%s", app_ns->ns_id);
      table_format_cell (t, i++, j++, "%s", app_ns->sock_name);
    }

  t->default_body.align = TTAA_LEFT;
  t->default_header_col.align = TTAA_LEFT;
  t->default_header_col.fg_color = TTAC_YELLOW;
  t->default_header_col.flags = TTAF_FG_COLOR_SET;
  vlib_cli_output (vm, "%U", format_table, t);
  table_free (t);

done:
  if (had_input)
    unformat_free (line_input);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_app_ns_command, static) = {
  .path = "show app ns",
  .short_help = "show app ns [id <id> [api-clients]]",
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
