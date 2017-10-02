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

u32
app_namespace_index (app_namespace_t *app_ns)
{
  return (app_ns - app_namespace_pool);
}

app_namespace_t *
app_namespace_alloc (u8 *ns_id)
{
  app_namespace_t *app_ns;
  pool_get (app_namespace_pool, app_ns);
  memset (app_ns, 0, sizeof (*app_ns));
  app_ns->ns_id = vec_dup (ns_id);
  hash_set_mem (app_namespace_lookup_table, ns_id,
                app_ns - app_namespace_pool);
  return app_ns;
}

int
vnet_app_namespace_add_del (vnet_app_namespace_add_del_args_t *a)
{
  app_namespace_t *app_ns;
  session_lookup_table_t *slt;
  if (a->is_add)
    {
      slt = session_table_alloc ();
      session_table_init (slt);

      app_ns = app_namespace_alloc (a->ns_id);
      app_ns->ns_secret = a->secret;
      app_ns->sw_if_index = a->sw_if_index;
      app_ns->local_table_index = session_table_index (slt);
    }
  else
    {
      clib_warning ("namespace deletion not supported");
      return -1;
    }
  return 0;
}

const u8 *
app_namespace_id (app_namespace_t *app_ns)
{
  return app_ns->ns_id;
}

u32
app_namespace_index_from_id (u8 *ns_id)
{
  uword *indexp;
  indexp = hash_get_mem (app_namespace_lookup_table, ns_id);
  if (!indexp)
    return APP_NAMESPACE_INVALID_INDEX;
  return *indexp;
}

void
app_namespaces_init (void)
{
  u8 *ns_id = format (0, "default%c", 0);

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
  app_namespace_lookup_table = hash_create_vec (0, sizeof(u8), sizeof(uword));
  vec_free (ns_id);
}

static clib_error_t *
app_ns_fn (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 is_add = 0, *ns_id = 0, secret_set = 0, sw_if_index_set = 0;
  app_namespace_t *app_ns;
  u64 secret;

  session_cli_return_if_not_enabled ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "id %_%v%_", &ns_id))
	;
      else if (unformat (input, "secret %lu", &secret))
	secret_set = 1;
      else if (unformat (input, "sw_if_index %u", &sw_if_index))
	sw_if_index_set = 1;
      else
	return clib_error_return(0, "unknown input `%U'", format_unformat_error,
	                         input);
    }

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
	 .is_add = 1
      };
      vnet_app_namespace_add_del (&args);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (session_enable_disable_command, static) =
{
  .path = "app ns",
  .short_help = "app ns [add] id <namespace-id> secret <secret> "
      "sw_if_index <sw_if_index>",
  .function = app_ns_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_app_ns_fn (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 is_add = 0, *ns_id = 0;
  app_namespace_t *app_ns;

  session_cli_return_if_not_enabled ();

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return(0, "unknown input `%U'", format_unformat_error,
	                     input);

  pool_foreach (app_ns, app_namespace_pool, ({

  }));

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (session_enable_disable_command, static) =
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



