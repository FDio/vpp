/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/format_ansi.h>
#include <vppinfra/format_table.h>
#include <vnet/crypto/crypto.h>

static const char *
crypto_alg_type_name (vnet_crypto_alg_type_t alg_type)
{
  switch (alg_type)
    {
    case VNET_CRYPTO_ALG_T_NONE:
      return "none";
    case VNET_CRYPTO_ALG_T_CIPHER:
      return "cipher";
    case VNET_CRYPTO_ALG_T_AEAD:
      return "aead";
    case VNET_CRYPTO_ALG_T_AUTH:
      return "auth";
    case VNET_CRYPTO_ALG_T_COMBINED:
      return "combined";
    }

  return "unknown";
}

static const char *
crypto_alg_family_name (vnet_crypto_alg_family_t family)
{
  static char *strings[] = {
#define _(n, s) [VNET_CRYPTO_ALG_FAMILY_##n] = s,
    foreach_crypto_alg_family
#undef _
  };

  if (family >= VNET_CRYPTO_N_ALG_FAMILIES)
    return "unknown";

  return strings[family];
}

static const char *
crypto_handler_type_name (vnet_crypto_handler_type_t t)
{
  static char *strings[] = {
#define _(n, s) [VNET_CRYPTO_HANDLER_TYPE_##n] = s,
    foreach_crypto_handler_type
#undef _
  };

  if (t >= VNET_CRYPTO_HANDLER_N_TYPES)
    return "unknown";

  return strings[t];
}

static void
show_crypto_algorithms_table (vlib_main_t *vm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  table_t table = {};
  u8 *s = 0;
  int row = 0;

  table_add_hdr_col (&table, 0);
  table_add_hdr_row (&table, 8, "Name", "Type", "Cipher", "Auth", "Key", "Auth", "AAD", "Block");
  for (int i = 0; i < 8; i++)
    table_set_cell_align (&table, -1, i, TTAA_LEFT);

  FOREACH_ARRAY_ELT (ad, cm->algs)
    {
      int c = -1;
      if (ad == cm->algs)
	continue;

      table_format_cell (&table, row, c++, "%s", ad->name);
      table_format_cell (&table, row, c++, "%s", crypto_alg_type_name (ad->alg_type));
      table_format_cell (&table, row, c++, "%s", crypto_alg_family_name (ad->cipher_family));
      table_format_cell (&table, row, c++, "%s", crypto_alg_family_name (ad->auth_family));
      table_format_cell (&table, row, c++, "%u", ad->key_len);
      if (ad->auth_len)
	table_format_cell (&table, row, c++, "%u", ad->auth_len);
      else
	table_format_cell (&table, row, c++, "%s", "var");
      if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
	{
	  if (ad->variable_aad_length == 0)
	    table_format_cell (&table, row, c++, "%u", ad->aad_len);
	  else
	    table_format_cell (&table, row, c++, "%s", "var");
	}
      else
	table_format_cell (&table, row, c++, "%s", "-");
      table_format_cell (&table, row, c++, "%u", ad->block_len);
      for (int i = -1; i < c; i++)
	table_set_cell_align (&table, row, i, TTAA_LEFT);
      row++;
    }

  s = format (s, "%U", format_table, &table);
  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  table_free (&table);
}

static void
show_crypto_algorithm_detail (vlib_main_t *vm, vnet_crypto_alg_t alg)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + alg;
  vnet_crypto_key_layout_t *kl = cm->key_layout + alg;
  vnet_crypto_engine_t *e;
  u32 n_threads = vlib_get_n_threads ();
  vnet_crypto_handler_type_t t;
  vnet_crypto_op_type_t op_type;

  vlib_cli_output (vm, "algorithm: %U", format_vnet_crypto_alg, alg);
  vlib_cli_output (vm, "  type: %s", crypto_alg_type_name (ad->alg_type));
  vlib_cli_output (vm, "  cipher-family: %s", crypto_alg_family_name (ad->cipher_family));
  vlib_cli_output (vm, "  auth-family: %s", crypto_alg_family_name (ad->auth_family));
  if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
    {
      if (ad->auth_len)
	{
	  if (ad->variable_aad_length)
	    vlib_cli_output (vm, "  lengths: block %u key %u icv %u aad var", ad->block_len,
			     ad->key_len, ad->auth_len);
	  else
	    vlib_cli_output (vm, "  lengths: block %u key %u icv %u aad %u", ad->block_len,
			     ad->key_len, ad->auth_len, ad->aad_len);
	}
      else
	{
	  if (ad->variable_aad_length)
	    vlib_cli_output (vm, "  lengths: block %u key %u icv var aad var", ad->block_len,
			     ad->key_len);
	  else
	    vlib_cli_output (vm, "  lengths: block %u key %u icv var aad %u", ad->block_len,
			     ad->key_len, ad->aad_len);
	}
    }
  else
    {
      if (ad->auth_len)
	vlib_cli_output (vm, "  lengths: block %u key %u icv %u", ad->block_len, ad->key_len,
			 ad->auth_len);
      else
	vlib_cli_output (vm, "  lengths: block %u key %u icv var", ad->block_len, ad->key_len);
    }
  vlib_cli_output (vm, "  variable-cipher-key-len: %u", ad->variable_cipher_key_length);
  vlib_cli_output (vm, "  variable-auth-key-len: %u", ad->variable_auth_key_length);
  vlib_cli_output (vm, "  key-data:");
  for (t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
    {
      vlib_cli_output (vm, "    %s: size %u offset %u", crypto_handler_type_name (t),
		       kl->key_data_size[t], kl->key_data_offset[t]);
    }
  vlib_cli_output (vm, "    total: %u", kl->total_key_data_size);

  vlib_cli_output (vm, "  ops:");
  vlib_cli_output (vm, "    %-10s%-8s%-18s%-18s%s", "type", "id", "simple", "chained", "async");
  for (op_type = 0; op_type < VNET_CRYPTO_OP_N_TYPES; op_type++)
    {
      vnet_crypto_op_id_t op = ad->op_by_type[op_type];

      if (op == VNET_CRYPTO_OP_NONE)
	continue;

      vlib_cli_output (
	vm, "    %-10U%-8u%-18U%-18U%U", format_vnet_crypto_op_type, op_type, op,
	format_vnet_crypto_engine, cm->active_engine_index[alg][VNET_CRYPTO_HANDLER_TYPE_SIMPLE],
	format_vnet_crypto_engine, cm->active_engine_index[alg][VNET_CRYPTO_HANDLER_TYPE_CHAINED],
	format_vnet_crypto_engine, cm->active_engine_index[alg][VNET_CRYPTO_HANDLER_TYPE_ASYNC]);
    }

  vec_foreach (e, cm->engines)
    {
      if (e == cm->engines || e->name == 0)
	continue;

      vlib_cli_output (vm, "  engine '%s':", e->name);
      vlib_cli_output (vm, "    key-data:");
      for (t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
	{
	  u8 support = 0;
	  u8 *support_vec = cm->engine_supports_alg[alg][t];
	  u32 key_data_size = e->key_data_sz[t][alg];
	  u8 key_data_per_thread = e->key_data_per_thread[t][alg];

	  if (support_vec && (e - cm->engines) < vec_len (support_vec))
	    support = support_vec[e - cm->engines];

	  if (support == 0)
	    continue;

	  if (key_data_per_thread)
	    vlib_cli_output (vm, "      %s: %u per-thread (%u total)", crypto_handler_type_name (t),
			     key_data_size, key_data_size * n_threads);
	  else
	    vlib_cli_output (vm, "      %s: %u", crypto_handler_type_name (t), key_data_size);
	}
    }
}

static clib_error_t *
show_crypto_algorithm_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_crypto_alg_t alg = VNET_CRYPTO_ALG_NONE;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      if (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT &&
	  !unformat (line_input, "%U", unformat_vnet_crypto_alg, &alg))
	{
	  unformat_free (line_input);
	  return clib_error_return (0, "unknown algorithm");
	}
      unformat_free (line_input);
    }

  if (alg == VNET_CRYPTO_ALG_NONE)
    show_crypto_algorithms_table (vm);
  else
    show_crypto_algorithm_detail (vm, alg);

  return 0;
}

VLIB_CLI_COMMAND (show_crypto_algorithm_command, static) = {
  .path = "show crypto algorithm",
  .short_help = "show crypto algorithm [algorithm]",
  .function = show_crypto_algorithm_command_fn,
};

static clib_error_t *
show_crypto_engines_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *p;

  if (unformat_user (input, unformat_line_input, line_input))
    unformat_free (line_input);

  if (vec_len (cm->engines) == 0)
    {
      vlib_cli_output (vm, "No crypto engines registered");
      return 0;
    }

  vlib_cli_output (vm, "%-20s%-8s%s", "Name", "Prio", "Description");
  vec_foreach (p, cm->engines)
    {
      if (p->name)
	vlib_cli_output (vm, "%-20s%-8u%s", p->name, p->priority, p->desc);
    }
  return 0;
}

VLIB_CLI_COMMAND (show_crypto_engines_command, static) =
{
  .path = "show crypto engines",
  .short_help = "show crypto engines",
  .function = show_crypto_engines_command_fn,
};

static clib_error_t *
show_crypto_handlers_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_crypto_main_t *cm = &crypto_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  table_t table = {}, *t = &table;
  u8 *cell = 0;
  u8 *s = 0;
  int row = 0;

  if (unformat_user (input, unformat_line_input, line_input))
    unformat_free (line_input);

  table_add_hdr_col (t, 0);
  table_add_hdr_row (t, 5, "Algorithm", "Op", "Simple", "Chained", "Async");
  for (int i = -1; i <= 3; i++)
    table_set_cell_align (t, -1, i, TTAA_LEFT);

  FOREACH_ARRAY_ELT (a, cm->algs)
    {
      int first = 1;

      if (a == cm->algs)
	continue;

      for (u32 i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
	if (a->op_by_type[i] != VNET_CRYPTO_OP_NONE)
	  {
	    vnet_crypto_op_id_t id = a->op_by_type[i];
	    vnet_crypto_op_data_t *od = cm->opt_data + id;
	    vnet_crypto_handler_type_t ht;

	    table_format_cell (t, row, -1, first ? "%s" : "", a->name);
	    table_format_cell (t, row, 0, "%U", format_crypto_op_type_short, i);
	    first = 0;

	    for (ht = 0; ht < VNET_CRYPTO_HANDLER_N_TYPES; ht++)
	      {
		vnet_crypto_engine_t *e;

		vec_foreach (e, cm->engines)
		  {
		    if (e->ops[id].handlers[ht])
		      {
			if (vec_len (cell))
			  cell = format (cell, " ");
			if (e->ops[id].handlers[ht] == od->handlers[ht])
			  cell = format (cell, ANSI_FG_CYAN "%s*" ANSI_RESET, e->name);
			else
			  cell = format (cell, "%s", e->name);
		      }
		  }

		if (vec_len (cell))
		  table_format_cell (t, row, 1 + ht,
				     ht == VNET_CRYPTO_HANDLER_TYPE_ASYNC ? "%v" : "%v  ", cell);
		else
		  table_format_cell (t, row, 1 + ht,
				     ht == VNET_CRYPTO_HANDLER_TYPE_ASYNC ? "%s" : "%s  ", "-");
		vec_reset_length (cell);
	      }

	    for (int i = -1; i <= 3; i++)
	      table_set_cell_align (t, row, i, TTAA_LEFT);
	    row++;
	  }
    }
  s = format (s, "%U", format_table, t);
  vlib_cli_output (vm, "%v", s);
  table_free (t);
  vec_free (cell);
  vec_free (s);

  return 0;
}

VLIB_CLI_COMMAND (show_crypto_handlers_command, static) =
{
  .path = "show crypto handlers",
  .short_help = "show crypto handlers",
  .function = show_crypto_handlers_command_fn,
};

static clib_error_t *
set_crypto_handler_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_crypto_main_t *cm = &crypto_main;
  int rc = 0;
  char **args = 0, *s, **arg;
  int all = 0;
  clib_error_t *error = 0;
  vnet_crypto_set_handlers_args_t ha = {};

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "all"))
	all = 1;
      else if (unformat (line_input, "simple"))
	ha.set_simple = 1;
      else if (unformat (line_input, "chained"))
	ha.set_chained = 1;
      else if (unformat (line_input, "both"))
	ha.set_simple = ha.set_chained = 1;
      else if (unformat (line_input, "async"))
	ha.set_async = 1;
      else if (unformat (line_input, "%s", &s))
	vec_add1 (args, s);
      else
	{
	  error = clib_error_return (0, "invalid params");
	  goto done;
	}
    }

  if ((vec_len (args) < 2 && !all) || (vec_len (args) == 0 && all))
    {
      error = clib_error_return (0, "missing cipher or engine!");
      goto done;
    }

  ha.engine = vec_elt_at_index (args, vec_len (args) - 1)[0];
  vec_del1 (args, vec_len (args) - 1);

  if (all)
    {
      char *key;
      u8 *value;

      hash_foreach_mem (key, value, cm->alg_index_by_name,
      ({
        (void) value;
	ha.handler_name = key;
	rc += vnet_crypto_set_handlers (&ha);
      }));

      if (rc)
	vlib_cli_output (vm, "failed to set crypto engine!");
    }
  else
    {
      vec_foreach (arg, args)
      {
	  ha.handler_name = arg[0];
	  rc = vnet_crypto_set_handlers (&ha);
	  if (rc)
	    vlib_cli_output (vm, "failed to set engine %s for %s!", ha.engine,
			     arg[0]);
      }
    }

done:
  vec_free (ha.engine);
  vec_foreach (arg, args) vec_free (arg[0]);
  vec_free (args);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (set_crypto_handler_command, static) = {
  .path = "set crypto handler",
  .short_help = "set crypto handler cipher [cipher2 cipher3 ...] engine"
		" [simple|chained|async]",
  .function = set_crypto_handler_command_fn,
};

static clib_error_t *
show_crypto_async_status_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  int i;

  if (unformat_user (input, unformat_line_input, line_input))
    unformat_free (line_input);

  for (i = 0; i < tm->n_vlib_mains; i++)
    {
      vlib_node_state_t state = vlib_node_get_state (
	vlib_get_main_by_index (i), cm->crypto_node_index);
      if (state == VLIB_NODE_STATE_POLLING)
	vlib_cli_output (vm, "threadId: %-6d POLLING", i);
      if (state == VLIB_NODE_STATE_INTERRUPT)
	vlib_cli_output (vm, "threadId: %-6d INTERRUPT", i);
      if (state == VLIB_NODE_STATE_DISABLED)
	vlib_cli_output (vm, "threadId: %-6d DISABLED", i);
    }
  return 0;
}

VLIB_CLI_COMMAND (show_crypto_async_status_command, static) =
{
  .path = "show crypto async status",
  .short_help = "show crypto async status",
  .function = show_crypto_async_status_command_fn,
};

static clib_error_t *
set_crypto_async_dispatch_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u8 adaptive = 0;
  u8 mode = VLIB_NODE_STATE_INTERRUPT;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "polling"))
	mode = VLIB_NODE_STATE_POLLING;
      else if (unformat (line_input, "interrupt"))
	mode = VLIB_NODE_STATE_INTERRUPT;
      else if (unformat (line_input, "adaptive"))
	adaptive = 1;
      else
	{
	  error = clib_error_return (0, "invalid params");
	  goto done;
	}
    }

  vnet_crypto_set_async_dispatch (mode, adaptive);
done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (set_crypto_async_dispatch_mode_command, static) = {
  .path = "set crypto async dispatch mode",
  .short_help = "set crypto async dispatch mode <polling|interrupt|adaptive>",
  .function = set_crypto_async_dispatch_command_fn,
};
