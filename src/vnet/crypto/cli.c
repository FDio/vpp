/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/format_ansi.h>
#include <vppinfra/format_table.h>
#include <vnet/crypto/crypto.h>

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
