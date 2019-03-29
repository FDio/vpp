/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <stdbool.h>
#include <vlib/vlib.h>
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
  /* *INDENT-OFF* */
  vec_foreach (p, cm->engines)
    {
      vlib_cli_output (vm, "%-20s%-8u%s", p->name, p->priority, p->desc);
    }
  /* *INDENT-ON* */
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_crypto_engines_command, static) =
{
  .path = "show crypto engines",
  .short_help = "show crypto engines",
  .function = show_crypto_engines_command_fn,
};

static u8 *
format_vnet_crypto_handlers (u8 * s, va_list * args)
{
  vnet_crypto_alg_t alg = va_arg (*args, vnet_crypto_alg_t);
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *d = vec_elt_at_index (cm->algs, alg);
  u32 indent = format_get_indent (s);
  int i, first = 1;

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    {
      vnet_crypto_op_data_t *od;
      vnet_crypto_engine_t *e;
      vnet_crypto_op_id_t id = d->op_by_type[i];

      if (id == 0)
	continue;

      od = vec_elt_at_index (cm->opt_data, id);
      if (first == 0)
        s = format (s, "\n%U", format_white_space, indent);
      s = format (s, "%-20U%-20U", format_vnet_crypto_op_type, od->type,
		  format_vnet_crypto_engine, od->active_engine_index,s);

      vec_foreach (e, cm->engines)
	{
	  if (e->ops_handlers[id] != 0)
	    s = format (s, "%U ", format_vnet_crypto_engine, e - cm->engines);
	}
      first = 0;
    }
  return s;
}


static clib_error_t *
show_crypto_handlers_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  int i;

  if (unformat_user (input, unformat_line_input, line_input))
    unformat_free (line_input);

  vlib_cli_output (vm, "%-20s%-20s%-20s%s", "Algo", "Type", "Active",
		   "Candidates");

  for (i = 0; i < VNET_CRYPTO_N_ALGS; i++)
    vlib_cli_output (vm, "%-20U%U", format_vnet_crypto_alg, i,
		     format_vnet_crypto_handlers, i);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_crypto_handlers_command, static) =
{
  .path = "show crypto handlers",
  .short_help = "show crypto handlers",
  .function = show_crypto_handlers_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
set_crypto_handler_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_crypto_main_t *cm = &crypto_main;
  int rc = 0;
  char **args = 0, *s, **arg, *engine = 0;
  int all = 0;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "all"))
	all = 1;
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

  engine = vec_elt_at_index (args, vec_len (args) - 1)[0];
  vec_del1 (args, vec_len (args) - 1);

  if (all)
    {
      char *key;
      u8 *value;

      /* *INDENT-OFF* */
      hash_foreach_mem (key, value, cm->alg_index_by_name,
      ({
        (void) value;
        rc += vnet_crypto_set_handler (key, engine);
      }));
      /* *INDENT-ON* */

      if (rc)
	vlib_cli_output (vm, "failed to set crypto engine!");
    }
  else
    {
      vec_foreach (arg, args)
      {
	rc = vnet_crypto_set_handler (arg[0], engine);
	if (rc)
	  {
	    vlib_cli_output (vm, "failed to set engine %s for %s!",
			     engine, arg[0]);
	  }
      }
    }

done:
  vec_free (engine);
  vec_foreach (arg, args) vec_free (arg[0]);
  vec_free (args);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_crypto_handler_command, static) =
{
  .path = "set crypto handler",
  .short_help = "set crypto handler cipher [cipher2 cipher3 ...] engine",
  .function = set_crypto_handler_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
