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

static clib_error_t *
show_crypto_handlers_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_crypto_main_t *cm = &crypto_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *s = 0;

  if (unformat_user (input, unformat_line_input, line_input))
    unformat_free (line_input);

  vlib_cli_output (vm, "%-40s%-20s%s", "Name", "Active", "Candidates");
  for (int i = 1; i < VNET_CRYPTO_N_OP_TYPES; i++)
    {
      vnet_crypto_op_type_data_t *otd = cm->opt_data + i;
      vnet_crypto_engine_t *e;

      vec_reset_length (s);
      vec_foreach (e, cm->engines)
	{
	  if (e->ops_handlers[i] != 0)
	    s = format (s, "%U ", format_vnet_crypto_engine, e - cm->engines);
	}
      vlib_cli_output (vm, "%-40U%-20U%v", format_vnet_crypto_op, i,
		       format_vnet_crypto_engine, otd->active_engine_index,s);
    }
  vec_free (s);
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
  int i, rc = 0;
  u8 *engine = 0;
  u8 *s = 0;
  vnet_crypto_op_type_t ot, *otp, *ots = 0;
  int all = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_crypto_op_type, &ot))
	vec_add1 (ots, ot);
      else if (unformat (line_input, "all"))
	all = 1;
      else if (unformat (line_input, "%s", &s))
	{
	  vec_free (engine);
	  engine = s;
	}
      else
	{
	  vec_free (engine);
	  vec_free (ots);
	  unformat_free (line_input);
	  return clib_error_return (0, "invalid params");
	}
    }
  unformat_free (line_input);

  if (vec_len (ots) == 0 && !all)
    return clib_error_return (0, "missing cipher(s)!");

  if (!engine)
    {
      vec_free (ots);
      return clib_error_return (0, "missing crypto engine!");
    }

  if (all)
    {
      for (i = 0; i < VNET_CRYPTO_N_OP_TYPES; i++)
	rc += vnet_crypto_set_handler (i, (char *) engine);

      if (rc)
	vlib_cli_output (vm, "failed to set crypto engine!");
    }
  else
    {
      vec_foreach (otp, ots)
      {
	rc = vnet_crypto_set_handler (otp[0], (char *) engine);
	if (rc)
	  {
	    vlib_cli_output (vm, "failed to set engine %s for type %d!",
			     engine, otp[0]);
	  }
      }
    }

  vec_free (ots);
  vec_free (engine);
  return 0;
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
