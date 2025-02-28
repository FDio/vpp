/*
 * config.c: crypto engines configuration
 *
 * Copyright (c) 2025 Cisco and/or its affiliates.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <stdbool.h>

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>

static clib_error_t *
config_one_crypto (vlib_main_t *vm, char *name, unformat_input_t *input)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_config_t *pc;
  clib_error_t *error = 0;
  uword *p;
  int is_enable = 0;
  int is_disable = 0;

  if (cm->config_index_by_name == 0)
    cm->config_index_by_name = hash_create_string (0, sizeof (uword));

  p = hash_get_mem (cm->config_index_by_name, name);
  if (p)
    {
      error = clib_error_return (0, "crypto '%s' already configured", name);
      goto done;
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	is_enable = 1;
      else if (unformat (input, "disable"))
	is_disable = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (is_enable && is_disable)
    {
      error = clib_error_return (0,
				 "please specify either enable or disable"
				 " for crypto '%s'",
				 name);
      goto done;
    }

  vec_add2 (cm->configs, pc, 1);
  hash_set_mem (cm->config_index_by_name, name, pc - cm->configs);
  pc->is_enabled = is_enable;
  pc->is_disabled = is_disable;
  pc->name = name;

done:
  return error;
}

static clib_error_t *
cryptos_config (vlib_main_t *vm, unformat_input_t *input)
{
  vnet_crypto_main_t *cm = &crypto_main;
  clib_error_t *error = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      unformat_input_t sub_input;
      u8 *s = 0;
      if (unformat (input, "crypto default %U", unformat_vlib_cli_sub_input,
		    &sub_input))
	{
	  cm->default_disabled = unformat (&sub_input, "disable") ? 1 : 0;

	  unformat_free (&sub_input);
	}
      else if (unformat (input, "crypto %s %U", &s,
			 unformat_vlib_cli_sub_input, &sub_input))
	{
	  error = config_one_crypto (vm, (char *) s, &sub_input);
	  unformat_free (&sub_input);
	  if (error)
	    goto done;
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, input);
	  {
	    vec_free (s);
	    goto done;
	  }
	}
    }

done:
  return error;
}

VLIB_EARLY_CONFIG_FUNCTION (cryptos_config, "cryptos");
