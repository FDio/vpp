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
show_crypto_providers_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_provider_t *p;

  if (unformat_user (input, unformat_line_input, line_input))
    unformat_free (line_input);

  if (vec_len (cm->providers) == 0)
    {
      vlib_cli_output (vm, "No crypto providers registered");
      return 0;
    }

  vlib_cli_output (vm, "%-20s%-8s%s", "Name", "Prio", "Description");
  vec_foreach (p, cm->providers)
    {
      vlib_cli_output (vm, "%-20s%-8u%s", p->name, p->priority, p->desc);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_crypto_providers_command, static) =
{
  .path = "show crypto providers",
  .short_help = "show crypto providers",
  .function = show_crypto_providers_command_fn,
};

static clib_error_t *
show_crypto_algorithms_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *a;

  if (unformat_user (input, unformat_line_input, line_input))
    unformat_free (line_input);

  vlib_cli_output (vm, "%s", "Name");
  for (int i = 0; i < VNET_CRYPTO_N_ALGS; i++)
    {
      a = &cm->algs[i];
      vlib_cli_output (vm, "%s", a->name);
    }
  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_crypto_algorithms_command, static) =
{
  .path = "show crypto algorithms",
  .short_help = "show crypto algorithms",
  .function = show_crypto_algorithms_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
