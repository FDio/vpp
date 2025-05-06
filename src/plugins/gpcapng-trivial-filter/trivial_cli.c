/*
 * trivial_cli.c - CLI commands for trivial filter
 *
 * Copyright (c) 2024 Cisco Systems, Inc.
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <gpcapng/public_inlines.h>
#include "trivial_filter.h"

/*
 * GPCAPNG plugin method vtable
 */
static gpcapng_plugin_methods_t gpcapng_plugin;

static clib_error_t *
gpcapng_filter_trivial_command_fn (vlib_main_t *vm,
                                   unformat_input_t *input,
                                   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  trivial_filter_main_t *tfm = get_trivial_filter_main ();
  clib_error_t *error = 0;
  u8 *destination_name = 0;
  u32 destination_index = ~0;
  u8 capture_all = 0;
  u8 capture_none = 0;

  /* Initialize gpcapng plugin exports if not already done */
  if (!gpcapng_plugin.find_destination_by_name)
    {
      clib_error_t *gpcapng_init_res = gpcapng_plugin_exports_init (&gpcapng_plugin);
      if (gpcapng_init_res)
        return gpcapng_init_res;
    }

  /* Get a line of input */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected 'capture-all destination {none | name <name>}'");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "capture-all"))
        {
          capture_all = 1;
        }
      else if (unformat (line_input, "destination"))
        {
          if (unformat (line_input, "none"))
            {
              capture_none = 1;
            }
          else if (unformat (line_input, "name %s", &destination_name))
            {
              /* Destination name will be resolved below */
            }
          else
            {
              error = clib_error_return (0, "expected 'none' or 'name <destination-name>'");
              goto done;
            }
        }
      else
        {
          error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
          goto done;
        }
    }

  /* Validate command syntax */
  if (!capture_all)
    {
      error = clib_error_return (0, "expected 'capture-all' keyword");
      goto done;
    }

  if (capture_none && destination_name)
    {
      error = clib_error_return (0, "cannot specify both 'none' and destination name");
      goto done;
    }

  if (!capture_none && !destination_name)
    {
      error = clib_error_return (0, "must specify either 'none' or destination name");
      goto done;
    }

  /* Configure the filter */
  if (capture_none)
    {
      tfm->mode = TRIVIAL_FILTER_CAPTURE_NONE;
      tfm->destination_index = ~0;
      vlib_cli_output (vm, "Trivial filter set to capture no packets");
    }
  else
    {
      /* Resolve destination name */
      destination_index = gpcapng_plugin.find_destination_by_name ((char *) destination_name);
      if (destination_index == ~0)
        {
          error = clib_error_return (0, "destination '%s' not found", destination_name);
          goto done;
        }

      tfm->mode = TRIVIAL_FILTER_CAPTURE_ALL;
      tfm->destination_index = destination_index;
      vlib_cli_output (vm, "Trivial filter set to capture all packets to destination '%s' (index %u)", 
                       destination_name, destination_index);
    }

done:
  if (destination_name)
    vec_free (destination_name);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (gpcapng_filter_trivial_command, static) =
{
  .path = "gpcapng filter trivial",
  .short_help = "gpcapng filter trivial capture-all destination {none | name <name>}",
  .function = gpcapng_filter_trivial_command_fn,
};