/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>

#include <lina/shared.h>
#include <lina/lina.h>

static clib_error_t *
lina_create_instance_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  lina_create_instance_args_t args = { 0 };

  args.hw_if_index = ~0;
  args.ring_size = 1024;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "interface %U", unformat_vnet_hw_interface, vnm,
	   &args.hw_if_index))
	;
      else if (unformat (line_input, "listener %s", &args.filename))
	;
      else if (unformat (line_input, "ring-size %u", &args.ring_size))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (args.hw_if_index == ~0)
    return clib_error_return (0, "please specifty interface");

  if (args.filename == 0)
    return clib_error_return (0, "please specifty listener filename");

  lina_create_instance (vm, &args);

  if (args.error)
    return args.error;

  vlib_cli_output (vm, "instance created\n");

  vec_free (args.filename);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lina_create_instance_command, static) = {
  .path = "lina create-instance",
  .short_help = "lina create-instance <filename>",
  .function = lina_create_instance_fn,
};
/* *INDENT-ON* */

static clib_error_t *
lina_show_command_fn (vlib_main_t * vm, unformat_input_t * input,
		      vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "TODO\n");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lina_show_command, static) = {
  .path = "show lina",
  .short_help = "show lina",
  .function = lina_show_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
lina_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (lina_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
