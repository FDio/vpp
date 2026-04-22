/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2017 RaydoNetworks.
 * Copyright (c) 2026 Hi-Jiajun.
 */
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <ppp/packet.h>
#include <pppoeclient/pppox/pppox.h>
#include <pppoeclient/pppox/pppd/pppd.h>

static clib_error_t *
pppox_set_auth_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  int r;
  u32 sw_if_index = ~0;
  u8 *username = 0;
  u8 *password = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw-if-index %d", &sw_if_index))
	;
      else if (unformat (line_input, "username %s", &username))
	;
      else if (unformat (line_input, "password %s", &password))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'", format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "missing required argument 'sw-if-index'");
      goto done;
    }

  if (!username)
    {
      error = clib_error_return (0, "missing required argument 'username'");
      goto done;
    }

  if (!password)
    {
      error = clib_error_return (0, "missing required argument 'password'");
      goto done;
    }

  r = pppox_set_auth (sw_if_index, username, password);

  if (r == VNET_API_ERROR_INVALID_INTERFACE)
    error = clib_error_return (0, "Invalid interface name");

done:
  unformat_free (line_input);
  vec_free (username);
  vec_free (password);

  return error;
}

/*?
 * Set pppox auth username and password
 *
 * @cliexpar
 * Example of how to set pppox pap secret:
 * @cliexcmd{pppox set auth username 027 password 720}
 ?*/
VLIB_CLI_COMMAND (pppox_set_auth_command, static) = {
  .path = "pppox set auth",
  .short_help = "pppox set auth sw-if-index <nn> username <string> password <string>",
  .function = pppox_set_auth_command_fn,
};
