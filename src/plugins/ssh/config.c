/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <ssh/ssh.h>
#include <vlib/unix/unix.h>

#define SSH_DEFAULT_PORT  2222
#define SSH_HOST_KEY_FILE "ssh_host_ed25519_key"

static clib_error_t *
ssh_config_user (unformat_input_t *input, char *name)
{
  clib_error_t *err = 0;
  u32 n_keys = 0;
  char *type, *b64;

  while (err == 0 && unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "key %s %s", &type, &b64))
	{
	  err = ssh_user_add_key (name, type, b64);
	  n_keys++;
	  vec_free (type);
	  vec_free (b64);
	}
      else
	err = clib_error_return (0, "ssh: unknown input '%U' in user %s", format_unformat_error,
				 input, name);
    }

  if (err == 0 && n_keys == 0)
    err = clib_error_return (0, "ssh: user %s has no key", name);

  return err;
}

static clib_error_t *
ssh_config (vlib_main_t *vm, unformat_input_t *input)
{
  unformat_input_t sub;
  clib_error_t *err = 0;
  char *address = 0, *host_key = 0, *name;
  u32 port = SSH_DEFAULT_PORT;

  /* vlib calls the config function of every plugin, with empty input when there is no section */
  if (unformat_check_input (input) == UNFORMAT_END_OF_INPUT)
    return 0;

  while (err == 0 && unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "port %u", &port))
	;
      else if (unformat (input, "listen-address %s", &address))
	;
      else if (unformat (input, "host-key %s", &host_key))
	;
      else if (unformat (input, "user %s %U", &name, unformat_vlib_cli_sub_input, &sub))
	{
	  err = ssh_config_user (&sub, name);
	  unformat_free (&sub);
	  vec_free (name);
	}
      else
	err = clib_error_return (0, "ssh: unknown input '%U'", format_unformat_error, input);
    }

  if (err == 0 && vec_len (ssh_main.users) == 0)
    err = clib_error_return (0, "ssh: no user is configured");

  if (err == 0 && (port == 0 || port > 0xffff))
    err = clib_error_return (0, "ssh: invalid port %u", port);

  if (err == 0 && host_key == 0)
    {
      char *dir = vlib_unix_get_config_dir ();

      if (dir == 0)
	err = clib_error_return (0, "ssh: host-key is not set and there is no config-dir, set one");
      else
	{
	  host_key = (char *) format (0, "%s/%s%c", dir, SSH_HOST_KEY_FILE, 0);
	  log_info ("host-key is not set, using %s", host_key);
	}
    }

  if (err == 0)
    err = ssh_listen (address, port, host_key);

  vec_free (address);
  vec_free (host_key);

  return err;
}

VLIB_CONFIG_FUNCTION (ssh_config, "ssh");
