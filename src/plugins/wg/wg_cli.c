/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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

#include <wg/wg.h>
#include <wg/wg_convert.h>

static clib_error_t *
wg_set_device_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  wg_main_t *wmp = &wg_main;
  clib_error_t *error = NULL;
  unformat_input_t _line_input, *line_input = &_line_input;

  char *private_key_64 = 0;
  u32 portSrc = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "private-key %s", &private_key_64))
	;
      else if (unformat (line_input, "port-src %d", &portSrc))
	;
      else
	{
	  error = clib_error_return (0, "Error input");
	  goto done;
	}
    }

  error = wg_device_set (wmp, private_key_64, portSrc);

done:
  unformat_free (line_input);
  return error;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_set_device_command, static) =
{
  .path = "wg set device",
  .short_help =
  "wg set device private-key <priv_key>"
  "port-src <port_src>",
  .function = wg_set_device_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
wg_remove_device_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  wg_main_t *wmp = &wg_main;
  clib_error_t *error = NULL;

  error = wg_device_clear (wmp);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_remove_device_command, static) =
{
  .path = "wg remove device",
  .short_help =
  "wg remove device",
  .function = wg_remove_device_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
wg_set_peer_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  wg_main_t *wmp = &wg_main;
  clib_error_t *error = NULL;
  unformat_input_t _line_input, *line_input = &_line_input;

  char *public_key_64 = 0;
  ip4_address_t allowed_ip;
  ip4_address_t ip4;
  u32 portDst = 0;
  u32 persistent_keepalive = 0;
  u32 tun_sw_if_index = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "public-key %s", &public_key_64))
	;
      else if (unformat
	       (line_input, "endpoint %U", unformat_ip4_address, &ip4))
	;
      else if (unformat (line_input, "port-dst %d", &portDst))
	;
      else if (unformat
	       (line_input, "persistent-keepalive %d", &persistent_keepalive))
	;
      else if (unformat
	       (line_input, "allowed-ip %U", unformat_ip4_address,
		&allowed_ip))
	;
      else if (unformat
	       (line_input, "tunnel %U",
		unformat_vnet_sw_interface, vnm, &tun_sw_if_index))
	;
      else
	{
	  error = clib_error_return (0, "Error input");
	  goto done;
	}
    }

  error = wg_peer_set (wmp, public_key_64,
		       ip4, allowed_ip, portDst,
		       tun_sw_if_index, persistent_keepalive);

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_set_peer_command, static) =
{
  .path = "wg set peer",
  .short_help =
  "wg set peer public-key <pub_key_other> private-key <priv_key>"
  "endpoint <ip4_dst> allowed-ip <ip4_tun> tunnel <tun_int>"
  "port-dst [port_dst] persistent-keepalive [keepalive_interval]",
  .function = wg_set_peer_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
wg_remove_peer_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  wg_main_t *wmp = &wg_main;

  char *public_key_64 = 0;

  unformat_input_t _line_input, *line_input = &_line_input;
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat (line_input, "public-key %s", &public_key_64))
    ;
  else
    {
      error = clib_error_return (0, "Error input");
      goto done;
    }

  error = wg_peer_remove (wmp, public_key_64);

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_remove_peer_command, static) =
{
  .path = "wg remove peer",
  .short_help =
  "wg remove peer <peer_pub_key>",
  .function = wg_remove_peer_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
wg_genkey_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  u8 secret[NOISE_PUBLIC_KEY_LEN];
  char secret_64[NOISE_KEY_LEN_BASE64];

  curve25519_gen_secret (secret);
  key_to_base64 (secret_64, secret);

  vlib_cli_output (vm, "%s", secret_64);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_genkey_command, static) =
{
  .path = "wg genkey ",
  .short_help =
  "wg genkey",
  .function = wg_genkey_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
wg_pubkey_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;

  char *secret_64 = 0;
  u8 secret[NOISE_PUBLIC_KEY_LEN];
  u8 public[NOISE_PUBLIC_KEY_LEN];
  char public_64[NOISE_KEY_LEN_BASE64];

  unformat_input_t _line_input, *line_input = &_line_input;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat (line_input, "%s", &secret_64))
    {
      if (!(key_from_base64 (secret, secret_64)))
	{
	  error = clib_error_return (0, "Error parce private key");
	  goto done;
	}
    }
  else
    {
      error = clib_error_return (0, "Error input");
      goto done;
    }

  if (!curve25519_gen_public (public, secret))
    {
      error = clib_error_return (0, "Error public key generating");
      return error;
    }

  key_to_base64 (public_64, public);
  vlib_cli_output (vm, "%s", public_64);

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_pubkey_command, static) =
{
  .path = "wg pubkey ",
  .short_help =
  "wg pubkey",
  .function = wg_pubkey_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
wg_peers_count_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  wg_main_t *wmp = &wg_main;
  clib_error_t *error = NULL;

  vlib_cli_output (vm, "%d", pool_elts (wmp->peers));

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_peers_count_command, static) =
{
  .path = "wg peers count",
  .short_help =
  "wg peers count",
  .function = wg_peers_count_command_fn,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
