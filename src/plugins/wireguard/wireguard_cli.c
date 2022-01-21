/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <wireguard/wireguard.h>
#include <wireguard/wireguard_key.h>
#include <wireguard/wireguard_peer.h>
#include <wireguard/wireguard_if.h>

static clib_error_t *
wg_if_create_cli (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  wg_main_t *wmp = &wg_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 private_key[NOISE_PUBLIC_KEY_LEN];
  u32 instance, sw_if_index;
  ip_address_t src_ip;
  clib_error_t *error;
  u8 *private_key_64;
  u32 port, generate_key = 0;
  int rv;

  error = NULL;
  instance = sw_if_index = ~0;
  private_key_64 = 0;
  port = 0;

  wg_feature_init (wmp);

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "instance %d", &instance))
	    ;
	  else if (unformat (line_input, "private-key %s", &private_key_64))
	    {
	      if (!(key_from_base64 (private_key_64,
				     NOISE_KEY_LEN_BASE64, private_key)))
		{
		  error = clib_error_return (0, "Error parsing private key");
		  break;
		}
	    }
	  else if (unformat (line_input, "listen-port %d", &port))
	    ;
	  else if (unformat (line_input, "port %d", &port))
	    ;
	  else if (unformat (line_input, "generate-key"))
	    generate_key = 1;
	  else
	    if (unformat (line_input, "src %U", unformat_ip_address, &src_ip))
	    ;
	  else
	    {
	      error = clib_error_return (0, "unknown input: %U",
					 format_unformat_error, line_input);
	      break;
	    }
	}

      unformat_free (line_input);

      if (error)
	return error;
    }

  if (generate_key)
    curve25519_gen_secret (private_key);

  rv = wg_if_create (instance, private_key, port, &src_ip, &sw_if_index);

  if (rv)
    return clib_error_return (0, "wireguard interface create failed");

  vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);
  return 0;
}

/*?
 * Create a Wireguard interface.
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_if_create_command, static) = {
  .path = "wireguard create",
  .short_help = "wireguard create listen-port <port> "
    "private-key <key> src <IP> [generate-key]",
  .function = wg_if_create_cli,
};
/* *INDENT-ON* */

static clib_error_t *
wg_if_delete_cli (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  wg_main_t *wmp = &wg_main;
  vnet_main_t *vnm;
  u32 sw_if_index;
  int rv;

  wg_feature_init (wmp);

  vnm = vnet_get_main ();
  sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  if (~0 != sw_if_index)
    {
      rv = wg_if_delete (sw_if_index);

      if (rv)
	return clib_error_return (0, "wireguard interface delete failed");
    }
  else
    return clib_error_return (0, "no such interface: %U",
			      format_unformat_error, input);

  return 0;
}

/*?
 * Delete a Wireguard interface.
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_if_delete_command, static) = {
  .path = "wireguard delete",
  .short_help = "wireguard delete <interface>",
  .function = wg_if_delete_cli,
};
/* *INDENT-ON* */


static clib_error_t *
wg_peer_add_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  wg_main_t *wmp = &wg_main;
  clib_error_t *error = NULL;
  unformat_input_t _line_input, *line_input = &_line_input;

  u8 *public_key_64 = 0;
  u8 public_key[NOISE_PUBLIC_KEY_LEN];
  fib_prefix_t allowed_ip, *allowed_ips = NULL;
  ip_prefix_t pfx;
  ip_address_t ip;
  u32 portDst = 0, table_id = 0;
  u32 persistent_keepalive = 0;
  u32 tun_sw_if_index = ~0;
  u32 peer_index;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  wg_feature_init (wmp);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "public-key %s", &public_key_64))
	{
	  if (!(key_from_base64 (public_key_64,
				 NOISE_KEY_LEN_BASE64, public_key)))
	    {
	      error = clib_error_return (0, "Error parsing private key");
	      goto done;
	    }
	}
      else if (unformat (line_input, "endpoint %U", unformat_ip_address, &ip))
	;
      else if (unformat (line_input, "table-id %d", &table_id))
	;
      else if (unformat (line_input, "dst-port %d", &portDst))
	;
      else if (unformat (line_input, "persistent-keepalive %d",
			 &persistent_keepalive))
	;
      else if (unformat (line_input, "allowed-ip %U",
			 unformat_ip_prefix, &pfx))
	{
	  ip_prefix_to_fib_prefix (&pfx, &allowed_ip);
	  vec_add1 (allowed_ips, allowed_ip);
	}
      else if (unformat (line_input, "%U",
			 unformat_vnet_sw_interface, vnm, &tun_sw_if_index))
	;
      else
	{
	  error = clib_error_return (0, "Input error");
	  goto done;
	}
    }

  rv = wg_peer_add (tun_sw_if_index, public_key, table_id, &ip_addr_46 (&ip),
		    allowed_ips, portDst, persistent_keepalive, &peer_index);

  switch (rv)
    {
    case VNET_API_ERROR_KEY_LENGTH:
      error = clib_error_return (0, "Error parsing public key");
      break;
    case VNET_API_ERROR_ENTRY_ALREADY_EXISTS:
      error = clib_error_return (0, "Peer already exist");
      break;
    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      error = clib_error_return (0, "Tunnel is not specified");
      break;
    case VNET_API_ERROR_LIMIT_EXCEEDED:
      error = clib_error_return (0, "Max peers limit");
      break;
    case VNET_API_ERROR_INIT_FAILED:
      error = clib_error_return (0, "wireguard device parameters is not set");
      break;
    case VNET_API_ERROR_INVALID_PROTOCOL:
      error = clib_error_return (0, "ipv6 not supported yet");
      break;
    }

done:
  vec_free (public_key_64);
  vec_free (allowed_ips);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_peer_add_command, static) = {
  .path = "wireguard peer add",
  .short_help =
    "wireguard peer add <wg_int> public-key <pub_key_other> "
    "endpoint <ip4_dst> allowed-ip <prefix> "
    "dst-port [port_dst] persistent-keepalive [keepalive_interval]",
  .function = wg_peer_add_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
wg_peer_remove_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  wg_main_t *wmp = &wg_main;
  clib_error_t *error = NULL;
  u32 peer_index;
  int rv;

  unformat_input_t _line_input, *line_input = &_line_input;
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  wg_feature_init (wmp);

  if (unformat (line_input, "%d", &peer_index))
    ;
  else
    {
      error = clib_error_return (0, "Input error");
      goto done;
    }

  rv = wg_peer_remove (peer_index);

  switch (rv)
    {
    case VNET_API_ERROR_KEY_LENGTH:
      error = clib_error_return (0, "Error parsing public key");
      break;
    }

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_peer_remove_command, static) =
{
  .path = "wireguard peer remove",
  .short_help = "wireguard peer remove <index>",
  .function = wg_peer_remove_command_fn,
};
/* *INDENT-ON* */

static walk_rc_t
wg_peer_show_one (index_t peeri, void *arg)
{
  vlib_cli_output (arg, "%U", format_wg_peer, peeri);

  return (WALK_CONTINUE);
}

static clib_error_t *
wg_show_peer_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  wg_peer_walk (wg_peer_show_one, vm);

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_show_peers_command, static) =
{
  .path = "show wireguard peer",
  .short_help = "show wireguard peer",
  .function = wg_show_peer_command_fn,
};
/* *INDENT-ON* */

static walk_rc_t
wg_if_show_one (index_t itfi, void *arg)
{
  vlib_cli_output (arg, "%U", format_wg_if, itfi);

  return (WALK_CONTINUE);
}

static clib_error_t *
wg_show_if_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  wg_main_t *wmp = &wg_main;

  wg_feature_init (wmp);

  wg_if_walk (wg_if_show_one, vm);

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_show_itfs_command, static) =
{
  .path = "show wireguard interface",
  .short_help = "show wireguard",
  .function = wg_show_if_command_fn,
};

static clib_error_t *
wg_set_async_mode_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  int async_enable = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on"))
	async_enable = 1;
      else if (unformat (line_input, "off"))
	async_enable = 0;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input));
    }

  wg_set_async_mode (async_enable);

  unformat_free (line_input);
  return (NULL);
}

VLIB_CLI_COMMAND (wg_set_async_mode_command, static) = {
  .path = "set wireguard async mode",
  .short_help = "set wireguard async mode on|off",
  .function = wg_set_async_mode_command_fn,
};

static clib_error_t *
wg_show_mode_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  vlib_cli_output (vm, "Wireguard mode");

#define _(v, f, s)                                                            \
  vlib_cli_output (vm, "\t%s: %s", s,                                         \
		   (wg_op_mode_is_set_##f () ? "enabled" : "disabled"));
  foreach_wg_op_mode_flags
#undef _

    return (NULL);
}

VLIB_CLI_COMMAND (wg_show_modemode_command, static) = {
  .path = "show wireguard mode",
  .short_help = "show wireguard mode",
  .function = wg_show_mode_command_fn,
};

/* *INDENT-ON* */

static clib_error_t *
wg_set_blake_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  wg_main_t *wmp = &wg_main;
  wmp->blake3 = false;
  clib_error_t *error = NULL;

  unformat_input_t _line_input, *line_input = &_line_input;
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  if (unformat (line_input, "%d", &(wmp->blake3)))
    ;
  else
    {
      error = clib_error_return (0, "Input error");
      goto done;
    }

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (wg_set_blake_command, static) = {
  .path = "set wireguard blake3",
  .short_help = "set wireguard blake3 [0|1]",
  .function = wg_set_blake_command_fn,
};
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
