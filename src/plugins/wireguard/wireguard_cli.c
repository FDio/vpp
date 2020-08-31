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

#include <wireguard/wireguard.h>
#include <wireguard/wireguard_key.h>
#include <wireguard/wireguard_peer.h>
#include <wireguard/wireguard_itf.h>


static clib_error_t *
wg_peer_add_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = NULL;
  unformat_input_t _line_input, *line_input = &_line_input;

  u8 *public_key_64 = 0;
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

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "peer"))
	{
	  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (line_input, "public-key %s", &public_key_64))
		;
	      else
		if (unformat
		    (line_input, "endpoint %U", unformat_ip_address, &ip))
		;
	      else if (unformat (line_input, "table-id %d", &table_id))
		;
	      else if (unformat (line_input, "dst-port %d", &portDst))
		;
	      else if (unformat
		       (line_input, "persistent-keepalive %d",
			&persistent_keepalive))
		;
	      else if (unformat (line_input, "allowed-ip %U",
				 unformat_ip_prefix, &pfx))
		{
		  ip_prefix_to_fib_prefix (&pfx, &allowed_ip);
		  vec_add1 (allowed_ips, allowed_ip);
		}
	      else
		{
		  error = clib_error_return (0, "Input error");
		  goto done;
		}
	    }
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

  if (AF_IP6 == ip_addr_version (&ip) ||
      FIB_PROTOCOL_IP6 == allowed_ip.fp_proto)
    rv = VNET_API_ERROR_INVALID_PROTOCOL;
  else
    rv = wg_peer_add (tun_sw_if_index, public_key_64,
		      table_id,
		      &ip_addr_46 (&ip),
		      allowed_ips,
		      portDst, persistent_keepalive, &peer_index);

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
      error = clib_error_return (0, "wg device parameters is not set");
      break;
    case VNET_API_ERROR_INVALID_PROTOCOL:
      error = clib_error_return (0, "ipv6 not supported yet");
      break;
    }

done:
  vec_free (allowed_ips);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_peer_add_command, static) =
{
  .path = "wg peer add",
  .short_help = "wg peer add <wg_int> public-key <pub_key_other>"
  "endpoint <ip4_dst> allowed-ip <prefix>"
  "dst-port [port_dst] persistent-keepalive [keepalive_interval]",
  .function = wg_peer_add_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
wg_peer_remove_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  u32 peer_index;
  int rv;

  unformat_input_t _line_input, *line_input = &_line_input;
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

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
  .path = "wg peer remove",
  .short_help = "wg peer remove <index>",
  .function = wg_peer_remove_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
wg_genkey_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  u8 secret[NOISE_PUBLIC_KEY_LEN];
  u8 secret_64[NOISE_KEY_LEN_BASE64];

  curve25519_gen_secret (secret);
  key_to_base64 (secret, NOISE_PUBLIC_KEY_LEN, secret_64);
  vlib_cli_output (vm, "key-base64: %s", secret_64);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_genkey_command, static) =
{
  .path = "wg genkey ",
  .short_help = "wg genkey",
  .function = wg_genkey_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
wg_pubkey_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;

  u8 *privatev = NULL;
  u8 private[NOISE_PUBLIC_KEY_LEN];
  u8 public[NOISE_PUBLIC_KEY_LEN];
  u8 public_64[NOISE_KEY_LEN_BASE64];

  unformat_input_t _line_input, *line_input = &_line_input;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat (line_input, "binary %v", &privatev))
    {
      clib_memcpy (private, privatev,
		   clib_min (NOISE_PUBLIC_KEY_LEN, vec_len (privatev)));
    }
  else if (unformat (line_input, "base64 %v", &privatev))
    {
      if (!(key_from_base64 (privatev, NOISE_KEY_LEN_BASE64, private)))
	{
	  error = clib_error_return (0, "Error parsing private key");
	  goto done;
	}
    }
  else
    {
      error = clib_error_return (0, "Input error");
      goto done;
    }

  if (!curve25519_gen_public (public, private))
    {
      error = clib_error_return (0, "Error generating public key");
      return error;
    }

  key_to_base64 (public, NOISE_PUBLIC_KEY_LEN, public_64);
  vlib_cli_output (vm, "key-base64: %s", public_64);

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_pubkey_command, static) =
{
  .path = "wg pubkey",
  .short_help = "wg pubkey <binary KEY> <base64 KEY>",
  .function = wg_pubkey_command_fn,
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
  .path = "show wg peer",
  .short_help = "show wg peer",
  .function = wg_show_peer_command_fn,
};
/* *INDENT-ON* */

static walk_rc_t
wg_itf_show_one (index_t itfi, void *arg)
{
  vlib_cli_output (arg, "%U", format_wg_itf, itfi);

  return (WALK_CONTINUE);
}

static clib_error_t *
wg_show_itf_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  wg_itf_walk (wg_itf_show_one, vm);

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (wg_show_itfs_command, static) =
{
  .path = "show wg itf",
  .short_help = "show wg itf",
  .function = wg_show_itf_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
