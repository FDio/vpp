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
  u8 private_key[NOISE_PUBLIC_KEY_LEN + 1];
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
VLIB_CLI_COMMAND (wg_if_create_command, static) = {
  .path = "wireguard create",
  .short_help = "wireguard create listen-port <port> "
    "private-key <key> src <IP> [generate-key]",
  .function = wg_if_create_cli,
};

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
VLIB_CLI_COMMAND (wg_if_delete_command, static) = {
  .path = "wireguard delete",
  .short_help = "wireguard delete <interface>",
  .function = wg_if_delete_cli,
};


static clib_error_t *
wg_peer_add_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  wg_main_t *wmp = &wg_main;
  clib_error_t *error = NULL;
  unformat_input_t _line_input, *line_input = &_line_input;

  u8 *public_key_64 = 0;
  u8 public_key[NOISE_PUBLIC_KEY_LEN + 1];
  fib_prefix_t allowed_ip, *allowed_ips = NULL;
  ip_prefix_t pfx;
  ip_address_t ip = ip_address_initializer;
  ip_address_t obfuscation_ip = ip_address_initializer;
  u32 portDst = 0, table_id = 0;
  u32 persistent_keepalive = 0;
  u32 tun_sw_if_index = ~0;
  u32 peer_index;
  bool obfuscate = false;
  u32 obfuscation_port = 0;
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
      else if (unformat (line_input, "obfuscate"))
	obfuscate = true;
      else if (unformat (line_input, "obfuscation-endpoint %U",
			 unformat_ip_address, &obfuscation_ip))
	;
      else if (unformat (line_input, "obfuscation-port %d", &obfuscation_port))
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

  if (0 == vec_len (allowed_ips))
    {
      error = clib_error_return (0, "Allowed IPs are not specified");
      goto done;
    }

  rv = wg_peer_add (tun_sw_if_index, public_key, table_id, &ip_addr_46 (&ip),
		    allowed_ips, portDst, persistent_keepalive, obfuscate,
		    &ip_addr_46 (&obfuscation_ip), obfuscation_port,
		    &peer_index);

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

VLIB_CLI_COMMAND (wg_peer_add_command, static) = {
  .path = "wireguard peer add",
  .short_help =
    "wireguard peer add <wg_int> public-key <pub_key_other> "
    "endpoint <ip4_dst> allowed-ip <prefix> "
    "dst-port [port_dst] persistent-keepalive [keepalive_interval] "
    "[obfuscate] [obfuscation-endpoint <ip>] [obfuscation-port <port>]",
  .function = wg_peer_add_command_fn,
};

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

VLIB_CLI_COMMAND (wg_peer_remove_command, static) =
{
  .path = "wireguard peer remove",
  .short_help = "wireguard peer remove <index>",
  .function = wg_peer_remove_command_fn,
};

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

VLIB_CLI_COMMAND (wg_show_peers_command, static) =
{
  .path = "show wireguard peer",
  .short_help = "show wireguard peer",
  .function = wg_show_peer_command_fn,
};

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

/* AmneziaWG configuration commands */
static clib_error_t *
wg_set_awg_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  wg_if_t *wg_if;
  index_t wgii;
  clib_error_t *error = NULL;
  u8 enable = 0;
  u32 jc = 0, jmin = 0, jmax = 0;
  u32 s1 = 0, s2 = 0, s3 = 0, s4 = 0;
  u32 h1 = 0, h2 = 0, h3 = 0, h4 = 0;
  u8 set_enable = 0, set_junk = 0, set_header_junk = 0, set_magic = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected interface name");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface,
		    vnet_get_main (), &sw_if_index))
	;
      else if (unformat (line_input, "enable"))
	{
	  enable = 1;
	  set_enable = 1;
	}
      else if (unformat (line_input, "disable"))
	{
	  enable = 0;
	  set_enable = 1;
	}
      else if (unformat (line_input, "junk-packet-count %u", &jc))
	set_junk = 1;
      else if (unformat (line_input, "junk-packet-min-size %u", &jmin))
	set_junk = 1;
      else if (unformat (line_input, "junk-packet-max-size %u", &jmax))
	set_junk = 1;
      else if (unformat (line_input, "init-junk-size %u", &s1))
	set_header_junk = 1;
      else if (unformat (line_input, "response-junk-size %u", &s2))
	set_header_junk = 1;
      else if (unformat (line_input, "cookie-junk-size %u", &s3))
	set_header_junk = 1;
      else if (unformat (line_input, "transport-junk-size %u", &s4))
	set_header_junk = 1;
      else if (unformat (line_input, "magic-header-init %u", &h1))
	set_magic = 1;
      else if (unformat (line_input, "magic-header-response %u", &h2))
	set_magic = 1;
      else if (unformat (line_input, "magic-header-cookie %u", &h3))
	set_magic = 1;
      else if (unformat (line_input, "magic-header-data %u", &h4))
	set_magic = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "interface not specified");
      goto done;
    }

  wgii = wg_if_find_by_sw_if_index (sw_if_index);
  if (wgii == INDEX_INVALID)
    {
      error = clib_error_return (0, "interface is not a wireguard interface");
      goto done;
    }

  wg_if = wg_if_get (wgii);

  if (set_enable)
    wg_if->awg_cfg.enabled = enable;

  if (set_junk)
    {
      if (jc > 0)
	wg_if->awg_cfg.junk_packet_count = jc;
      if (jmin > 0)
	wg_if->awg_cfg.junk_packet_min_size = jmin;
      if (jmax > 0)
	wg_if->awg_cfg.junk_packet_max_size = jmax;
    }

  if (set_header_junk)
    {
      if (s1 > 0)
	wg_if->awg_cfg.init_header_junk_size = s1;
      if (s2 > 0)
	wg_if->awg_cfg.response_header_junk_size = s2;
      if (s3 > 0)
	wg_if->awg_cfg.cookie_reply_header_junk_size = s3;
      if (s4 > 0)
	wg_if->awg_cfg.transport_header_junk_size = s4;
    }

  if (set_magic)
    {
      if (h1 > 0)
	wg_if->awg_cfg.magic_header[0] = h1;
      if (h2 > 0)
	wg_if->awg_cfg.magic_header[1] = h2;
      if (h3 > 0)
	wg_if->awg_cfg.magic_header[2] = h3;
      if (h4 > 0)
	wg_if->awg_cfg.magic_header[3] = h4;
    }

  vlib_cli_output (vm, "AmneziaWG configuration updated for %U",
		   format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (wg_set_awg_command, static) = {
  .path = "set wireguard awg",
  .short_help =
    "set wireguard awg <interface> [enable|disable] "
    "[junk-packet-count <n>] [junk-packet-min-size <n>] [junk-packet-max-size <n>] "
    "[init-junk-size <n>] [response-junk-size <n>] [cookie-junk-size <n>] [transport-junk-size <n>] "
    "[magic-header-init <n>] [magic-header-response <n>] [magic-header-cookie <n>] [magic-header-data <n>]",
  .function = wg_set_awg_command_fn,
};

static clib_error_t *
wg_show_awg_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  u32 sw_if_index = ~0;
  wg_if_t *wg_if;
  index_t wgii;
  unformat_input_t _line_input, *line_input = &_line_input;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected interface name");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface,
		    vnet_get_main (), &sw_if_index))
	;
      else
	{
	  unformat_free (line_input);
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, line_input);
	}
    }

  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface not specified");

  wgii = wg_if_find_by_sw_if_index (sw_if_index);
  if (wgii == INDEX_INVALID)
    return clib_error_return (0, "interface is not a wireguard interface");

  wg_if = wg_if_get (wgii);
  wg_awg_cfg_t *cfg = &wg_if->awg_cfg;

  vlib_cli_output (vm, "AmneziaWG configuration for %U:", format_vnet_sw_if_index_name,
		   vnet_get_main (), sw_if_index);
  vlib_cli_output (vm, "  Enabled: %s", cfg->enabled ? "yes" : "no");
  vlib_cli_output (vm, "  Junk packets: count=%u min=%u max=%u",
		   cfg->junk_packet_count, cfg->junk_packet_min_size,
		   cfg->junk_packet_max_size);
  vlib_cli_output (vm, "  Header junk: init=%u response=%u cookie=%u transport=%u",
		   cfg->init_header_junk_size, cfg->response_header_junk_size,
		   cfg->cookie_reply_header_junk_size, cfg->transport_header_junk_size);
  vlib_cli_output (vm, "  Magic headers: [%u, %u, %u, %u]",
		   cfg->magic_header[0], cfg->magic_header[1],
		   cfg->magic_header[2], cfg->magic_header[3]);

  return NULL;
}

VLIB_CLI_COMMAND (wg_show_awg_command, static) = {
  .path = "show wireguard awg",
  .short_help = "show wireguard awg <interface>",
  .function = wg_show_awg_command_fn,
};

/* AmneziaWG 1.5: i-header configuration */
static clib_error_t *
wg_set_i_header_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  wg_if_t *wg_if;
  index_t wgii;
  clib_error_t *error = NULL;
  u32 i_num = 0;
  u8 *tag_string = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected interface name");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface,
		    vnet_get_main (), &sw_if_index))
	;
      else if (unformat (line_input, "i%u %s", &i_num, &tag_string))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "interface not specified");
      goto done;
    }

  if (i_num < 1 || i_num > 5)
    {
      error = clib_error_return (0, "i-header number must be 1-5");
      goto done;
    }

  if (!tag_string)
    {
      error = clib_error_return (0, "tag string not specified");
      goto done;
    }

  wgii = wg_if_find_by_sw_if_index (sw_if_index);
  if (wgii == INDEX_INVALID)
    {
      error = clib_error_return (0, "interface is not a wireguard interface");
      goto done;
    }

  wg_if = wg_if_get (wgii);
  wg_awg_i_header_t *ihdr = &wg_if->awg_cfg.i_headers[i_num - 1];

  /* Free previous configuration if any */
  wg_awg_free_i_header (ihdr);

  /* Parse new tag string */
  if (wg_awg_parse_tag_string ((char *) tag_string, ihdr) < 0)
    {
      error = clib_error_return (0, "failed to parse tag string");
      goto done;
    }

  /* Mark i-headers as enabled if i1 is configured */
  if (i_num == 1 && ihdr->enabled)
    {
      wg_if->awg_cfg.i_headers_enabled = 1;
    }

  vlib_cli_output (vm, "i-header i%u configured for %U", i_num,
		   format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);

done:
  if (tag_string)
    vec_free (tag_string);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (wg_set_i_header_command, static) = {
  .path = "set wireguard i-header",
  .short_help = "set wireguard i-header <interface> i<1-5> <tag-string>\n"
    "  Example: set wireguard i-header wg0 i1 \"<b 0xc00000000108...><r 16><c><t>\"\n"
    "  Tags: <b 0xHEX> <c> <t> <r N> <rc N> <rd N>",
  .function = wg_set_i_header_command_fn,
};

static clib_error_t *
wg_clear_i_header_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  wg_if_t *wg_if;
  index_t wgii;
  clib_error_t *error = NULL;
  u32 i_num = 0;
  u32 i;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected interface name");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface,
		    vnet_get_main (), &sw_if_index))
	;
      else if (unformat (line_input, "i%u", &i_num))
	;
      else if (unformat (line_input, "all"))
	i_num = 99; /* Special value for all */
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "interface not specified");
      goto done;
    }

  wgii = wg_if_find_by_sw_if_index (sw_if_index);
  if (wgii == INDEX_INVALID)
    {
      error = clib_error_return (0, "interface is not a wireguard interface");
      goto done;
    }

  wg_if = wg_if_get (wgii);

  if (i_num == 99)
    {
      /* Clear all i-headers */
      for (i = 0; i < WG_AWG_MAX_I_HEADERS; i++)
	{
	  wg_awg_free_i_header (&wg_if->awg_cfg.i_headers[i]);
	}
      wg_if->awg_cfg.i_headers_enabled = 0;
      vlib_cli_output (vm, "All i-headers cleared for %U",
		       format_vnet_sw_if_index_name, vnet_get_main (),
		       sw_if_index);
    }
  else if (i_num >= 1 && i_num <= 5)
    {
      wg_awg_free_i_header (&wg_if->awg_cfg.i_headers[i_num - 1]);

      /* Check if we should disable i-headers entirely */
      u8 any_enabled = 0;
      for (i = 0; i < WG_AWG_MAX_I_HEADERS; i++)
	{
	  if (wg_if->awg_cfg.i_headers[i].enabled)
	    {
	      any_enabled = 1;
	      break;
	    }
	}
      wg_if->awg_cfg.i_headers_enabled = any_enabled;

      vlib_cli_output (vm, "i-header i%u cleared for %U", i_num,
		       format_vnet_sw_if_index_name, vnet_get_main (),
		       sw_if_index);
    }
  else
    {
      error = clib_error_return (0, "i-header number must be 1-5 or 'all'");
    }

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (wg_clear_i_header_command, static) = {
  .path = "clear wireguard i-header",
  .short_help = "clear wireguard i-header <interface> {i<1-5>|all}",
  .function = wg_clear_i_header_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
