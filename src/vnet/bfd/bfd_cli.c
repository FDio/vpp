/*
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief BFD CLI implementation
 */

#include <vlib/vlib.h>
#include <vlib/cli.h>
#include <vppinfra/format.h>
#include <vnet/api_errno.h>
#include <vnet/ip/format.h>
#include <vnet/bfd/bfd_api.h>
#include <vnet/bfd/bfd_main.h>

static u8 *
format_bfd_session_cli (u8 * s, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  bfd_main_t *bm = va_arg (*args, bfd_main_t *);
  bfd_session_t *bs = va_arg (*args, bfd_session_t *);
  switch (bs->transport)
    {
    case BFD_TRANSPORT_UDP4:
      s = format (s, "%=10u %-32s %20U %20U\n", bs->bs_idx, "IPv4 address",
		  format_ip4_address, bs->udp.key.local_addr.ip4.as_u8,
		  format_ip4_address, bs->udp.key.peer_addr.ip4.as_u8);
      break;
    case BFD_TRANSPORT_UDP6:
      s = format (s, "%=10u %-32s %20U %20U\n", bs->bs_idx, "IPv6 address",
		  format_ip6_address, &bs->udp.key.local_addr.ip6,
		  format_ip6_address, &bs->udp.key.peer_addr.ip6);
      break;
    }
  s = format (s, "%10s %-32s %20s %20s\n", "", "Session state",
	      bfd_state_string (bs->local_state),
	      bfd_state_string (bs->remote_state));
  s = format (s, "%10s %-32s %20s %20s\n", "", "Diagnostic code",
	      bfd_diag_code_string (bs->local_diag),
	      bfd_diag_code_string (bs->remote_diag));
  s = format (s, "%10s %-32s %20u %20u\n", "", "Detect multiplier",
	      bs->local_detect_mult, bs->remote_detect_mult);
  s = format (s, "%10s %-32s %20u %20llu\n", "",
	      "Required Min Rx Interval (usec)",
	      bs->config_required_min_rx_usec, bs->remote_min_rx_usec);
  s = format (s, "%10s %-32s %20u %20u\n", "",
	      "Desired Min Tx Interval (usec)",
	      bs->config_desired_min_tx_usec, bfd_clocks_to_usec (bm,
								  bs->remote_desired_min_tx_clocks));
  s =
    format (s, "%10s %-32s %20u\n", "", "Transmit interval",
	    bfd_clocks_to_usec (bm, bs->transmit_interval_clocks));
  u64 now = clib_cpu_time_now ();
  u8 *tmp = NULL;
  if (bs->last_tx_clocks > 0)
    {
      tmp = format (tmp, "%.2fs ago", (now - bs->last_tx_clocks) *
		    vm->clib_time.seconds_per_clock);
      s = format (s, "%10s %-32s %20v\n", "", "Last control frame tx", tmp);
      vec_reset_length (tmp);
    }
  if (bs->last_rx_clocks)
    {
      tmp = format (tmp, "%.2fs ago", (now - bs->last_rx_clocks) *
		    vm->clib_time.seconds_per_clock);
      s = format (s, "%10s %-32s %20v\n", "", "Last control frame rx", tmp);
      vec_reset_length (tmp);
    }
  s =
    format (s, "%10s %-32s %20u %20llu\n", "", "Min Echo Rx Interval (usec)",
	    1, bs->remote_min_echo_rx_usec);
  if (bs->echo)
    {
      s = format (s, "%10s %-32s %20u\n", "", "Echo transmit interval",
		  bfd_clocks_to_usec (bm, bs->echo_transmit_interval_clocks));
      tmp = format (tmp, "%.2fs ago", (now - bs->echo_last_tx_clocks) *
		    vm->clib_time.seconds_per_clock);
      s = format (s, "%10s %-32s %20v\n", "", "Last echo frame tx", tmp);
      vec_reset_length (tmp);
      tmp = format (tmp, "%.6fs",
		    (bs->echo_last_rx_clocks - bs->echo_last_tx_clocks) *
		    vm->clib_time.seconds_per_clock);
      s =
	format (s, "%10s %-32s %20v\n", "", "Last echo frame roundtrip time",
		tmp);
    }
  vec_free (tmp);
  tmp = NULL;
  s = format (s, "%10s %-32s %20s %20s\n", "", "Demand mode", "no",
	      bs->remote_demand ? "yes" : "no");
  s = format (s, "%10s %-32s %20s\n", "", "Poll state",
	      bfd_poll_state_string (bs->poll_state));
  if (bs->auth.curr_key)
    {
      s = format (s, "%10s %-32s %20u\n", "", "Authentication config key ID",
		  bs->auth.curr_key->conf_key_id);
      s = format (s, "%10s %-32s %20u\n", "", "Authentication BFD key ID",
		  bs->auth.curr_bfd_key_id);
      s = format (s, "%10s %-32s %20u %20u\n", "", "Sequence number",
		  bs->auth.local_seq_number, bs->auth.remote_seq_number);
    }
  return s;
}

static clib_error_t *
show_bfd (vlib_main_t * vm, unformat_input_t * input,
	  CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  bfd_main_t *bm = &bfd_main;
  bfd_session_t *bs = NULL;

  if (unformat (input, "keys"))
    {
      bfd_auth_key_t *key = NULL;
      u8 *s = format (NULL, "%=10s %=25s %=10s\n", "Configuration Key ID",
		      "Type", "Use Count");
      /* *INDENT-OFF* */
      pool_foreach (key, bm->auth_keys, {
        s = format (s, "%10u %-25s %10u\n", key->conf_key_id,
                    bfd_auth_type_str (key->auth_type), key->use_count);
      });
      /* *INDENT-ON* */
      vlib_cli_output (vm, "%v\n", s);
      vec_free (s);
      vlib_cli_output (vm, "Number of configured BFD keys: %lu\n",
		       (u64) pool_elts (bm->auth_keys));
    }
  else if (unformat (input, "sessions"))
    {
      u8 *s = format (NULL, "%=10s %=32s %=20s %=20s\n", "Index", "Property",
		      "Local value", "Remote value");
      /* *INDENT-OFF* */
      pool_foreach (bs, bm->sessions, {
        s = format (s, "%U", format_bfd_session_cli, vm, bm, bs);
      });
      /* *INDENT-ON* */
      vlib_cli_output (vm, "%v", s);
      vec_free (s);
      vlib_cli_output (vm, "Number of configured BFD sessions: %lu\n",
		       (u64) pool_elts (bm->sessions));
    }
  else if (unformat (input, "echo-source"))
    {
      int is_set;
      u32 sw_if_index;
      int have_usable_ip4;
      ip4_address_t ip4;
      int have_usable_ip6;
      ip6_address_t ip6;
      bfd_udp_get_echo_source (&is_set, &sw_if_index, &have_usable_ip4, &ip4,
			       &have_usable_ip6, &ip6);
      if (is_set)
	{
	  vnet_sw_interface_t *sw_if =
	    vnet_get_sw_interface_safe (&vnet_main, sw_if_index);
	  vnet_hw_interface_t *hw_if =
	    vnet_get_hw_interface (&vnet_main, sw_if->hw_if_index);
	  u8 *s = format (NULL, "UDP echo source is: %v\n", hw_if->name);
	  s = format (s, "IPv4 address usable as echo source: ");
	  if (have_usable_ip4)
	    {
	      s = format (s, "%U\n", format_ip4_address, &ip4);
	    }
	  else
	    {
	      s = format (s, "none\n");
	    }
	  s = format (s, "IPv6 address usable as echo source: ");
	  if (have_usable_ip6)
	    {
	      s = format (s, "%U\n", format_ip6_address, &ip6);
	    }
	  else
	    {
	      s = format (s, "none\n");
	    }
	  vlib_cli_output (vm, "%v", s);
	  vec_free (s);
	}
      else
	{
	  vlib_cli_output (vm, "UDP echo source is not set.\n");
	}
    }
  else
    {
      vlib_cli_output (vm, "Number of configured BFD sessions: %lu\n",
		       (u64) pool_elts (bm->sessions));
      vlib_cli_output (vm, "Number of configured BFD keys: %lu\n",
		       (u64) pool_elts (bm->auth_keys));
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_bfd_command, static) = {
  .path = "show bfd",
  .short_help = "show bfd [keys|sessions|echo-source]",
  .function = show_bfd,
};
/* *INDENT-ON* */

static u8 *
format_vnet_api_errno (u8 * s, va_list * args)
{
  vnet_api_error_t api_error = va_arg (*args, vnet_api_error_t);
#define _(a, b, c)           \
  case b:                    \
    s = format (s, "%s", c); \
    break;
  switch (api_error)
    {
      foreach_vnet_api_error default:s = format (s, "UNKNOWN");
      break;
    }
  return s;
}

static clib_error_t *
bfd_cli_key_add (vlib_main_t * vm, unformat_input_t * input,
		 CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  clib_error_t *ret = NULL;
  int have_key_id = 0;
  u32 key_id = 0;
  u8 *vec_auth_type = NULL;
  bfd_auth_type_e auth_type = BFD_AUTH_TYPE_reserved;
  u8 *secret = NULL;
  static const u8 keyed_sha1[] = "keyed-sha1";
  static const u8 meticulous_keyed_sha1[] = "meticulous-keyed-sha1";

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "conf-key-id %u", &key_id))
	{
	  have_key_id = 1;
	}
      else if (unformat (input, "type %U", unformat_token, "a-zA-Z0-9-",
			 &vec_auth_type))
	{
	  if (vec_len (vec_auth_type) == sizeof (keyed_sha1) - 1 &&
	      0 == memcmp (vec_auth_type, keyed_sha1,
			   sizeof (keyed_sha1) - 1))
	    {
	      auth_type = BFD_AUTH_TYPE_keyed_sha1;
	    }
	  else if (vec_len (vec_auth_type) ==
		   sizeof (meticulous_keyed_sha1) - 1 &&
		   0 == memcmp (vec_auth_type, meticulous_keyed_sha1,
				sizeof (meticulous_keyed_sha1) - 1))
	    {
	      auth_type = BFD_AUTH_TYPE_meticulous_keyed_sha1;
	    }
	  else
	    {
	      ret = clib_error_return (0, "invalid type `%v'", vec_auth_type);
	      goto out;
	    }
	}
      else if (unformat (input, "secret %U", unformat_hex_string, &secret))
	{
	  /* nothing to do here */
	}
      else
	{
	  ret = clib_error_return (0, "Unknown input `%U'",
				   format_unformat_error, input);
	  goto out;
	}
    }

  if (!have_key_id)
    {
      ret =
	clib_error_return (0, "required parameter missing: `conf-key-id'");
      goto out;
    }
  if (!vec_auth_type)
    {
      ret = clib_error_return (0, "required parameter missing: `type'");
      goto out;
    }
  if (!secret)
    {
      ret = clib_error_return (0, "required parameter missing: `secret'");
      goto out;
    }

  vnet_api_error_t rv =
    bfd_auth_set_key (key_id, auth_type, vec_len (secret), secret);
  if (rv)
    {
      ret =
	clib_error_return (0, "`bfd_auth_set_key' API call failed, rv=%d:%U",
			   (int) rv, format_vnet_api_errno, rv);
    }

out:
  vec_free (vec_auth_type);
  return ret;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bfd_cli_key_add_command, static) = {
  .path = "bfd key set",
  .short_help = "bfd key set"
                " conf-key-id <id>"
                " type <keyed-sha1|meticulous-keyed-sha1> "
                " secret <secret>",
  .function = bfd_cli_key_add,
};
/* *INDENT-ON* */

static clib_error_t *
bfd_cli_key_del (vlib_main_t * vm, unformat_input_t * input,
		 CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  clib_error_t *ret = NULL;
  u32 key_id = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!unformat (input, "conf-key-id %u", &key_id))
	{
	  ret = clib_error_return (0, "Unknown input `%U'",
				   format_unformat_error, input);
	  goto out;
	}
    }

  vnet_api_error_t rv = bfd_auth_del_key (key_id);
  if (rv)
    {
      ret =
	clib_error_return (0, "`bfd_auth_del_key' API call failed, rv=%d:%U",
			   (int) rv, format_vnet_api_errno, rv);
    }

out:
  return ret;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bfd_cli_key_del_command, static) = {
  .path = "bfd key del",
  .short_help = "bfd key del conf-key-id <id>",
  .function = bfd_cli_key_del,
};
/* *INDENT-ON* */

#define INTERFACE_STR "interface"
#define LOCAL_ADDR_STR "local-addr"
#define PEER_ADDR_STR "peer-addr"
#define CONF_KEY_ID_STR "conf-key-id"
#define BFD_KEY_ID_STR "bfd-key-id"
#define DESIRED_MIN_TX_STR "desired-min-tx"
#define REQUIRED_MIN_RX_STR "required-min-rx"
#define DETECT_MULT_STR "detect-mult"
#define ADMIN_STR "admin"
#define DELAYED_STR "delayed"

static const unsigned mandatory = 1;
static const unsigned optional = 0;

#define DECLARE(t, n, s, r, ...) \
  int have_##n = 0;              \
  t n;

#define UNFORMAT(t, n, s, r, ...)              \
  if (unformat (input, s " " __VA_ARGS__, &n)) \
    {                                          \
      something_parsed = 1;                    \
      have_##n = 1;                            \
    }

#if __GNUC__ >= 6
#define PRAGMA_STR1 \
  _Pragma ("GCC diagnostic ignored \"-Wtautological-compare\"");
#define PRAGMA_STR2 _Pragma ("GCC diagnostic pop");
#else
#define PRAGMA_STR1
#define PRAGMA_STR2
#endif

#define CHECK_MANDATORY(t, n, s, r, ...)                                  \
  PRAGMA_STR1                                                             \
  if (mandatory == r && !have_##n)                                        \
    {                                                                     \
      PRAGMA_STR2                                                         \
      ret = clib_error_return (0, "Required parameter `%s' missing.", s); \
      goto out;                                                           \
    }

static clib_error_t *
bfd_cli_udp_session_add (vlib_main_t * vm, unformat_input_t * input,
			 CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  clib_error_t *ret = NULL;
#define foreach_bfd_cli_udp_session_add_cli_param(F)              \
  F (u32, sw_if_index, INTERFACE_STR, mandatory, "%U",            \
     unformat_vnet_sw_interface, &vnet_main)                      \
  F (ip46_address_t, local_addr, LOCAL_ADDR_STR, mandatory, "%U", \
     unformat_ip46_address)                                       \
  F (ip46_address_t, peer_addr, PEER_ADDR_STR, mandatory, "%U",   \
     unformat_ip46_address)                                       \
  F (u32, desired_min_tx, DESIRED_MIN_TX_STR, mandatory, "%u")    \
  F (u32, required_min_rx, REQUIRED_MIN_RX_STR, mandatory, "%u")  \
  F (u32, detect_mult, DETECT_MULT_STR, mandatory, "%u")          \
  F (u32, conf_key_id, CONF_KEY_ID_STR, optional, "%u")           \
  F (u32, bfd_key_id, BFD_KEY_ID_STR, optional, "%u")

  foreach_bfd_cli_udp_session_add_cli_param (DECLARE);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      int something_parsed = 0;
      foreach_bfd_cli_udp_session_add_cli_param (UNFORMAT);

      if (!something_parsed)
	{
	  ret = clib_error_return (0, "Unknown input `%U'",
				   format_unformat_error, input);
	  goto out;
	}
    }

  foreach_bfd_cli_udp_session_add_cli_param (CHECK_MANDATORY);

  if (1 == have_conf_key_id + have_bfd_key_id)
    {
      ret = clib_error_return (0, "Incompatible parameter combination, `%s' "
			       "and `%s' must be either both specified or none",
			       CONF_KEY_ID_STR, BFD_KEY_ID_STR);
      goto out;
    }

  if (detect_mult > 255)
    {
      ret = clib_error_return (0, "%s value `%u' out of range <1,255>",
			       DETECT_MULT_STR, detect_mult);
      goto out;
    }

  if (have_bfd_key_id && bfd_key_id > 255)
    {
      ret = clib_error_return (0, "%s value `%u' out of range <1,255>",
			       BFD_KEY_ID_STR, bfd_key_id);
      goto out;
    }

  vnet_api_error_t rv =
    bfd_udp_add_session (sw_if_index, &local_addr, &peer_addr, desired_min_tx,
			 required_min_rx,
			 detect_mult, have_conf_key_id, conf_key_id,
			 bfd_key_id);
  if (rv)
    {
      ret =
	clib_error_return (0,
			   "`bfd_add_add_session' API call failed, rv=%d:%U",
			   (int) rv, format_vnet_api_errno, rv);
      goto out;
    }

out:
  return ret;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bfd_cli_udp_session_add_command, static) = {
  .path = "bfd udp session add",
  .short_help = "bfd udp session add"
                " interface <interface>"
                " local-addr <local-address>"
                " peer-addr <peer-address>"
                " desired-min-tx <desired min tx interval>"
                " required-min-rx <required min rx interval>"
                " detect-mult <detect multiplier> "
                "["
                " conf-key-id <config key ID>"
                " bfd-key-id <BFD key ID>"
                "]",
  .function = bfd_cli_udp_session_add,
};
/* *INDENT-ON* */

static clib_error_t *
bfd_cli_udp_session_mod (vlib_main_t * vm, unformat_input_t * input,
			 CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  clib_error_t *ret = NULL;
#define foreach_bfd_cli_udp_session_mod_cli_param(F)              \
  F (u32, sw_if_index, INTERFACE_STR, mandatory, "%U",            \
     unformat_vnet_sw_interface, &vnet_main)                      \
  F (ip46_address_t, local_addr, LOCAL_ADDR_STR, mandatory, "%U", \
     unformat_ip46_address)                                       \
  F (ip46_address_t, peer_addr, PEER_ADDR_STR, mandatory, "%U",   \
     unformat_ip46_address)                                       \
  F (u32, desired_min_tx, DESIRED_MIN_TX_STR, mandatory, "%u")    \
  F (u32, required_min_rx, REQUIRED_MIN_RX_STR, mandatory, "%u")  \
  F (u32, detect_mult, DETECT_MULT_STR, mandatory, "%u")

  foreach_bfd_cli_udp_session_mod_cli_param (DECLARE);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      int something_parsed = 0;
      foreach_bfd_cli_udp_session_mod_cli_param (UNFORMAT);

      if (!something_parsed)
	{
	  ret = clib_error_return (0, "Unknown input `%U'",
				   format_unformat_error, input);
	  goto out;
	}
    }

  foreach_bfd_cli_udp_session_mod_cli_param (CHECK_MANDATORY);

  if (detect_mult > 255)
    {
      ret = clib_error_return (0, "%s value `%u' out of range <1,255>",
			       DETECT_MULT_STR, detect_mult);
      goto out;
    }

  vnet_api_error_t rv =
    bfd_udp_mod_session (sw_if_index, &local_addr, &peer_addr,
			 desired_min_tx, required_min_rx, detect_mult);
  if (rv)
    {
      ret =
	clib_error_return (0,
			   "`bfd_udp_mod_session' API call failed, rv=%d:%U",
			   (int) rv, format_vnet_api_errno, rv);
      goto out;
    }

out:
  return ret;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bfd_cli_udp_session_mod_command, static) = {
  .path = "bfd udp session mod",
  .short_help = "bfd udp session mod interface"
                " <interface> local-addr"
                " <local-address> peer-addr"
                " <peer-address> desired-min-tx"
                " <desired min tx interval> required-min-rx"
                " <required min rx interval> detect-mult"
                " <detect multiplier> ",
  .function = bfd_cli_udp_session_mod,
};
/* *INDENT-ON* */

static clib_error_t *
bfd_cli_udp_session_del (vlib_main_t * vm, unformat_input_t * input,
			 CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  clib_error_t *ret = NULL;
#define foreach_bfd_cli_udp_session_del_cli_param(F)              \
  F (u32, sw_if_index, INTERFACE_STR, mandatory, "%U",            \
     unformat_vnet_sw_interface, &vnet_main)                      \
  F (ip46_address_t, local_addr, LOCAL_ADDR_STR, mandatory, "%U", \
     unformat_ip46_address)                                       \
  F (ip46_address_t, peer_addr, PEER_ADDR_STR, mandatory, "%U",   \
     unformat_ip46_address)

  foreach_bfd_cli_udp_session_del_cli_param (DECLARE);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      int something_parsed = 0;
      foreach_bfd_cli_udp_session_del_cli_param (UNFORMAT);

      if (!something_parsed)
	{
	  ret = clib_error_return (0, "Unknown input `%U'",
				   format_unformat_error, input);
	  goto out;
	}
    }

  foreach_bfd_cli_udp_session_del_cli_param (CHECK_MANDATORY);

  vnet_api_error_t rv =
    bfd_udp_del_session (sw_if_index, &local_addr, &peer_addr);
  if (rv)
    {
      ret =
	clib_error_return (0,
			   "`bfd_udp_del_session' API call failed, rv=%d:%U",
			   (int) rv, format_vnet_api_errno, rv);
      goto out;
    }

out:
  return ret;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bfd_cli_udp_session_del_command, static) = {
  .path = "bfd udp session del",
  .short_help = "bfd udp session del interface"
                " <interface> local-addr"
                " <local-address> peer-addr"
                "<peer-address> ",
  .function = bfd_cli_udp_session_del,
};
/* *INDENT-ON* */

static clib_error_t *
bfd_cli_udp_session_set_flags (vlib_main_t * vm, unformat_input_t * input,
			       CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  clib_error_t *ret = NULL;
#define foreach_bfd_cli_udp_session_set_flags_cli_param(F)        \
  F (u32, sw_if_index, INTERFACE_STR, mandatory, "%U",            \
     unformat_vnet_sw_interface, &vnet_main)                      \
  F (ip46_address_t, local_addr, LOCAL_ADDR_STR, mandatory, "%U", \
     unformat_ip46_address)                                       \
  F (ip46_address_t, peer_addr, PEER_ADDR_STR, mandatory, "%U",   \
     unformat_ip46_address)                                       \
  F (u8 *, admin_up_down_token, ADMIN_STR, mandatory, "%v",       \
     &admin_up_down_token)

  foreach_bfd_cli_udp_session_set_flags_cli_param (DECLARE);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      int something_parsed = 0;
      foreach_bfd_cli_udp_session_set_flags_cli_param (UNFORMAT);

      if (!something_parsed)
	{
	  ret = clib_error_return (0, "Unknown input `%U'",
				   format_unformat_error, input);
	  goto out;
	}
    }

  foreach_bfd_cli_udp_session_set_flags_cli_param (CHECK_MANDATORY);

  u8 admin_up_down;
  static const char up[] = "up";
  static const char down[] = "down";
  if (!memcmp (admin_up_down_token, up, sizeof (up) - 1))
    {
      admin_up_down = 1;
    }
  else if (!memcmp (admin_up_down_token, down, sizeof (down) - 1))
    {
      admin_up_down = 0;
    }
  else
    {
      ret =
	clib_error_return (0, "Unrecognized value for `%s' parameter: `%v'",
			   ADMIN_STR, admin_up_down_token);
      goto out;
    }
  vnet_api_error_t rv = bfd_udp_session_set_flags (sw_if_index, &local_addr,
						   &peer_addr, admin_up_down);
  if (rv)
    {
      ret =
	clib_error_return (0,
			   "`bfd_udp_session_set_flags' API call failed, rv=%d:%U",
			   (int) rv, format_vnet_api_errno, rv);
      goto out;
    }

out:
  return ret;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bfd_cli_udp_session_set_flags_command, static) = {
  .path = "bfd udp session set-flags",
  .short_help = "bfd udp session set-flags"
                " interface <interface>"
                " local-addr <local-address>"
                " peer-addr <peer-address>"
                " admin <up|down>",
  .function = bfd_cli_udp_session_set_flags,
};
/* *INDENT-ON* */

static clib_error_t *
bfd_cli_udp_session_auth_activate (vlib_main_t * vm, unformat_input_t * input,
				   CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  clib_error_t *ret = NULL;
#define foreach_bfd_cli_udp_session_auth_activate_cli_param(F)    \
  F (u32, sw_if_index, INTERFACE_STR, mandatory, "%U",            \
     unformat_vnet_sw_interface, &vnet_main)                      \
  F (ip46_address_t, local_addr, LOCAL_ADDR_STR, mandatory, "%U", \
     unformat_ip46_address)                                       \
  F (ip46_address_t, peer_addr, PEER_ADDR_STR, mandatory, "%U",   \
     unformat_ip46_address)                                       \
  F (u8 *, delayed_token, DELAYED_STR, optional, "%v")            \
  F (u32, conf_key_id, CONF_KEY_ID_STR, mandatory, "%u")          \
  F (u32, bfd_key_id, BFD_KEY_ID_STR, mandatory, "%u")

  foreach_bfd_cli_udp_session_auth_activate_cli_param (DECLARE);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      int something_parsed = 0;
      foreach_bfd_cli_udp_session_auth_activate_cli_param (UNFORMAT);

      if (!something_parsed)
	{
	  ret = clib_error_return (0, "Unknown input `%U'",
				   format_unformat_error, input);
	  goto out;
	}
    }

  foreach_bfd_cli_udp_session_auth_activate_cli_param (CHECK_MANDATORY);

  u8 is_delayed = 0;
  if (have_delayed_token)
    {
      static const char yes[] = "yes";
      static const char no[] = "no";
      if (!memcmp (delayed_token, yes, sizeof (yes) - 1))
	{
	  is_delayed = 1;
	}
      else if (!memcmp (delayed_token, no, sizeof (no) - 1))
	{
	  is_delayed = 0;
	}
      else
	{
	  ret =
	    clib_error_return (0,
			       "Unrecognized value for `%s' parameter: `%v'",
			       DELAYED_STR, delayed_token);
	  goto out;
	}
    }

  if (have_bfd_key_id && bfd_key_id > 255)
    {
      ret = clib_error_return (0, "%s value `%u' out of range <1,255>",
			       BFD_KEY_ID_STR, bfd_key_id);
      goto out;
    }

  vnet_api_error_t rv =
    bfd_udp_auth_activate (sw_if_index, &local_addr, &peer_addr, conf_key_id,
			   bfd_key_id, is_delayed);
  if (rv)
    {
      ret =
	clib_error_return (0,
			   "`bfd_udp_auth_activate' API call failed, rv=%d:%U",
			   (int) rv, format_vnet_api_errno, rv);
      goto out;
    }

out:
  return ret;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bfd_cli_udp_session_auth_activate_command, static) = {
  .path = "bfd udp session auth activate",
  .short_help = "bfd udp session auth activate"
                " interface <interface>"
                " local-addr <local-address>"
                " peer-addr <peer-address>"
                " conf-key-id <config key ID>"
                " bfd-key-id <BFD key ID>"
                " [ delayed <yes|no> ]",
  .function = bfd_cli_udp_session_auth_activate,
};

static clib_error_t *
bfd_cli_udp_session_auth_deactivate (vlib_main_t *vm, unformat_input_t *input,
                                     CLIB_UNUSED (vlib_cli_command_t *lmd))
{
  clib_error_t *ret = NULL;
#define foreach_bfd_cli_udp_session_auth_deactivate_cli_param(F)  \
  F (u32, sw_if_index, INTERFACE_STR, mandatory, "%U",            \
     unformat_vnet_sw_interface, &vnet_main)                      \
  F (ip46_address_t, local_addr, LOCAL_ADDR_STR, mandatory, "%U", \
     unformat_ip46_address)                                       \
  F (ip46_address_t, peer_addr, PEER_ADDR_STR, mandatory, "%U",   \
     unformat_ip46_address)                                       \
  F (u8 *, delayed_token, DELAYED_STR, optional, "%v")

  foreach_bfd_cli_udp_session_auth_deactivate_cli_param (DECLARE);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      int something_parsed = 0;
      foreach_bfd_cli_udp_session_auth_deactivate_cli_param (UNFORMAT);

      if (!something_parsed)
        {
          ret = clib_error_return (0, "Unknown input `%U'",
                                   format_unformat_error, input);
          goto out;
        }
    }

  foreach_bfd_cli_udp_session_auth_deactivate_cli_param (CHECK_MANDATORY);

  u8 is_delayed = 0;
  if (have_delayed_token)
    {
      static const char yes[] = "yes";
      static const char no[] = "no";
      if (!memcmp (delayed_token, yes, sizeof (yes) - 1))
        {
          is_delayed = 1;
        }
      else if (!memcmp (delayed_token, no, sizeof (no) - 1))
        {
          is_delayed = 0;
        }
      else
        {
          ret = clib_error_return (
              0, "Unrecognized value for `%s' parameter: `%v'", DELAYED_STR,
              delayed_token);
          goto out;
        }
    }

  vnet_api_error_t rv = bfd_udp_auth_deactivate (sw_if_index, &local_addr,
                                                 &peer_addr, is_delayed);
  if (rv)
    {
      ret = clib_error_return (
          0, "`bfd_udp_auth_deactivate' API call failed, rv=%d:%U", (int)rv,
          format_vnet_api_errno, rv);
      goto out;
    }

out:
  return ret;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bfd_cli_udp_session_auth_deactivate_command, static) = {
  .path = "bfd udp session auth deactivate",
  .short_help = "bfd udp session auth deactivate"
                " interface <interface>"
                " local-addr <local-address>"
                " peer-addr <peer-address>"
                "[ delayed <yes|no> ]",
  .function = bfd_cli_udp_session_auth_deactivate,
};
/* *INDENT-ON* */

static clib_error_t *
bfd_cli_udp_set_echo_source (vlib_main_t * vm, unformat_input_t * input,
			     CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  clib_error_t *ret = NULL;
#define foreach_bfd_cli_udp_set_echo_source_cli_param(F) \
  F (u32, sw_if_index, INTERFACE_STR, mandatory, "%U",   \
     unformat_vnet_sw_interface, &vnet_main)

  foreach_bfd_cli_udp_set_echo_source_cli_param (DECLARE);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      int something_parsed = 0;
      foreach_bfd_cli_udp_set_echo_source_cli_param (UNFORMAT);

      if (!something_parsed)
	{
	  ret = clib_error_return (0, "Unknown input `%U'",
				   format_unformat_error, input);
	  goto out;
	}
    }

  foreach_bfd_cli_udp_set_echo_source_cli_param (CHECK_MANDATORY);

  vnet_api_error_t rv = bfd_udp_set_echo_source (sw_if_index);
  if (rv)
    {
      ret =
	clib_error_return (0,
			   "`bfd_udp_set_echo_source' API call failed, rv=%d:%U",
			   (int) rv, format_vnet_api_errno, rv);
      goto out;
    }

out:
  return ret;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bfd_cli_udp_set_echo_source_cmd, static) = {
  .path = "bfd udp echo-source set",
  .short_help = "bfd udp echo-source set interface <interface>",
  .function = bfd_cli_udp_set_echo_source,
};
/* *INDENT-ON* */

static clib_error_t *
bfd_cli_udp_del_echo_source (vlib_main_t * vm, unformat_input_t * input,
			     CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  vnet_api_error_t rv = bfd_udp_del_echo_source ();
  if (rv)
    {
      return clib_error_return (0,
				"`bfd_udp_del_echo_source' API call failed, rv=%d:%U",
				(int) rv, format_vnet_api_errno, rv);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bfd_cli_udp_del_echo_source_cmd, static) = {
  .path = "bfd udp echo-source del",
  .short_help = "bfd udp echo-source del",
  .function = bfd_cli_udp_del_echo_source,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
