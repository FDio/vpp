/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
 */

/**
 * @file
 * @brief BFD CLI implementation
 */

#include <vlib/vlib.h>
#include <vlib/cli.h>
#include <vppinfra/format.h>
#include <vppinfra/warnings.h>
#include <vnet/api_errno.h>
#include <vnet/ip/format.h>
#include <vnet/bfd/bfd_api.h>
#include <vnet/bfd/bfd_main.h>
#include <vnet/interface/cli_types.h>
#include <vnet/ip/cli_types.h>

static u8 *
format_bfd_session_cli (u8 * s, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  bfd_session_t *bs = va_arg (*args, bfd_session_t *);
  s = format (s, "%10s %-32s %20s\n", "", "Hop Type",
	      bfd_hop_type_string (bs->hop_type));

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
  s = format (s, "%10s %-32s %20llu\n", "", "Detection Time (usec)",
	      bfd_nsec_to_usec (bs->detection_time_nsec));
  s = format (s, "%10s %-32s %20u %20llu\n", "",
	      "Required Min Rx Interval (usec)",
	      bs->config_required_min_rx_usec, bs->remote_min_rx_usec);
  s = format (s, "%10s %-32s %20u %20u\n", "",
	      "Desired Min Tx Interval (usec)",
	      bs->config_desired_min_tx_usec,
	      bfd_nsec_to_usec (bs->remote_desired_min_tx_nsec));
  s =
    format (s, "%10s %-32s %20u\n", "", "Transmit interval",
	    bfd_nsec_to_usec (bs->transmit_interval_nsec));
  u64 now = (u64) (vlib_time_now (vm) * NSEC_PER_SEC);
  u8 *tmp = NULL;
  if (bs->last_tx_nsec > 0)
    {
      tmp = format (tmp, "%.2fs ago", (f64) (now - bs->last_tx_nsec) / NSEC_PER_SEC);
      s = format (s, "%10s %-32s %20v\n", "", "Last control frame tx", tmp);
      vec_reset_length (tmp);
    }
  if (bs->last_rx_nsec)
    {
      tmp = format (tmp, "%.2fs ago", (f64) (now - bs->last_rx_nsec) / NSEC_PER_SEC);
      s = format (s, "%10s %-32s %20v\n", "", "Last control frame rx", tmp);
      vec_reset_length (tmp);
    }
  s =
    format (s, "%10s %-32s %20u %20llu\n", "", "Min Echo Rx Interval (usec)",
	    1, bs->remote_min_echo_rx_usec);
  if (bs->echo)
    {
      s =
	format (s, "%10s %-32s %20u\n", "", "Echo transmit interval",
		bfd_nsec_to_usec (bs->echo_transmit_interval_nsec));
      tmp = format (tmp, "%.2fs ago", (f64) (now - bs->echo_last_tx_nsec) / NSEC_PER_SEC);
      s = format (s, "%10s %-32s %20v\n", "", "Last echo frame tx", tmp);
      vec_reset_length (tmp);
      tmp =
	format (tmp, "%.6fs", (f64) (bs->echo_last_rx_nsec - bs->echo_last_tx_nsec) / NSEC_PER_SEC);
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

typedef enum
{
  BFD_CLI_SHOW_KEYS = 1,
  BFD_CLI_SHOW_SESSIONS,
  BFD_CLI_SHOW_ECHO_SOURCE,
} bfd_cli_show_t;

static clib_error_t *
show_bfd (vlib_main_t *vm, cli_ctx_t *ctx)
{
  bfd_main_t *bm = &bfd_main;
  bfd_session_t *bs = NULL;
  u32 what = cli_index (ctx, "what");

  if (what == BFD_CLI_SHOW_KEYS)
    {
      bfd_auth_key_t *key = NULL;
      u8 *s = format (NULL, "%=10s %=25s %=10s\n", "Configuration Key ID",
		      "Type", "Use Count");
      pool_foreach (key, bm->auth_keys) {
        s = format (s, "%10u %-25s %10u\n", key->conf_key_id,
                    bfd_auth_type_str (key->auth_type), key->use_count);
      }
      vlib_cli_output (vm, "%v\n", s);
      vec_free (s);
      vlib_cli_output (vm, "Number of configured BFD keys: %lu\n",
		       (u64) pool_elts (bm->auth_keys));
    }
  else if (what == BFD_CLI_SHOW_SESSIONS)
    {
      u8 *s = format (NULL, "%=10s %=32s %=20s %=20s\n", "Index", "Property",
		      "Local value", "Remote value");
      pool_foreach (bs, bm->sessions) {
        s = format (s, "%U", format_bfd_session_cli, vm, bs);
      }
      vlib_cli_output (vm, "%v", s);
      vec_free (s);
      vlib_cli_output (vm, "Number of configured BFD sessions: %lu\n",
		       (u64) pool_elts (bm->sessions));
    }
  else if (what == BFD_CLI_SHOW_ECHO_SOURCE)
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
	    vnet_get_sw_interface_or_null (&vnet_main, sw_if_index);
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

VLIB_CLI_COMMAND (show_bfd_command, static) = {
  .path = "show bfd",
  .short_help = "Show the BFD keys, sessions or echo source",
  .args = CLI_ARGS (CLI_ENUM ("what", CLI_F_OPTIONAL,
			      { "keys", "authentication keys", BFD_CLI_SHOW_KEYS },
			      { "sessions", "sessions", BFD_CLI_SHOW_SESSIONS },
			      { "echo-source", "UDP echo source", BFD_CLI_SHOW_ECHO_SOURCE })),
  .handler = show_bfd,
};

static const cli_choice_t bfd_auth_type_choices[] = {
  { "keyed-sha1", "keyed SHA1", BFD_AUTH_TYPE_keyed_sha1 },
  { "meticulous-keyed-sha1", "meticulous keyed SHA1", BFD_AUTH_TYPE_meticulous_keyed_sha1 },
  {},
};

static clib_error_t *
bfd_cli_key_add (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u32 key_id = cli_u64 (ctx, "conf-key-id", 0);
  u8 *secret = cli_get (ctx, "secret")->str;

  vnet_api_error_t rv =
    bfd_auth_set_key (key_id, cli_index (ctx, "type"), vec_len (secret), secret);
  if (rv)
    return clib_error_return (0, "`bfd_auth_set_key' API call failed, rv=%d:%U", (int) rv,
			      format_vnet_api_errno, rv);

  return 0;
}

VLIB_CLI_COMMAND (bfd_cli_key_add_command, static) = {
  .path = "bfd key set",
  .short_help = "Add or change a BFD authentication key",
  .args = CLI_ARGS (CLI_KEYWORD ("conf-key-id", cli_type_u32, .help = "id of the key"),
		    CLI_KEYWORD ("type", cli_type_enum, .choices = bfd_auth_type_choices),
		    CLI_KEYWORD ("secret", cli_type_hex, .help = "key in hex")),
  .handler = bfd_cli_key_add,
};

static clib_error_t *
bfd_cli_key_del (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_api_error_t rv = bfd_auth_del_key (cli_u64 (ctx, "conf-key-id", 0));

  if (rv)
    return clib_error_return (0, "`bfd_auth_del_key' API call failed, rv=%d:%U", (int) rv,
			      format_vnet_api_errno, rv);

  return 0;
}

VLIB_CLI_COMMAND (bfd_cli_key_del_command, static) = {
  .path = "bfd key del",
  .short_help = "Delete a BFD authentication key",
  .args = CLI_ARGS (CLI_KEYWORD ("conf-key-id", cli_type_u32, .help = "id of the key")),
  .handler = bfd_cli_key_del,
};

/* the arguments which identify a session */
typedef struct
{
  bool multihop;
  u32 sw_if_index;
  ip46_address_t local_addr, peer_addr;
} bfd_cli_session_t;

static void
bfd_cli_get_address (cli_ctx_t *ctx, const char *name, ip46_address_t *addr)
{
  cli_value_t *v = cli_get (ctx, name);

  ip46_address_reset (addr);

  if (v->prefix.is_ip6)
    clib_memcpy (&addr->ip6, v->prefix.addr, sizeof (addr->ip6));
  else
    clib_memcpy (&addr->ip4, v->prefix.addr, sizeof (addr->ip4));
}

static clib_error_t *
bfd_cli_get_session (cli_ctx_t *ctx, bfd_cli_session_t *s)
{
  int have_sw_if_index = cli_flag (ctx, "interface");

  s->multihop = cli_flag (ctx, "multihop");
  s->sw_if_index = cli_index (ctx, "interface");
  bfd_cli_get_address (ctx, "local-addr", &s->local_addr);
  bfd_cli_get_address (ctx, "peer-addr", &s->peer_addr);

  if (s->multihop && have_sw_if_index)
    return clib_error_return (0, "Incompatible parameter combination, "
				 "interface cannot be specified when multihop is enabled");

  if (!s->multihop && !have_sw_if_index)
    return clib_error_return (0, "Incompatible parameter combination, "
				 "interface must be set if not multihop");

  return 0;
}

static clib_error_t *
bfd_cli_check_detect_mult (u32 detect_mult)
{
  if (detect_mult > 255)
    return clib_error_return (0, "detect-mult value `%u' out of range <1,255>", detect_mult);

  return 0;
}

static clib_error_t *
bfd_cli_check_bfd_key_id (u32 bfd_key_id)
{
  if (bfd_key_id > 255)
    return clib_error_return (0, "bfd-key-id value `%u' out of range <1,255>", bfd_key_id);

  return 0;
}

static clib_error_t *
bfd_cli_udp_session_add (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u32 desired_min_tx = cli_u64 (ctx, "desired-min-tx", 0);
  u32 required_min_rx = cli_u64 (ctx, "required-min-rx", 0);
  u32 detect_mult = cli_u64 (ctx, "detect-mult", 0);
  u32 conf_key_id = cli_u64 (ctx, "conf-key-id", 0);
  u32 bfd_key_id = cli_u64 (ctx, "bfd-key-id", 0);
  int have_conf_key_id = cli_flag (ctx, "conf-key-id");
  int have_bfd_key_id = cli_flag (ctx, "bfd-key-id");
  bfd_cli_session_t s;
  clib_error_t *err;

  if ((err = bfd_cli_get_session (ctx, &s)))
    return err;

  if (have_conf_key_id != have_bfd_key_id)
    return clib_error_return (0, "Incompatible parameter combination, `conf-key-id' "
				 "and `bfd-key-id' must be either both specified or none");

  if ((err = bfd_cli_check_detect_mult (detect_mult)))
    return err;

  if ((err = bfd_cli_check_bfd_key_id (bfd_key_id)))
    return err;

  vnet_api_error_t rv =
    bfd_udp_add_session (s.multihop, s.sw_if_index, &s.local_addr, &s.peer_addr, desired_min_tx,
			 required_min_rx, detect_mult, have_conf_key_id, conf_key_id, bfd_key_id);
  if (rv)
    return clib_error_return (0, "`bfd_add_add_session' API call failed, rv=%d:%U", (int) rv,
			      format_vnet_api_errno, rv);

  return 0;
}

VLIB_CLI_COMMAND (bfd_cli_udp_session_add_command, static) = {
  .path = "bfd udp session add",
  .short_help = "Add a BFD session",
  .args = CLI_ARGS (CLI_FLAG ("multihop", .help = "multihop session, without an interface"),
		    CLI_OPT_KEYWORD ("interface", cli_type_sw_interface),
		    CLI_KEYWORD ("local-addr", cli_type_ip_address),
		    CLI_KEYWORD ("peer-addr", cli_type_ip_address),
		    CLI_KEYWORD ("desired-min-tx", cli_type_u32, .help = "microseconds"),
		    CLI_KEYWORD ("required-min-rx", cli_type_u32, .help = "microseconds"),
		    CLI_KEYWORD ("detect-mult", cli_type_u32, .help = "detect multiplier, 1 - 255"),
		    CLI_OPT_KEYWORD ("conf-key-id", cli_type_u32, .help = "authentication key"),
		    CLI_OPT_KEYWORD ("bfd-key-id", cli_type_u32,
				     .help = "key id sent in the packets, 1 - 255")),
  .handler = bfd_cli_udp_session_add,
};

static clib_error_t *
bfd_cli_udp_session_mod (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u32 desired_min_tx = cli_u64 (ctx, "desired-min-tx", 0);
  u32 required_min_rx = cli_u64 (ctx, "required-min-rx", 0);
  u32 detect_mult = cli_u64 (ctx, "detect-mult", 0);
  bfd_cli_session_t s;
  clib_error_t *err;

  if ((err = bfd_cli_get_session (ctx, &s)))
    return err;

  if ((err = bfd_cli_check_detect_mult (detect_mult)))
    return err;

  vnet_api_error_t rv = bfd_udp_mod_session (s.multihop, s.sw_if_index, &s.local_addr, &s.peer_addr,
					     desired_min_tx, required_min_rx, detect_mult);
  if (rv)
    return clib_error_return (0, "`bfd_udp_mod_session' API call failed, rv=%d:%U", (int) rv,
			      format_vnet_api_errno, rv);

  return 0;
}

VLIB_CLI_COMMAND (bfd_cli_udp_session_mod_command, static) = {
  .path = "bfd udp session mod",
  .short_help = "Change the parameters of a BFD session",
  .args = CLI_ARGS (CLI_FLAG ("multihop", .help = "multihop session, without an interface"),
		    CLI_OPT_KEYWORD ("interface", cli_type_sw_interface),
		    CLI_KEYWORD ("local-addr", cli_type_ip_address),
		    CLI_KEYWORD ("peer-addr", cli_type_ip_address),
		    CLI_KEYWORD ("desired-min-tx", cli_type_u32, .help = "microseconds"),
		    CLI_KEYWORD ("required-min-rx", cli_type_u32, .help = "microseconds"),
		    CLI_KEYWORD ("detect-mult", cli_type_u32,
				 .help = "detect multiplier, 1 - 255")),
  .handler = bfd_cli_udp_session_mod,
};

static clib_error_t *
bfd_cli_udp_session_del (vlib_main_t *vm, cli_ctx_t *ctx)
{
  bfd_cli_session_t s;
  clib_error_t *err;

  if ((err = bfd_cli_get_session (ctx, &s)))
    return err;

  vnet_api_error_t rv =
    bfd_udp_del_session (s.multihop, s.sw_if_index, &s.local_addr, &s.peer_addr);
  if (rv)
    return clib_error_return (0, "`bfd_udp_del_session' API call failed, rv=%d:%U", (int) rv,
			      format_vnet_api_errno, rv);

  return 0;
}

VLIB_CLI_COMMAND (bfd_cli_udp_session_del_command, static) = {
  .path = "bfd udp session del",
  .short_help = "Delete a BFD session",
  .args = CLI_ARGS (CLI_FLAG ("multihop", .help = "multihop session, without an interface"),
		    CLI_OPT_KEYWORD ("interface", cli_type_sw_interface),
		    CLI_KEYWORD ("local-addr", cli_type_ip_address),
		    CLI_KEYWORD ("peer-addr", cli_type_ip_address)),
  .handler = bfd_cli_udp_session_del,
};

static const cli_choice_t bfd_admin_choices[] = {
  { "up", "administratively up", 1 },
  { "down", "administratively down", 0 },
  {},
};

static clib_error_t *
bfd_cli_udp_session_set_flags (vlib_main_t *vm, cli_ctx_t *ctx)
{
  bfd_cli_session_t s;
  clib_error_t *err;

  if ((err = bfd_cli_get_session (ctx, &s)))
    return err;

  vnet_api_error_t rv = bfd_udp_session_set_flags (vm, s.multihop, s.sw_if_index, &s.local_addr,
						   &s.peer_addr, cli_index (ctx, "admin"));
  if (rv)
    return clib_error_return (0, "`bfd_udp_session_set_flags' API call failed, rv=%d:%U", (int) rv,
			      format_vnet_api_errno, rv);

  return 0;
}

VLIB_CLI_COMMAND (bfd_cli_udp_session_set_flags_command, static) = {
  .path = "bfd udp session set-flags",
  .short_help = "Set a BFD session administratively up or down",
  .args = CLI_ARGS (CLI_FLAG ("multihop", .help = "multihop session, without an interface"),
		    CLI_OPT_KEYWORD ("interface", cli_type_sw_interface),
		    CLI_KEYWORD ("local-addr", cli_type_ip_address),
		    CLI_KEYWORD ("peer-addr", cli_type_ip_address),
		    CLI_KEYWORD ("admin", cli_type_enum, .choices = bfd_admin_choices)),
  .handler = bfd_cli_udp_session_set_flags,
};

static clib_error_t *
bfd_cli_udp_session_auth_activate (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u32 conf_key_id = cli_u64 (ctx, "conf-key-id", 0);
  u32 bfd_key_id = cli_u64 (ctx, "bfd-key-id", 0);
  u8 is_delayed = cli_flag (ctx, "delayed") && cli_index (ctx, "delayed");
  bfd_cli_session_t s;
  clib_error_t *err;

  if ((err = bfd_cli_get_session (ctx, &s)))
    return err;

  if ((err = bfd_cli_check_bfd_key_id (bfd_key_id)))
    return err;

  vnet_api_error_t rv = bfd_udp_auth_activate (s.multihop, s.sw_if_index, &s.local_addr,
					       &s.peer_addr, conf_key_id, bfd_key_id, is_delayed);
  if (rv)
    return clib_error_return (0, "`bfd_udp_auth_activate' API call failed, rv=%d:%U", (int) rv,
			      format_vnet_api_errno, rv);

  return 0;
}

VLIB_CLI_COMMAND (bfd_cli_udp_session_auth_activate_command, static) = {
  .path = "bfd udp session auth activate",
  .short_help = "Turn the authentication of a BFD session on",
  .args = CLI_ARGS (CLI_FLAG ("multihop", .help = "multihop session, without an interface"),
		    CLI_OPT_KEYWORD ("interface", cli_type_sw_interface),
		    CLI_KEYWORD ("local-addr", cli_type_ip_address),
		    CLI_KEYWORD ("peer-addr", cli_type_ip_address),
		    CLI_KEYWORD ("conf-key-id", cli_type_u32, .help = "authentication key"),
		    CLI_KEYWORD ("bfd-key-id", cli_type_u32,
				 .help = "key id sent in the packets, 1 - 255"),
		    CLI_OPT_KEYWORD ("delayed", cli_type_bool, .help = "yes to wait for the peer")),
  .handler = bfd_cli_udp_session_auth_activate,
};

static clib_error_t *
bfd_cli_udp_session_auth_deactivate (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u8 is_delayed = cli_flag (ctx, "delayed") && cli_index (ctx, "delayed");
  bfd_cli_session_t s;
  clib_error_t *err;

  if ((err = bfd_cli_get_session (ctx, &s)))
    return err;

  vnet_api_error_t rv =
    bfd_udp_auth_deactivate (s.multihop, s.sw_if_index, &s.local_addr, &s.peer_addr, is_delayed);
  if (rv)
    return clib_error_return (0, "`bfd_udp_auth_deactivate' API call failed, rv=%d:%U", (int) rv,
			      format_vnet_api_errno, rv);

  return 0;
}

VLIB_CLI_COMMAND (bfd_cli_udp_session_auth_deactivate_command, static) = {
  .path = "bfd udp session auth deactivate",
  .short_help = "Turn the authentication of a BFD session off",
  .args = CLI_ARGS (CLI_FLAG ("multihop", .help = "multihop session, without an interface"),
		    CLI_OPT_KEYWORD ("interface", cli_type_sw_interface),
		    CLI_KEYWORD ("local-addr", cli_type_ip_address),
		    CLI_KEYWORD ("peer-addr", cli_type_ip_address),
		    CLI_OPT_KEYWORD ("delayed", cli_type_bool, .help = "yes to wait for the peer")),
  .handler = bfd_cli_udp_session_auth_deactivate,
};

static clib_error_t *
bfd_cli_udp_set_echo_source (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_api_error_t rv = bfd_udp_set_echo_source (cli_index (ctx, "interface"));

  if (rv)
    return clib_error_return (0, "`bfd_udp_set_echo_source' API call failed, rv=%d:%U", (int) rv,
			      format_vnet_api_errno, rv);

  return 0;
}

VLIB_CLI_COMMAND (bfd_cli_udp_set_echo_source_cmd, static) = {
  .path = "bfd udp echo-source set",
  .short_help = "Set the interface which gives the source address of echo packets",
  .args = CLI_ARGS (CLI_KEYWORD ("interface", cli_type_sw_interface)),
  .handler = bfd_cli_udp_set_echo_source,
};

static clib_error_t *
bfd_cli_udp_del_echo_source (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_api_error_t rv = bfd_udp_del_echo_source ();

  if (rv)
    return clib_error_return (0, "`bfd_udp_del_echo_source' API call failed, rv=%d:%U", (int) rv,
			      format_vnet_api_errno, rv);

  return 0;
}

VLIB_CLI_COMMAND (bfd_cli_udp_del_echo_source_cmd, static) = {
  .path = "bfd udp echo-source del",
  .short_help = "Unset the interface of the echo source",
  .handler = bfd_cli_udp_del_echo_source,
};
