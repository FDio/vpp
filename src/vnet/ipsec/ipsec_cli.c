/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

/* decap.c : IPSec tunnel support */

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>
#include <vnet/fib/fib.h>

#include <vnet/cli_types.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_tun.h>

static clib_error_t *
set_interface_spd_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  int err = ipsec_set_interface_spd (vm, cli_index (ctx, "interface"), cli_u64 (ctx, "spd-id", 0),
				     !cli_flag (ctx, "del"));

  switch (err)
    {
    case VNET_API_ERROR_SYSCALL_ERROR_1:
      return clib_error_return (0, "no such spd-id");
    case VNET_API_ERROR_SYSCALL_ERROR_2:
      return clib_error_return (0, "spd already assigned");
    }

  return 0;
}

VLIB_CLI_COMMAND (set_interface_spd_command, static) = {
  .path = "set interface ipsec spd",
  .short_help = "Bind an SPD to an interface, or unbind it",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_sw_interface),
      CLI_VALUE ("spd-id", cli_type_u32),
      CLI_FLAG ("del", .help = "unbind the SPD"),
      {},
    },
  .handler = set_interface_spd_command_fn,
};

/* Key given as a hex string, the value is the string */
static u8 *
parse_ipsec_key (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  unformat_input_t in;
  u8 *data = 0, *err = 0;

  unformat_init_vector (&in, vec_dup (tok));
  if (!unformat (&in, "%U", unformat_hex_string, &data) ||
      unformat_check_input (&in) != UNFORMAT_END_OF_INPUT)
    err = format (0, "'%v' is not a hex string", tok);
  else if (vec_len (data) > sizeof (((ipsec_key_t *) 0)->data))
    err = format (0, "key is longer than %u bytes", sizeof (((ipsec_key_t *) 0)->data));
  else
    v->str = data, data = 0;
  vec_free (data);
  unformat_free (&in);
  return err;
}

CLIB_CLI_TYPE (cli_type_ipsec_key) = {
  .name = "hex-key",
  .help = "key as hex string",
  .parse = parse_ipsec_key,
  .owns_str = 1,
};

static const cli_choice_t ipsec_crypto_alg_choices[] = {
#define _(v, f, s) { s, 0, IPSEC_CRYPTO_ALG_##f },
  foreach_ipsec_crypto_alg
#undef _
  {},
};

static const cli_choice_t ipsec_integ_alg_choices[] = {
#define _(v, f, s) { s, 0, IPSEC_INTEG_ALG_##f },
  foreach_ipsec_integ_alg
#undef _
  {},
};

static const cli_choice_t ip_dscp_choices[] = {
#define _(v, f) { #f, 0, IP_DSCP_##f },
  foreach_ip_dscp
#undef _
  {},
};

static clib_error_t *
ipsec_sa_add_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ipsec_crypto_alg_t crypto_alg = cli_u64 (ctx, "crypto-alg", IPSEC_CRYPTO_ALG_NONE);
  ipsec_integ_alg_t integ_alg = cli_u64 (ctx, "integ-alg", IPSEC_INTEG_ALG_NONE);
  ipsec_protocol_t proto = IPSEC_PROTOCOL_ESP;
  ipsec_sa_flags_t flags = IPSEC_SA_FLAG_NONE;
  u16 udp_src = cli_u64 (ctx, "udp-src-port", IPSEC_UDP_PORT_NONE);
  u16 udp_dst = cli_u64 (ctx, "udp-dst-port", IPSEC_UDP_PORT_NONE);
  u32 anti_replay_window_size = cli_u64 (ctx, "anti-replay-size", 0);
  cli_value_t *v;
  ipsec_key_t ck = { 0 }, ik = { 0 };
  tunnel_t tun = {};
  u32 id, sai;
  int rv;

  id = cli_u64 (ctx, "id", 0);

  if (cli_flag (ctx, "ah"))
    proto = IPSEC_PROTOCOL_AH;
  if (cli_flag (ctx, "anti-replay-size") || cli_flag (ctx, "use-anti-replay"))
    flags |= IPSEC_SA_FLAG_USE_ANTI_REPLAY;
  if (cli_flag (ctx, "inbound"))
    flags |= IPSEC_SA_FLAG_IS_INBOUND;
  if (cli_flag (ctx, "use-esn"))
    flags |= IPSEC_SA_FLAG_USE_ESN;
  if (cli_flag (ctx, "udp-encap"))
    flags |= IPSEC_SA_FLAG_UDP_ENCAP;
  if (cli_flag (ctx, "async"))
    flags |= IPSEC_SA_FLAG_IS_ASYNC;

  if ((v = cli_get (ctx, "crypto-key")))
    ipsec_mk_key (&ck, v->str, vec_len (v->str));
  if ((v = cli_get (ctx, "integ-key")))
    ipsec_mk_key (&ik, v->str, vec_len (v->str));

  if (cli_flag (ctx, "tunnel"))
    {
      ip_address_family_t af;

      if (!(v = cli_get (ctx, "src")) || !cli_get (ctx, "dst"))
	return clib_error_return (0, "tunnel needs src and dst");
      af = v->prefix.is_ip6 ? AF_IP6 : AF_IP4;
      ip_address_set (&tun.t_src, v->prefix.addr, af);
      v = cli_get (ctx, "dst");
      if ((v->prefix.is_ip6 ? AF_IP6 : AF_IP4) != af)
	return clib_error_return (0, "src and dst address families differ");
      ip_address_set (&tun.t_dst, v->prefix.addr, af);

      tun.t_table_id = cli_u64 (ctx, "table-id", 0);
      tun.t_hop_limit = cli_u64 (ctx, "hop-limit", 0);
      tun.t_dscp = cli_u64 (ctx, "dscp", IP_DSCP_CS0);
      tun.t_mode = cli_flag (ctx, "p2mp") ? TUNNEL_MODE_MP : TUNNEL_MODE_P2P;
      if (cli_flag (ctx, "track-mtu"))
	tun.t_flags |= TUNNEL_FLAG_TRACK_MTU;
#define _(a, b, c)                                                                                 \
  if (cli_flag (ctx, b))                                                                           \
    tun.t_encap_decap_flags |= TUNNEL_ENCAP_DECAP_FLAG_##a;
      foreach_tunnel_encap_decap_flag
#undef _

	flags |= IPSEC_SA_FLAG_IS_TUNNEL;
      if (AF_IP6 == af)
	flags |= IPSEC_SA_FLAG_IS_TUNNEL_V6;
    }

  rv = ipsec_sa_add_and_lock (id, cli_u64 (ctx, "spi", 0), proto, crypto_alg, &ck, integ_alg, &ik,
			      flags, clib_host_to_net_u32 (cli_u64 (ctx, "salt", 0)), udp_src,
			      udp_dst, anti_replay_window_size, &tun, &sai);
  if (rv)
    return clib_error_return (0, "failed: %d", rv);

  return 0;
}

VLIB_CLI_COMMAND (ipsec_sa_add_command, static) = {
  .path = "ipsec sa add",
  .short_help = "Add an IPsec SA",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("id", cli_type_u32, .help = "SA id"),
      CLI_KEYWORD ("spi", cli_type_u32, .help = "security parameter index"),
      CLI_KEYWORD ("salt", cli_type_u32, .flags = CLI_F_OPTIONAL, .help = "salt, e.g. 0x1234abcd"),
      CLI_FLAG ("esp", .help = "ESP protocol (default)"),
      CLI_FLAG ("ah", .help = "AH protocol"),
      CLI_KEYWORD ("crypto-alg", cli_type_enum, .flags = CLI_F_OPTIONAL,
		   .choices = ipsec_crypto_alg_choices, .help = "crypto algorithm"),
      CLI_KEYWORD ("crypto-key", cli_type_ipsec_key, .flags = CLI_F_OPTIONAL),
      CLI_KEYWORD ("integ-alg", cli_type_enum, .flags = CLI_F_OPTIONAL,
		   .choices = ipsec_integ_alg_choices, .help = "integrity algorithm"),
      CLI_KEYWORD ("integ-key", cli_type_ipsec_key, .flags = CLI_F_OPTIONAL),
      CLI_GROUP (
	"tunnel", "tunnel mode SA",
	CLI_KEYWORD ("src", cli_type_ip_address, .flags = CLI_F_OPTIONAL,
		     .help = "tunnel source address"),
	CLI_KEYWORD ("dst", cli_type_ip_address, .flags = CLI_F_OPTIONAL,
		     .help = "tunnel destination address"),
	CLI_KEYWORD ("table-id", cli_type_u32, .flags = CLI_F_OPTIONAL,
		     .help = "FIB table of the tunnel destination"),
	CLI_KEYWORD ("hop-limit", cli_type_u32, .max = 255, .flags = CLI_F_OPTIONAL),
	CLI_KEYWORD ("dscp", cli_type_enum, .flags = CLI_F_OPTIONAL, .choices = ip_dscp_choices),
	CLI_FLAG ("p2mp", .alias = "mp", .help = "multipoint tunnel"), CLI_FLAG ("track-mtu"),
	CLI_FLAG ("encap-copy-df"), CLI_FLAG ("encap-set-df"), CLI_FLAG ("encap-copy-dscp"),
	CLI_FLAG ("encap-copy-ecn"), CLI_FLAG ("decap-copy-ecn"), CLI_FLAG ("encap-inner-hash"),
	CLI_FLAG ("encap-copy-hop-limit"), CLI_FLAG ("encap-copy-flow-label")),
      CLI_KEYWORD ("udp-src-port", cli_type_u32, .max = 65535, .flags = CLI_F_OPTIONAL),
      CLI_KEYWORD ("udp-dst-port", cli_type_u32, .max = 65535, .flags = CLI_F_OPTIONAL),
      CLI_KEYWORD ("anti-replay-size", cli_type_u32, .flags = CLI_F_OPTIONAL,
		   .help = "anti-replay window size, enables anti-replay"),
      CLI_FLAG ("inbound", .help = "inbound SA"),
      CLI_FLAG ("use-anti-replay", .help = "enable anti-replay"),
      CLI_FLAG ("use-esn", .help = "extended sequence numbers"),
      CLI_FLAG ("udp-encap", .help = "UDP encapsulation"),
      CLI_FLAG ("async", .help = "use async crypto"),
      {},
    },
  .handler = ipsec_sa_add_command_fn,
};

static clib_error_t *
ipsec_sa_del_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  int rv = ipsec_sa_unlock_id (cli_u64 (ctx, "id", 0));

  if (rv)
    return clib_error_return (0, "failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (ipsec_sa_del_command, static) = {
  .path = "ipsec sa del",
  .short_help = "Delete an IPsec SA",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("id", cli_type_u32, .help = "SA id"),
      {},
    },
  .handler = ipsec_sa_del_command_fn,
};

static clib_error_t *
ipsec_sa_bind_common (cli_ctx_t *ctx, u32 worker, bool bind)
{
  switch (ipsec_sa_bind (cli_u64 (ctx, "sa-id", 0), worker, bind))
    {
    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "please specify a valid SA ID");
    case VNET_API_ERROR_INVALID_WORKER:
      return clib_error_return (0, "please specify a valid worker index");
    }

  return 0;
}

static clib_error_t *
ipsec_sa_bind_cli (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return ipsec_sa_bind_common (ctx, cli_u64 (ctx, "worker", 0), 1);
}

static clib_error_t *
ipsec_sa_unbind_cli (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return ipsec_sa_bind_common (ctx, ~0, 0);
}

VLIB_CLI_COMMAND (ipsec_sa_bind_cmd, static) = {
  .path = "ipsec sa bind",
  .short_help = "Bind an SA to a worker thread",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("sa-id", cli_type_u32),
      CLI_VALUE ("worker", cli_type_u32, .help = "worker index"),
      {},
    },
  .handler = ipsec_sa_bind_cli,
};

VLIB_CLI_COMMAND (ipsec_sa_unbind_cmd, static) = {
  .path = "ipsec sa unbind",
  .short_help = "Unbind an SA from its worker thread",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("sa-id", cli_type_u32),
      {},
    },
  .handler = ipsec_sa_unbind_cli,
};

static clib_error_t *
ipsec_spd_add_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ipsec_add_del_spd (vm, cli_u64 (ctx, "spd-id", 0), 1);
  return 0;
}

static clib_error_t *
ipsec_spd_del_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ipsec_add_del_spd (vm, cli_u64 (ctx, "spd-id", 0), 0);
  return 0;
}

VLIB_CLI_COMMAND (ipsec_spd_add_command, static) = {
  .path = "ipsec spd add",
  .short_help = "Add an SPD",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("spd-id", cli_type_u32),
      {},
    },
  .handler = ipsec_spd_add_command_fn,
};

VLIB_CLI_COMMAND (ipsec_spd_del_command, static) = {
  .path = "ipsec spd del",
  .short_help = "Delete an SPD",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("spd-id", cli_type_u32),
      {},
    },
  .handler = ipsec_spd_del_command_fn,
};

static const cli_choice_t ipsec_policy_action_choices[] = {
#define _(v, f, s) { s, 0, IPSEC_POLICY_ACTION_##f },
  foreach_ipsec_policy_action
#undef _
  {},
};

static void
ipsec_policy_set_range (cli_ctx_t *ctx, char *name, ip46_address_range_t *r, u8 *is_ip6)
{
  cli_value_t *v = cli_get (ctx, name);

  if (!v)
    return;

  if (v->ip_range.is_ip6)
    {
      clib_memcpy (&r->start.ip6, v->ip_range.start, 16);
      clib_memcpy (&r->stop.ip6, v->ip_range.stop, 16);
      *is_ip6 = 1;
    }
  else
    {
      clib_memcpy (&r->start.ip4, v->ip_range.start, 4);
      clib_memcpy (&r->stop.ip4, v->ip_range.stop, 4);
    }
}

static clib_error_t *
ipsec_policy_add_del (vlib_main_t *vm, cli_ctx_t *ctx, int is_add)
{
  ipsec_policy_t p = {};
  cli_value_t *v;
  u32 stat_index;
  int rv, is_outbound = cli_flag (ctx, "outbound");

  p.lport.stop = p.rport.stop = ~0;
  p.protocol = cli_u64 (ctx, "protocol", IPSEC_POLICY_PROTOCOL_ANY);
  p.id = cli_u64 (ctx, "spd", 0);
  p.priority = cli_u64 (ctx, "priority", 0);
  p.policy = cli_u64 (ctx, "action", IPSEC_POLICY_ACTION_BYPASS);
  p.sa_id = cli_u64 (ctx, "sa", 0);
  p.is_ipv6 = cli_flag (ctx, "ip6");

  if (p.policy == IPSEC_POLICY_ACTION_RESOLVE)
    return clib_error_return (0, "unsupported action: 'resolve'");

  ipsec_policy_set_range (ctx, "local-ip-range", &p.laddr, &p.is_ipv6);
  ipsec_policy_set_range (ctx, "remote-ip-range", &p.raddr, &p.is_ipv6);

  if (!cli_flag (ctx, "remote-ip-range"))
    {
      if (p.is_ipv6)
	clib_memset (&p.raddr.stop.ip6, 0xff, 16);
      else
	clib_memset (&p.raddr.stop.ip4, 0xff, 4);
    }
  if (!cli_flag (ctx, "local-ip-range"))
    {
      if (p.is_ipv6)
	clib_memset (&p.laddr.stop.ip6, 0xff, 16);
      else
	clib_memset (&p.laddr.stop.ip4, 0xff, 4);
    }

  if ((v = cli_get (ctx, "local-port-range")))
    {
      p.lport.start = v->range.start;
      p.lport.stop = v->range.stop;
    }
  if ((v = cli_get (ctx, "remote-port-range")))
    {
      p.rport.start = v->range.start;
      p.rport.stop = v->range.stop;
    }

  rv = ipsec_policy_mk_type (is_outbound, p.is_ipv6, p.policy, &p.type);
  if (rv)
    return clib_error_return (0, "unsupported policy type for: outbound:%s %s action:%U",
			      (is_outbound ? "yes" : "no"), (p.is_ipv6 ? "IPv6" : "IPv4"),
			      format_ipsec_policy_action, p.policy);

  rv = ipsec_add_del_policy (vm, &p, is_add, &stat_index);
  if (!rv)
    vlib_cli_output (vm, "policy-index:%d", stat_index);
  else
    vlib_cli_output (vm, "error:%d", rv);

  return 0;
}

static clib_error_t *
ipsec_policy_add_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return ipsec_policy_add_del (vm, ctx, 1);
}

static clib_error_t *
ipsec_policy_del_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return ipsec_policy_add_del (vm, ctx, 0);
}

/* Selectors of a policy, they are the same to add and to delete it */
#define IPSEC_POLICY_ARGS                                                                          \
  CLI_KEYWORD ("spd", cli_type_u32, .help = "SPD id"),                                             \
    CLI_ONEOF ("direction", CLI_F_OPTIONAL, CLI_FLAG ("inbound", .help = "inbound (default)"),     \
	       CLI_FLAG ("outbound")),                                                             \
    CLI_FLAG ("ip6", .help = "IPv6 policy"),                                                       \
    CLI_KEYWORD ("priority", cli_type_u32, .flags = CLI_F_OPTIONAL),                               \
    CLI_KEYWORD ("protocol", cli_type_u32, .max = 255, .flags = CLI_F_OPTIONAL,                    \
		 .help = "IP protocol number"),                                                    \
    CLI_KEYWORD ("action", cli_type_enum, .flags = CLI_F_OPTIONAL,                                 \
		 .choices = ipsec_policy_action_choices),                                          \
    CLI_KEYWORD ("sa", cli_type_u32, .flags = CLI_F_OPTIONAL, .help = "SA id for protect"),        \
    CLI_KEYWORD ("local-ip-range", cli_type_ip_range, .flags = CLI_F_OPTIONAL),                    \
    CLI_KEYWORD ("remote-ip-range", cli_type_ip_range, .flags = CLI_F_OPTIONAL),                   \
    CLI_KEYWORD ("local-port-range", cli_type_range, .max = 65535, .flags = CLI_F_OPTIONAL),       \
    CLI_KEYWORD ("remote-port-range", cli_type_range, .max = 65535, .flags = CLI_F_OPTIONAL)

VLIB_CLI_COMMAND (ipsec_policy_add_command, static) = {
  .path = "ipsec policy add",
  .short_help = "Add an IPsec policy",
  .args = (cli_arg_t[]) { IPSEC_POLICY_ARGS, {} },
  .handler = ipsec_policy_add_command_fn,
};

VLIB_CLI_COMMAND (ipsec_policy_del_command, static) = {
  .path = "ipsec policy del",
  .short_help = "Delete an IPsec policy",
  .args = (cli_arg_t[]) { IPSEC_POLICY_ARGS, {} },
  .handler = ipsec_policy_del_command_fn,
};

static void
ipsec_sa_show_all (vlib_main_t * vm, ipsec_main_t * im, u8 detail)
{
  u32 sai;

  pool_foreach_index (sai, im->sa_pool)
    {
      vlib_cli_output (vm, "%U", format_ipsec_sa, sai,
		       (detail ? IPSEC_FORMAT_DETAIL : IPSEC_FORMAT_BRIEF));
    }
}

static void
ipsec_spd_show_all (vlib_main_t * vm, ipsec_main_t * im)
{
  u32 spdi;

  pool_foreach_index (spdi, im->spds)  {
    vlib_cli_output(vm, "%U", format_ipsec_spd, spdi);
  }

  if (im->output_flow_cache_flag)
    {
      vlib_cli_output (vm, "%U", format_ipsec_out_spd_flow_cache);
    }
  if (im->input_flow_cache_flag)
    {
      vlib_cli_output (vm, "%U", format_ipsec_in_spd_flow_cache);
    }
}

static void
ipsec_spd_bindings_show_all (vlib_main_t * vm, ipsec_main_t * im)
{
  u32 sw_if_index;
  ipsec_spd_t *spd;

  vlib_cli_output (vm, "SPD Bindings:");

  vec_foreach_index (sw_if_index, im->spd_index_by_sw_if_index)
    {
      u32 spd_index = im->spd_index_by_sw_if_index[sw_if_index];

      if (spd_index == INDEX_INVALID)
	continue;
      spd = pool_elt_at_index (im->spds, spd_index);
      vlib_cli_output (vm, "  %d -> %U", spd->id, format_vnet_sw_if_index_name, im->vnet_main,
		       sw_if_index);
    }
}

static walk_rc_t
ipsec_tun_protect_show_one (index_t itpi, void *ctx)
{
  vlib_cli_output (ctx, "%U", format_ipsec_tun_protect_index, itpi);

  return (WALK_CONTINUE);
}

static void
ipsec_tunnel_show_all (vlib_main_t * vm)
{
  ipsec_tun_protect_walk (ipsec_tun_protect_show_one, vm);
}

static clib_error_t *
show_ipsec_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ipsec_main_t *im = &ipsec_main;

  ipsec_sa_show_all (vm, im, 0);
  ipsec_spd_show_all (vm, im);
  ipsec_spd_bindings_show_all (vm, im);
  ipsec_tun_protect_walk (ipsec_tun_protect_show_one, vm);

  vlib_cli_output (vm, "IPSec async mode: %s", (im->async_mode ? "on" : "off"));

  return 0;
}

VLIB_CLI_COMMAND (show_ipsec_command, static) = {
  .path = "show ipsec all",
  .short_help = "Show SAs, SPDs, bindings and tunnel protection",
  .handler = show_ipsec_command_fn,
};

static clib_error_t *
show_ipsec_sa_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ipsec_main_t *im = &ipsec_main;

  if (!cli_flag (ctx, "index"))
    ipsec_sa_show_all (vm, im, cli_flag (ctx, "detail"));
  else
    vlib_cli_output (vm, "%U", format_ipsec_sa, (u32) cli_u64 (ctx, "index", 0),
		     IPSEC_FORMAT_DETAIL | IPSEC_FORMAT_INSECURE);

  return 0;
}

static clib_error_t *
clear_ipsec_sa_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ipsec_main_t *im = &ipsec_main;
  u32 sai;

  if (!cli_flag (ctx, "index"))
    {
      pool_foreach_index (sai, im->sa_pool)
	ipsec_sa_clear (sai);
      return 0;
    }

  sai = cli_u64 (ctx, "index", 0);
  if (pool_is_free_index (im->sa_pool, sai))
    return clib_error_return (0, "unknown SA index: %d", sai);

  ipsec_sa_clear (sai);
  return 0;
}

VLIB_CLI_COMMAND (show_ipsec_sa_command, static) = {
  .path = "show ipsec sa",
  .short_help = "Show one or all SAs",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("index", cli_type_u32, .flags = CLI_F_OPTIONAL, .help = "SA index"),
      CLI_FLAG ("detail", .help = "more details"),
      {},
    },
  .handler = show_ipsec_sa_command_fn,
};

VLIB_CLI_COMMAND (clear_ipsec_sa_command, static) = {
  .path = "clear ipsec sa",
  .short_help = "Clear the counters of one or all SAs",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("index", cli_type_u32, .flags = CLI_F_OPTIONAL, .help = "SA index"),
      {},
    },
  .handler = clear_ipsec_sa_command_fn,
};

static clib_error_t *
show_ipsec_spd_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ipsec_main_t *im = &ipsec_main;

  if (cli_flag (ctx, "bindings"))
    ipsec_spd_bindings_show_all (vm, im);
  else if (cli_flag (ctx, "index"))
    vlib_cli_output (vm, "%U", format_ipsec_spd, (u32) cli_u64 (ctx, "index", 0));
  else
    ipsec_spd_show_all (vm, im);

  return 0;
}

VLIB_CLI_COMMAND (show_ipsec_spd_command, static) = {
  .path = "show ipsec spd",
  .short_help = "Show one or all SPDs",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("index", cli_type_u32, .flags = CLI_F_OPTIONAL, .help = "SPD index"),
      CLI_FLAG ("bindings", .help = "show interface bindings"),
      {},
    },
  .handler = show_ipsec_spd_command_fn,
};

static clib_error_t *
show_ipsec_tunnel_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ipsec_tunnel_show_all (vm);

  return 0;
}

VLIB_CLI_COMMAND (show_ipsec_tunnel_command, static) = {
  .path = "show ipsec tunnel",
  .short_help = "Show tunnel protection",
  .handler = show_ipsec_tunnel_command_fn,
};

static clib_error_t *
clear_ipsec_counters_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vlib_clear_combined_counters (&ipsec_spd_policy_counters);
  vlib_clear_combined_counters (&ipsec_sa_counters);
  for (int i = 0; i < IPSEC_SA_N_ERRORS; i++)
    vlib_clear_simple_counters (&ipsec_sa_err_counters[i]);

  return 0;
}

VLIB_CLI_COMMAND (clear_ipsec_counters_command, static) = {
  .path = "clear ipsec counters",
  .short_help = "Clear all IPsec counters",
  .handler = clear_ipsec_counters_command_fn,
};

static void
ipsec_tun_protect_peer (cli_ctx_t *ctx, ip_address_t *peer)
{
  cli_value_t *v = cli_get (ctx, "peer");

  if (v)
    ip_address_set (peer, v->prefix.addr, v->prefix.is_ip6 ? AF_IP6 : AF_IP4);
}

static clib_error_t *
ipsec_tun_protect_add_cmd (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u32 *sa_ins = 0;
  ip_address_t peer = {};
  cli_value_t *v;

  ipsec_tun_protect_peer (ctx, &peer);
  cli_foreach (v, ctx, "sa-in") vec_add1 (sa_ins, v->u64);

  ipsec_tun_protect_update (cli_index (ctx, "interface"), &peer, cli_u64 (ctx, "sa-out", 0),
			    sa_ins);
  return 0;
}

static clib_error_t *
ipsec_tun_protect_del_cmd (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ip_address_t peer = {};

  ipsec_tun_protect_peer (ctx, &peer);
  ipsec_tun_protect_del (cli_index (ctx, "interface"), &peer);
  return 0;
}

/**
 * Protect tunnel with IPSEC
 */
VLIB_CLI_COMMAND (ipsec_tun_protect_add_cmd_node, static) = {
  .path = "ipsec tunnel protect add",
  .short_help = "Protect a tunnel interface with IPsec SAs",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_sw_interface),
      CLI_VALUE ("peer", cli_type_ip_address, .flags = CLI_F_OPTIONAL,
		 .help = "peer address for multipoint tunnels"),
      CLI_KEYWORD ("sa-in", cli_type_u32, .flags = CLI_F_REPEAT,
		   .help = "inbound SA id, can be given more than once"),
      CLI_KEYWORD ("sa-out", cli_type_u32, .help = "outbound SA id"),
      {},
    },
  .handler = ipsec_tun_protect_add_cmd,
};

VLIB_CLI_COMMAND (ipsec_tun_protect_del_cmd_node, static) = {
  .path = "ipsec tunnel protect del",
  .short_help = "Remove the IPsec protection of a tunnel interface",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_sw_interface),
      CLI_VALUE ("peer", cli_type_ip_address, .flags = CLI_F_OPTIONAL,
		 .help = "peer address for multipoint tunnels"),
      {},
    },
  .handler = ipsec_tun_protect_del_cmd,
};

static clib_error_t *
ipsec_tun_protect_show (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ipsec_tun_protect_walk (ipsec_tun_protect_show_one, vm);

  return 0;
}

/**
 * show IPSEC tunnel protection
 */
VLIB_CLI_COMMAND (ipsec_tun_protect_show_node, static) = {
  .path = "show ipsec protect",
  .short_help = "Show tunnel protection",
  .handler = ipsec_tun_protect_show,
};

static int
ipsec_tun_protect4_hash_show_one (clib_bihash_kv_8_16_t * kv, void *arg)
{
  ipsec4_tunnel_kv_t *ikv = (ipsec4_tunnel_kv_t *) kv;
  vlib_main_t *vm = arg;

  vlib_cli_output (vm, " %U", format_ipsec4_tunnel_kv, ikv);

  return (BIHASH_WALK_CONTINUE);
}

static int
ipsec_tun_protect6_hash_show_one (clib_bihash_kv_24_16_t * kv, void *arg)
{
  ipsec6_tunnel_kv_t *ikv = (ipsec6_tunnel_kv_t *) kv;
  vlib_main_t *vm = arg;

  vlib_cli_output (vm, " %U", format_ipsec6_tunnel_kv, ikv);

  return (BIHASH_WALK_CONTINUE);
}

static clib_error_t *
ipsec_tun_protect_hash_show (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ipsec_main_t *im = &ipsec_main;

  vlib_cli_output (vm, "IPv4:");
  clib_bihash_foreach_key_value_pair_8_16 (&im->tun4_protect_by_key,
					   ipsec_tun_protect4_hash_show_one, vm);

  vlib_cli_output (vm, "IPv6:");
  clib_bihash_foreach_key_value_pair_24_16 (&im->tun6_protect_by_key,
					    ipsec_tun_protect6_hash_show_one, vm);

  return 0;
}

/**
 * show IPSEC tunnel protection hash tables
 */
VLIB_CLI_COMMAND (ipsec_tun_protect_hash_show_node, static) = {
  .path = "show ipsec protect-hash",
  .short_help = "Show tunnel protection hash tables",
  .handler = ipsec_tun_protect_hash_show,
};

clib_error_t *
ipsec_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ipsec_cli_init);

static clib_error_t *
set_async_mode_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ipsec_set_async_mode (cli_index (ctx, "mode"));

  return 0;
}

VLIB_CLI_COMMAND (set_async_mode_command, static) = {
  .path = "set ipsec async mode",
  .short_help = "Enable or disable asynchronous crypto processing of IPsec",
  .args =
    (cli_arg_t[]) {
      CLI_ENUM ("mode", 0, { "on", "async mode on", 1 }, { "off", "async mode off", 0 }),
      {},
    },
  .handler = set_async_mode_command_fn,
};
