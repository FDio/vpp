/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include "ipip.h"
#include <vppinfra/error.h>
#include <vnet/vnet.h>
#include <vnet/fib/fib_table.h>
#include <vnet/interface/cli_types.h>
#include <vnet/ip/cli_types.h>

static const cli_choice_t ipip_flag_choices[] = {
#define _(n, s, v) { s, 0, v },
  foreach_tunnel_encap_decap_flag
#undef _
  {},
};

static void
ipip_cli_address (cli_value_t *v, ip46_address_t *a)
{
  if (v->prefix.is_ip6)
    clib_memcpy (&a->ip6, v->prefix.addr, 16);
  else
    ip46_address_set_ip4 (a, (ip4_address_t *) v->prefix.addr);
}

/* the tunnel is given as sw_if_index <n>, or as the name of the interface */
#define IPIP_CLI_DELETE_ARGS                                                                       \
  CLI_ONEOF ("tunnel", 0, CLI_KEYWORD ("sw_if_index", cli_type_u32),                               \
	     CLI_VALUE ("interface", cli_type_sw_interface))

static u32
ipip_cli_sw_if_index (cli_ctx_t *ctx)
{
  cli_value_t *v = cli_get (ctx, "sw_if_index");

  return v ? v->u64 : cli_index (ctx, "interface");
}

static clib_error_t *
create_ipip_tunnel_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ip46_address_t src = ip46_address_initializer, dst = ip46_address_initializer;
  cli_value_t *vsrc = cli_get (ctx, "src"), *vdst = cli_get (ctx, "dst");
  u32 instance = cli_u64 (ctx, "instance", ~0);
  u32 table_id = cli_u64 (ctx, "outer-table-id", 0);
  tunnel_mode_t mode = cli_flag (ctx, "p2mp") ? TUNNEL_MODE_MP : TUNNEL_MODE_P2P;
  tunnel_encap_decap_flags_t flags = TUNNEL_ENCAP_DECAP_FLAG_NONE;
  u32 fib_index, sw_if_index;
  int rv, is_ip6 = vsrc->prefix.is_ip6;
  cli_value_t *vflags;

  if (!vdst && mode != TUNNEL_MODE_MP)
    return clib_error_return (0, "mandatory argument(s) missing");

  cli_foreach (vflags, ctx, "flags") flags |= vflags->u64;

  if (vdst && vdst->prefix.is_ip6 != is_ip6)
    return clib_error_return (0, "source and destination must be of same address family");

  ipip_cli_address (vsrc, &src);
  if (vdst)
    ipip_cli_address (vdst, &dst);

  fib_index = fib_table_find (fib_ip_proto (is_ip6), table_id);

  if (~0 == fib_index)
    rv = VNET_API_ERROR_NO_SUCH_FIB;
  else
    rv = ipip_add_tunnel (is_ip6 ? IPIP_TRANSPORT_IP6 : IPIP_TRANSPORT_IP4, instance, &src, &dst,
			  fib_index, flags, IP_DSCP_CS0, mode, &sw_if_index);

  switch (rv)
    {
    case 0:
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index);
      return 0;
    case VNET_API_ERROR_IF_ALREADY_EXISTS:
      return clib_error_return (0, "IPIP tunnel already exists...");
    case VNET_API_ERROR_NO_SUCH_FIB:
      return clib_error_return (0, "outer fib ID %d doesn't exist", table_id);
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "IPIP tunnel doesn't exist");
    case VNET_API_ERROR_INSTANCE_IN_USE:
      return clib_error_return (0, "Instance is in use");
    case VNET_API_ERROR_INVALID_DST_ADDRESS:
      return clib_error_return (0, "destination IP address when mode is multi-point");
    default:
      return clib_error_return (0, "vnet_ipip_add_del_tunnel returned %d", rv);
    }
}

static clib_error_t *
delete_ipip_tunnel_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  int rv = ipip_del_tunnel (ipip_cli_sw_if_index (ctx));

  if (rv)
    return clib_error_return (0, "deleting the tunnel failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (create_ipip_tunnel_command, static) = {
  .path = "create ipip tunnel",
  .short_help = "Create an IPIP tunnel",
  .args = CLI_ARGS (
    CLI_KEYWORD ("src", cli_type_ip_address, .help = "tunnel source address"),
    CLI_OPT_KEYWORD ("dst", cli_type_ip_address, .help = "tunnel destination address"),
    CLI_FLAG ("p2p", .excludes = "p2mp", .help = "point-to-point tunnel, the default"),
    CLI_FLAG ("p2mp", .alias = "mp", .excludes = "p2p", .help = "multi-point tunnel"),
    CLI_OPT_KEYWORD ("instance", cli_type_u32, .max = CLIB_U32_MAX - 1,
		     .help = "interface instance number"),
    CLI_OPT_KEYWORD ("outer-table-id", cli_type_u32, .help = "FIB table of the outer header"),
    CLI_OPT_KEYWORD_F ("flags", cli_type_flags, CLI_F_REPEAT, .choices = ipip_flag_choices,
		       .help = "encapsulation and decapsulation flags")),
  .handler = create_ipip_tunnel_command_fn,
};

VLIB_CLI_COMMAND (delete_ipip_tunnel_command, static) = {
  .path = "delete ipip tunnel",
  .short_help = "Delete an IPIP tunnel",
  .args = CLI_ARGS (IPIP_CLI_DELETE_ARGS),
  .handler = delete_ipip_tunnel_command_fn,
};

static u8 *
format_ipip_tunnel (u8 * s, va_list * args)
{
  ipip_tunnel_t *t = va_arg (*args, ipip_tunnel_t *);

  ip46_type_t type =
    (t->transport == IPIP_TRANSPORT_IP4) ? IP46_TYPE_IP4 : IP46_TYPE_IP6;
  u32 table_id;

  table_id = fib_table_get_table_id (t->fib_index,
				     fib_proto_from_ip46 (type));
  switch (t->mode)
    {
    case IPIP_MODE_6RD:
      s = format (s, "[%d] 6rd src %U ip6-pfx %U/%d ",
		  t->dev_instance,
		  format_ip46_address, &t->tunnel_src, type,
		  format_ip6_address, &t->sixrd.ip6_prefix,
		  t->sixrd.ip6_prefix_len);
      break;
    case IPIP_MODE_P2P:
      s = format (s, "[%d] instance %d src %U dst %U ",
		  t->dev_instance, t->user_instance,
		  format_ip46_address, &t->tunnel_src, type,
		  format_ip46_address, &t->tunnel_dst, type);
      break;
    case IPIP_MODE_P2MP:
      s = format (s, "[%d] instance %d p2mp src %U ",
		  t->dev_instance, t->user_instance,
		  format_ip46_address, &t->tunnel_src, type);
      break;
    }

  s = format (s, "table-ID %d sw-if-idx %d flags [%U] dscp %U",
	      table_id, t->sw_if_index,
	      format_tunnel_encap_decap_flags, t->flags,
	      format_ip_dscp, t->dscp);

  return s;
}

static clib_error_t *
show_ipip_tunnel_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ipip_main_t *gm = &ipip_main;
  ipip_tunnel_t *t;
  u32 ti = cli_u64 (ctx, "index", ~0);

  if (pool_elts (gm->tunnels) == 0)
    vlib_cli_output (vm, "No IPIP tunnels configured...");

  if (ti == ~0)
    {
    pool_foreach (t, gm->tunnels)
                  {vlib_cli_output(vm, "%U", format_ipip_tunnel, t); }
    }
  else
    {
      if (pool_is_free_index (gm->tunnels, ti))
	return clib_error_return (0, "unknown index:%d", ti);
      t = pool_elt_at_index (gm->tunnels, ti);
      if (t)
	vlib_cli_output (vm, "%U", format_ipip_tunnel, t);
    }
  return 0;
}

VLIB_CLI_COMMAND (show_ipip_tunnel_command, static) = {
  .path = "show ipip tunnel",
  .short_help = "Show the IPIP tunnels",
  .args = CLI_ARGS (CLI_VALUE ("index", cli_type_u32, .flags = CLI_F_OPTIONAL,
			       .help = "tunnel index, default all")),
  .handler = show_ipip_tunnel_command_fn,
};

static u8 *
format_ipip_tunnel_key (u8 * s, va_list * args)
{
  ipip_tunnel_key_t *t = va_arg (*args, ipip_tunnel_key_t *);

  s = format (s, "src:%U dst:%U fib:%d transport:%d mode:%d",
	      format_ip46_address, &t->src, IP46_TYPE_ANY,
	      format_ip46_address, &t->dst, IP46_TYPE_ANY,
	      t->fib_index, t->transport, t->mode);

  return (s);
}

static clib_error_t *
ipip_tunnel_hash_show (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ipip_main_t *im = &ipip_main;
  ipip_tunnel_key_t *key;
  u32 index;

  hash_foreach(key, index, im->tunnel_by_key,
  ({
      vlib_cli_output (vm, " %U -> %d", format_ipip_tunnel_key, key, index);
  }));

  return NULL;
}

/**
 * show IPSEC tunnel protection hash tables
 */
VLIB_CLI_COMMAND (ipip_tunnel_hash_show_node, static) = {
  .path = "show ipip tunnel-hash",
  .handler = ipip_tunnel_hash_show,
  .short_help = "Show the IPIP tunnel hash table",
};

static clib_error_t *
create_sixrd_tunnel_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  cli_value_t *p6 = cli_get (ctx, "ip6-pfx"), *p4 = cli_get (ctx, "ip4-pfx");
  cli_value_t *src = cli_get (ctx, "ip4-src");
  u32 ip4_table_id = cli_u64 (ctx, "ip4-table-id", 0);
  u32 ip6_table_id = cli_u64 (ctx, "ip6-table-id", 0);
  u32 ip4_fib_index, ip6_fib_index, sixrd_tunnel_index;
  int rv;

  if (!p6->prefix.is_ip6)
    return clib_error_return (0, "ip6-pfx needs an IPv6 prefix");
  if (p4->prefix.is_ip6 || src->prefix.is_ip6)
    return clib_error_return (0, "ip4-pfx and ip4-src need IPv4 addresses");

  ip4_fib_index = fib_table_find (FIB_PROTOCOL_IP4, ip4_table_id);
  ip6_fib_index = fib_table_find (FIB_PROTOCOL_IP6, ip6_table_id);

  if (~0 == ip4_fib_index)
    return clib_error_return (0, "No such IP4 table %d", ip4_table_id);
  if (~0 == ip6_fib_index)
    return clib_error_return (0, "No such IP6 table %d", ip6_table_id);

  rv = sixrd_add_tunnel ((ip6_address_t *) p6->prefix.addr, p6->prefix.len,
			 (ip4_address_t *) p4->prefix.addr, p4->prefix.len,
			 (ip4_address_t *) src->prefix.addr, cli_flag (ctx, "security-check"),
			 ip4_fib_index, ip6_fib_index, &sixrd_tunnel_index);
  if (rv)
    return clib_error_return (0, "adding tunnel failed %d", rv);
  return 0;
}

static clib_error_t *
delete_sixrd_tunnel_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  int rv = sixrd_del_tunnel (ipip_cli_sw_if_index (ctx));

  if (rv)
    return clib_error_return (0, "deleting the tunnel failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (create_sixrd_tunnel_command, static) = {
  .path = "create 6rd tunnel",
  .short_help = "Create a 6rd tunnel",
  .args = CLI_ARGS (CLI_KEYWORD ("ip6-pfx", cli_type_ip_prefix, .help = "IPv6 prefix"),
		    CLI_KEYWORD ("ip4-pfx", cli_type_ip_prefix, .help = "IPv4 prefix"),
		    CLI_KEYWORD ("ip4-src", cli_type_ip_address, .help = "IPv4 source address"),
		    CLI_OPT_KEYWORD ("ip4-table-id", cli_type_u32),
		    CLI_OPT_KEYWORD ("ip6-table-id", cli_type_u32),
		    CLI_FLAG ("security-check",
			      .help = "check the source of decapsulated packets")),
  .handler = create_sixrd_tunnel_command_fn,
};

VLIB_CLI_COMMAND (delete_sixrd_tunnel_command, static) = {
  .path = "delete 6rd tunnel",
  .short_help = "Delete a 6rd tunnel",
  .args = CLI_ARGS (IPIP_CLI_DELETE_ARGS),
  .handler = delete_sixrd_tunnel_command_fn,
};
