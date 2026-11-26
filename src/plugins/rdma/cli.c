/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/cli_types.h>

#include <rdma/rdma.h>

static const cli_choice_t rdma_mode_choices[] = {
  { "auto", "pick the best mode", RDMA_MODE_AUTO },
  { "ibv", "use the verbs library", RDMA_MODE_IBV },
  { "dv", "use direct verbs", RDMA_MODE_DV },
  {},
};

static const cli_choice_t rdma_on_off_choices[] = {
  { "on", "inline small packets", 1 },
  { "off", "do not inline", 0 },
  {},
};

enum
{
  RDMA_CLI_RSS6 = 0x100, /* marks the IPv6 choices, the low bits are the rdma_rss6_t */
};

static const cli_choice_t rdma_rss_choices[] = {
  { "ipv4", "hash IPv4 addresses", RDMA_RSS4_IP },
  { "ipv4-udp", "hash IPv4 addresses and UDP ports", RDMA_RSS4_IP_UDP },
  { "ipv4-tcp", "hash IPv4 addresses and TCP ports", RDMA_RSS4_IP_TCP },
  { "ipv6", "hash IPv6 addresses", RDMA_CLI_RSS6 | RDMA_RSS6_IP },
  { "ipv6-udp", "hash IPv6 addresses and UDP ports", RDMA_CLI_RSS6 | RDMA_RSS6_IP_UDP },
  { "ipv6-tcp", "hash IPv6 addresses and TCP ports", RDMA_CLI_RSS6 | RDMA_RSS6_IP_TCP },
  {},
};

static clib_error_t *
rdma_create_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  rdma_create_if_args_t args = {
    .rxq_size = cli_u64 (ctx, "rx-queue-size", 0),
    .txq_size = cli_u64 (ctx, "tx-queue-size", 0),
    .rxq_num = cli_u64 (ctx, "num-rx-queues", 0),
    .max_pktlen = cli_u64 (ctx, "max-pktlen", 0),
    .port_num = cli_u64 (ctx, "port-num", 0),
    .disable_striding_rq = cli_flag (ctx, "no-striding"),
    .no_multi_seg = cli_flag (ctx, "no-multi-seg"),
    .no_rx_cksum = cli_flag (ctx, "no-rx-cksum"),
    .no_empw = cli_flag (ctx, "no-empw"),
  };
  cli_value_t *v;

  if (cli_flag (ctx, "mode"))
    args.mode = cli_index (ctx, "mode");

  if (cli_index (ctx, "tx-empw-inline") == 1)
    args.tx_empw_inline_max = cli_u64 (ctx, "max-size", RDMA_MLX5_EMPW_INLINE_DEFAULT);
  else if (cli_flag (ctx, "max-size"))
    return clib_error_return (0, "'max-size' can be used only with 'tx-empw-inline on'");

  cli_foreach (v, ctx, "rss")
  {
    if (v->index & RDMA_CLI_RSS6)
      args.rss6 = v->index & ~RDMA_CLI_RSS6;
    else
      args.rss4 = v->index;
  }

  args.ifname = vec_dup (cli_get (ctx, "host-if")->str);

  if ((v = cli_get (ctx, "name")))
    args.name = vec_dup (v->str);

  rdma_create_if (vm, &args);

  vec_free (args.ifname);
  vec_free (args.name);

  return args.error;
}

VLIB_CLI_COMMAND (rdma_create_command, static) = {
  .path = "create interface rdma",
  .short_help = "Create an RDMA interface",
  .args =
    CLI_ARGS (CLI_KEYWORD ("host-if", cli_type_string, .help = "name of the kernel interface"),
	      CLI_OPT_KEYWORD ("name", cli_type_string, .help = "name of the interface"),
	      CLI_OPT_KEYWORD ("rx-queue-size", cli_type_u32),
	      CLI_OPT_KEYWORD ("tx-queue-size", cli_type_u32),
	      CLI_OPT_KEYWORD ("num-rx-queues", cli_type_u32),
	      CLI_OPT_KEYWORD ("tx-empw-inline", cli_type_enum, .choices = rdma_on_off_choices),
	      CLI_OPT_KEYWORD ("max-size", cli_type_u32, .min = 1, .requires = "tx-empw-inline",
			       .help = "largest packet which is inlined, in bytes"),
	      CLI_OPT_KEYWORD ("mode", cli_type_enum, .choices = rdma_mode_choices),
	      CLI_OPT_KEYWORD ("port-num", cli_type_u32, .min = 1, .max = 255),
	      CLI_OPT_KEYWORD_F ("rss", cli_type_enum, CLI_F_REPEAT, .choices = rdma_rss_choices),
	      CLI_OPT_KEYWORD ("max-pktlen", cli_type_u32), CLI_FLAG ("no-multi-seg"),
	      CLI_FLAG ("no-striding"), CLI_FLAG ("no-empw"), CLI_FLAG ("no-rx-cksum")),
  .handler = rdma_create_command_fn,
};

static rdma_device_t *
rdma_cli_get_device (cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  rdma_main_t *rm = &rdma_main;
  vnet_hw_interface_t *hw;

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, cli_index (ctx, "interface"));
  if (hw == NULL || rdma_device_class.index != hw->dev_class_index)
    return 0;

  return pool_elt_at_index (rm->devices, hw->dev_instance);
}

static clib_error_t *
rdma_delete_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  rdma_device_t *rd = rdma_cli_get_device (ctx);

  if (rd == 0)
    return clib_error_return (0, "not a RDMA interface");

  rdma_delete_if (vm, rd);

  return 0;
}

VLIB_CLI_COMMAND (rdma_delete_command, static) = {
  .path = "delete interface rdma",
  .short_help = "Delete an RDMA interface",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_sw_interface, .alt_keyword = "sw_if_index")),
  .handler = rdma_delete_command_fn,
};

static clib_error_t *
test_rdma_dump_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  rdma_device_t *rd = rdma_cli_get_device (ctx);
  int i;

  if (rd == 0)
    return clib_error_return (0, "not a RDMA interface");

  if ((rd->flags & RDMA_DEVICE_F_MLX5DV) == 0)
    return clib_error_return (0, "not a mlx5 interface");

  vlib_cli_output (vm, "netdev %s pci-addr %U lkey 0x%x",
		   rd->linux_ifname, format_vlib_pci_addr, &rd->pci->addr,
		   &rd->lkey);

  vec_foreach_index (i, rd->rxqs)
  {
    vlib_cli_output (vm, "RX queue %u\n  %U\n", i, format_rdma_rxq, rd, i);
  }

  return 0;
}

VLIB_CLI_COMMAND (test_rdma_mlx5dv_dump_command, static) = {
  .path = "test rdma dump",
  .short_help = "Dump the RX queues of an RDMA interface",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_sw_interface, .alt_keyword = "sw_if_index")),
  .handler = test_rdma_dump_command_fn,
};

clib_error_t *
rdma_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (rdma_cli_init);
