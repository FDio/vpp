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

#include <af_xdp/af_xdp.h>

static u8 *
parse_af_xdp_num_rx_queues (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  u8 *err;

  if (vec_len (tok) == 3 && memcmp (tok, "all", 3) == 0)
    {
      v->u64 = AF_XDP_NUM_RX_QUEUES_ALL;
      return 0;
    }

  if ((err = cli_type_u32.parse (a, tok, v)))
    {
      vec_free (err);
      return format (0, "'%v' is not a number or 'all'", tok);
    }

  return 0;
}

static void
complete_af_xdp_num_rx_queues (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  if (cli_prefix_match ("all", prefix))
    cli_candidate_add (out, "all", "one queue for each queue of the kernel interface");
}

CLIB_CLI_TYPE (cli_type_af_xdp_num_rx_queues, static) = {
  .name = "number",
  .help = "number of queues, or 'all'",
  .parse = parse_af_xdp_num_rx_queues,
  .complete = complete_af_xdp_num_rx_queues,
};

/* a copy of the string argument, 0 if it was not given */
static char *
af_xdp_cli_string (cli_ctx_t *ctx, const char *name)
{
  cli_value_t *v = cli_get (ctx, name);

  if (v == 0)
    return 0;

  return (char *) vec_dup (v->str);
}

static clib_error_t *
af_xdp_create_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  af_xdp_create_if_args_t args = {
    .rxq_size = cli_u64 (ctx, "rx-queue-size", 0),
    .txq_size = cli_u64 (ctx, "tx-queue-size", 0),
    .rxq_num = cli_u64 (ctx, "num-rx-queues", 0),
    .busy_poll_usecs = cli_u64 (ctx, "busy-poll-usecs", 0),
    .busy_poll_budget = cli_u64 (ctx, "busy-poll-budget", 0),
  };

  if (cli_flag (ctx, "no-zero-copy"))
    args.mode = AF_XDP_MODE_COPY;
  else if (cli_flag (ctx, "zero-copy"))
    args.mode = AF_XDP_MODE_ZERO_COPY;

  if (cli_flag (ctx, "mac-reuse"))
    args.flags |= AF_XDP_CREATE_FLAGS_MAC_REUSE;
  if (cli_flag (ctx, "multi-buffer"))
    args.flags |= AF_XDP_CREATE_FLAGS_MULTI_BUFFER;
  if (cli_flag (ctx, "no-syscall-lock"))
    args.flags |= AF_XDP_CREATE_FLAGS_NO_SYSCALL_LOCK;

  args.linux_ifname = af_xdp_cli_string (ctx, "host-if");
  args.name = af_xdp_cli_string (ctx, "name");
  args.prog = af_xdp_cli_string (ctx, "prog");
  args.netns = af_xdp_cli_string (ctx, "netns");

  af_xdp_create_if (vm, &args);

  vec_free (args.linux_ifname);
  vec_free (args.name);
  vec_free (args.prog);
  vec_free (args.netns);

  return args.error;
}

VLIB_CLI_COMMAND (af_xdp_create_command, static) = {
  .path = "create interface af_xdp",
  .short_help = "Create an AF_XDP interface",
  .long_help = "prog: a bare filename (e.g. xsk_def_xdp_prog.o) is searched in "
	       "LIBXDP_OBJECT_PATH (/usr/lib/bpf), a path containing '/' "
	       "(e.g. /path/to/prog.o) is opened directly from the filesystem",
  .args = CLI_ARGS (
    CLI_KEYWORD ("host-if", cli_type_string, .help = "name of the kernel interface"),
    CLI_OPT_KEYWORD ("name", cli_type_string, .help = "name of the interface"),
    CLI_OPT_KEYWORD ("rx-queue-size", cli_type_u32),
    CLI_OPT_KEYWORD ("tx-queue-size", cli_type_u32),
    CLI_OPT_KEYWORD ("num-rx-queues", cli_type_af_xdp_num_rx_queues),
    CLI_OPT_KEYWORD ("busy-poll-usecs", cli_type_u32),
    CLI_OPT_KEYWORD ("busy-poll-budget", cli_type_u32, .max = 0xffff, .help = "packets"),
    CLI_OPT_KEYWORD ("prog", cli_type_string, .help = "XDP program"),
    CLI_OPT_KEYWORD ("netns", cli_type_string, .help = "network namespace"),
    CLI_FLAG ("zero-copy", .excludes = "no-zero-copy"), CLI_FLAG ("no-zero-copy"),
    CLI_FLAG ("no-syscall-lock"), CLI_FLAG ("mac-reuse"),
    CLI_FLAG ("multi-buffer", .excludes = "no-multi-buffer"), CLI_FLAG ("no-multi-buffer")),
  .handler = af_xdp_create_command_fn,
};

static clib_error_t *
af_xdp_delete_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_hw_interface_t *hw;
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad;
  vnet_main_t *vnm = vnet_get_main ();

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, cli_index (ctx, "interface"));
  if (hw == NULL || af_xdp_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not an AF_XDP interface");

  ad = pool_elt_at_index (am->devices, hw->dev_instance);

  if (af_xdp_delete_if (vm, ad))
    return clib_error_return (0, "failed to delete AF_XDP interface");

  return 0;
}

VLIB_CLI_COMMAND (af_xdp_delete_command, static) = {
  .path = "delete interface af_xdp",
  .short_help = "Delete an AF_XDP interface",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_sw_interface, .alt_keyword = "sw_if_index")),
  .handler = af_xdp_delete_command_fn,
};

clib_error_t *
af_xdp_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (af_xdp_cli_init);
