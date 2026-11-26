/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018-2025 Cisco and/or its affiliates.
 */
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/cli_types.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/pci.h>

static u8 *
parse_virtio_pci_addr (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  unformat_input_t in;
  vlib_pci_addr_t addr;
  int ok;

  unformat_init_vector (&in, vec_dup (tok));
  ok = unformat (&in, "%U", unformat_vlib_pci_addr, &addr) &&
       unformat_check_input (&in) == UNFORMAT_END_OF_INPUT;
  unformat_free (&in);

  if (!ok)
    return format (0, "'%v' is not a PCI address like 0000:00:04.0", tok);

  v->u64 = addr.as_u32;

  return 0;
}

CLIB_CLI_TYPE (cli_type_virtio_pci_addr, static) = {
  .name = "pci-address",
  .help = "PCI address, 0000:00:04.0",
  .parse = parse_virtio_pci_addr,
};

static clib_error_t *
virtio_pci_create_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  virtio_pci_create_if_args_t args = {
    .addr = cli_u64 (ctx, "pci-address", 0),
    .features = cli_u64 (ctx, "feature-mask", 0),
    .tx_queue_size = cli_u64 (ctx, "tx-queue-size", 0),
    .gso_enabled = cli_flag (ctx, "gso-enabled"),
    .checksum_offload_enabled = cli_flag (ctx, "csum-enabled"),
    .mac_filter_enabled = cli_flag (ctx, "mac-filter-enabled"),
    .rss_enabled = cli_flag (ctx, "rss-enabled"),
    .buffering_size = cli_u64 (ctx, "size", 0),
  };
  cli_value_t *v;

  if (cli_flag (ctx, "buffering"))
    args.virtio_flags |= VIRTIO_FLAG_BUFFERING;
  if (cli_flag (ctx, "packed"))
    args.virtio_flags |= VIRTIO_FLAG_PACKED;
  if (cli_flag (ctx, "consistent-qp"))
    args.virtio_flags |= VIRTIO_FLAG_CONSISTENT_QP;

  if (cli_flag (ctx, "force"))
    args.bind = VIRTIO_BIND_FORCE;
  else if (cli_flag (ctx, "bind"))
    args.bind = VIRTIO_BIND_DEFAULT;

  if ((v = cli_get (ctx, "if-name")))
    args.if_name = vec_dup (v->str);

  virtio_pci_create_if (vm, &args);

  vec_free (args.if_name);

  return args.error;
}

VLIB_CLI_COMMAND (virtio_pci_create_command, static) = {
  .path = "create interface virtio",
  .short_help = "Create a virtio PCI interface",
  .args = CLI_ARGS (
    CLI_VALUE ("pci-address", cli_type_virtio_pci_addr),
    CLI_OPT_KEYWORD ("if-name", cli_type_string, .help = "name of the interface"),
    CLI_OPT_KEYWORD ("feature-mask", cli_type_u64, .help = "features to negotiate, 0x..."),
    CLI_OPT_KEYWORD ("tx-queue-size", cli_type_u32), CLI_FLAG ("gso-enabled"),
    CLI_FLAG ("csum-enabled"), CLI_FLAG ("rss-enabled"), CLI_FLAG ("mac-filter-enabled"),
    CLI_GROUP ("buffering", "buffer packets when the TX queue is full",
	       CLI_OPT_KEYWORD ("size", cli_type_u32, .help = "number of buffers")),
    CLI_FLAG ("packed", .help = "use the packed virtqueue"),
    CLI_GROUP ("bind", "bind the device to the vfio-pci driver",
	       CLI_FLAG ("force", .help = "even if the interface is up in the kernel")),
    CLI_FLAG ("consistent-qp")),
  .handler = virtio_pci_create_command_fn,
};

static clib_error_t *
virtio_pci_cli_get_if (cli_ctx_t *ctx, virtio_if_t **vif)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vim = &virtio_main;
  vnet_hw_interface_t *hw;

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, cli_index (ctx, "interface"));
  if (hw == NULL || virtio_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not a virtio interface");

  *vif = pool_elt_at_index (vim->interfaces, hw->dev_instance);

  return 0;
}

static clib_error_t *
virtio_pci_delete_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  virtio_if_t *vif;
  clib_error_t *err = virtio_pci_cli_get_if (ctx, &vif);

  if (err)
    return err;

  if (virtio_pci_delete_if (vm, vif) < 0)
    return clib_error_return (0, "not a virtio pci interface");

  return 0;
}

VLIB_CLI_COMMAND (virtio_pci_delete_command, static) = {
  .path = "delete interface virtio",
  .short_help = "Delete a virtio PCI interface",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_sw_interface, .alt_keyword = "sw_if_index")),
  .handler = virtio_pci_delete_command_fn,
};

static clib_error_t *
virtio_pci_enable_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  virtio_if_t *vif;
  clib_error_t *err = virtio_pci_cli_get_if (ctx, &vif);

  if (err)
    return err;

  if (virtio_pci_enable_disable_offloads (vm, vif, cli_flag (ctx, "gso-enabled"),
					  cli_flag (ctx, "csum-offload-enabled"),
					  cli_flag (ctx, "offloads-disabled")) < 0)
    return clib_error_return (0, "not able to enable/disable offloads");

  return 0;
}

VLIB_CLI_COMMAND (virtio_pci_enable_command, static) = {
  .path = "set virtio pci",
  .short_help = "Set the offloads of a virtio PCI interface",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_sw_interface, .alt_keyword = "sw_if_index"),
		    CLI_FLAG ("gso-enabled"), CLI_FLAG ("csum-offload-enabled"),
		    CLI_FLAG ("offloads-disabled")),
  .handler = virtio_pci_enable_command_fn,
};

static clib_error_t *
show_virtio_pci_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  virtio_main_t *vim = &virtio_main;
  vnet_main_t *vnm = &vnet_main;
  virtio_if_t *vif;
  clib_error_t *error = 0;
  u32 *hw_if_indices = 0;
  cli_value_t *v;

  cli_foreach (v, ctx, "interface")
  {
    if (vnet_get_hw_interface (vnm, v->index)->dev_class_index != virtio_device_class.index)
      {
	error = clib_error_return (0, "not a virtio interface");
	goto done;
      }
    vec_add1 (hw_if_indices, v->index);
  }

  if (vec_len (hw_if_indices) == 0)
    {
      pool_foreach (vif, vim->interfaces)
	vec_add1 (hw_if_indices, vif->hw_if_index);
    }

  virtio_show (vm, hw_if_indices, cli_flag (ctx, "descriptors"));

done:
  vec_free (hw_if_indices);
  return error;
}

VLIB_CLI_COMMAND (show_virtio_pci_command, static) = {
  .path = "show virtio pci",
  .short_help = "Show virtio PCI interfaces",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_hw_interface,
			       .flags = CLI_F_OPTIONAL | CLI_F_REPEAT),
		    CLI_FLAG ("descriptors", .alias = "desc", .help = "show the descriptors")),
  .handler = show_virtio_pci_fn,
};

clib_error_t *
virtio_pci_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (virtio_pci_cli_init);
