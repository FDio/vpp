/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dev_cnxk/cnxk.h>
//#include <dev_cnxk/bar.h>

#include <roc/base/roc_api.h>
struct roc_model cnxk_model;

VLIB_REGISTER_LOG_CLASS (cnxk_log, static) = {
  .class_name = "cnxk",
  .subclass_name = "init",
};

vnet_dev_node_t cnxk_rx_node = {};
vnet_dev_node_t cnxk_tx_node = {};

static struct
{
  u16 device_id;
  cnxk_device_type_t type;
  char *description;
} cnxk_dev_types[] = {

#define _(id, device_type, desc)                                              \
  {                                                                           \
    .device_id = (id), .type = CNXK_DEVICE_TYPE_##device_type,                \
    .description = (desc)                                                     \
  }

  _ (0xa063, RVU_PF, "Marvell CNXK Resource Virtualization Unit PF"),
  _ (0xa0f3, CPT_VF, "Marvell CNXK Cryptographic Accelerator Unit VF"),
#undef _
};

static u8 *
cnxk_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;

  if (di->vendor_id != 0x177d) /* Cavium */
    return 0;

  FOREACH_ARRAY_ELT (dt, cnxk_dev_types)
    {
      if (dt->device_id == di->device_id)
	return format (0, "%s", dt->description);
    }

  return 0;
}

vnet_dev_rv_t
cnx_return_roc_err (vnet_dev_t *dev, int rrv, char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  u8 *s = va_format (0, fmt, &va);
  va_end (va);

  log_err (dev, "%v: %s [%d]", s, roc_error_msg_get (rrv), rrv);
  vec_free (s);

  return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
}

static vnet_dev_rv_t
cnxk_alloc (vlib_main_t *vm, vnet_dev_t *dev)
{
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  cd->nix =
    clib_mem_alloc_aligned (sizeof (struct roc_nix), CLIB_CACHE_LINE_BYTES);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
cnxk_init_nix (vlib_main_t *vm, vnet_dev_t *dev)
{
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  u8 mac_addr[6];
  int rrv;
  cnxk_port_t cnxk_port = {};

  *cd->nix = (struct roc_nix){
    .reta_sz = ROC_NIX_RSS_RETA_SZ_256,
    .max_sqb_count = 512,
    .pci_dev = &cd->plt_pci_dev,
  };

  if ((rrv = roc_nix_dev_init (cd->nix)))
    return cnx_return_roc_err (dev, rrv, "roc_nix_dev_init");

  if (roc_nix_npc_mac_addr_get (cd->nix, mac_addr))
    return cnx_return_roc_err (dev, rrv, "roc_nix_npc_mac_addr_get");

  vnet_dev_port_add_args_t port_add_args = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
        .max_rx_queues = 64,
        .max_tx_queues = 64,
        .max_supported_frame_size = roc_nix_max_pkt_len (cd->nix),
      },
      .ops = {
        .init = cnxk_port_init,
        .start = cnxk_port_start,
        .stop = cnxk_port_stop,
        .config_change = cnxk_port_cfg_change,
        .format_status = format_cnxk_port_status,
      },
      .data_size = sizeof (cnxk_port_t),
      .initial_data = &cnxk_port,
    },
    .rx_node = &cnxk_rx_node,
    .tx_node = &cnxk_tx_node,
    .rx_queue = {
      .config = {
        .data_size = sizeof (cnxk_rxq_t),
        .default_size = 1024,
        .multiplier = 32,
        .min_size = 256,
        .max_size = 16384,
      },
      .ops = {
        .alloc = cnxk_rx_queue_alloc,
        .free = cnxk_rx_queue_free,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (cnxk_txq_t),
        .default_size = 1024,
        .multiplier = 32,
        .min_size = 256,
        .max_size = 16384,
      },
      .ops = {
        .alloc = cnxk_tx_queue_alloc,
        .free = cnxk_tx_queue_free,
      },
    },
  };

  vnet_dev_set_hw_addr_eth_mac (&port_add_args.port.attr.hw_addr, mac_addr);

  log_info (dev, "MAC address is %U", format_ethernet_address, mac_addr);

  return vnet_dev_port_add (vm, dev, 0, &port_add_args);
}

static vnet_dev_rv_t
cnxk_init_cpt (vlib_main_t *vm, vnet_dev_t *dev)
{
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  int rrv;
  struct roc_cpt cpt = {
    .pci_dev = &cd->plt_pci_dev,
  };

  if ((rrv = roc_cpt_dev_init (&cpt)))
    return cnx_return_roc_err (dev, rrv, "roc_cpt_dev_init");
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
cnxk_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  vlib_pci_config_hdr_t pci_hdr;
  vnet_dev_rv_t rv;

  rv = vnet_dev_pci_read_config_header (vm, dev, &pci_hdr);
  if (rv != VNET_DEV_OK)
    return rv;

  if (pci_hdr.vendor_id != 0x177d)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  FOREACH_ARRAY_ELT (dt, cnxk_dev_types)
    {
      if (dt->device_id == pci_hdr.device_id)
	cd->type = dt->type;
    }

  if (cd->type == CNXK_DEVICE_TYPE_UNKNOWN)
    return rv;

  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  cd->plt_pci_dev = (struct plt_pci_device){
    .id.vendor_id = pci_hdr.vendor_id,
    .id.device_id = pci_hdr.device_id,
    .id.class_id = pci_hdr.class << 16 | pci_hdr.subclass,
    .vnet_dev = dev,
  };

  foreach_int (i, 2, 4)
    {
      rv = vnet_dev_pci_map_region (vm, dev, i,
				    &cd->plt_pci_dev.mem_resource[i].addr);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  strncpy ((char *) cd->plt_pci_dev.name, dev->device_id,
	   sizeof (cd->plt_pci_dev.name) - 1);

  if (cd->type == CNXK_DEVICE_TYPE_RVU_PF)
    return cnxk_init_nix (vm, dev);
  else if (cd->type == CNXK_DEVICE_TYPE_CPT_VF)
    return cnxk_init_cpt (vm, dev);
  else
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  return 0;
}

static void
cnxk_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  cnxk_device_t *cd = vnet_dev_get_data (dev);

  if (cd->nix_initialized)
    roc_nix_dev_fini (cd->nix);
}

static void
cnxk_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  cnxk_device_t *cd = vnet_dev_get_data (dev);

  if (cd->nix_initialized)
    roc_nix_dev_fini (cd->nix);
}

VNET_DEV_REGISTER_DRIVER (cnxk) = {
  .name = "cnxk",
  .bus = "pci",
  .device_data_sz = sizeof (cnxk_device_t),
  .ops = {
    .alloc = cnxk_alloc,
    .init = cnxk_init,
    .deinit = cnxk_deinit,
    .free = cnxk_free,
    .probe = cnxk_probe,
  },
};

static clib_error_t *
cnxk_plugin_init (vlib_main_t *vm)
{
  int rv;
  rv = roc_model_init (&cnxk_model);
  if (rv)
    clib_error_return (0, "roc_model_init failed");
  __builtin_dump_struct (&cnxk_model, &printf);
  return 0;
}

VLIB_INIT_FUNCTION (cnxk_plugin_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_cnxk",
};
