/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/pci.h>
#include <dev_atlantic/atlantic.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#define _(f, n, s, d)                                                         \
  { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },
static vlib_error_desc_t atl_tx_node_counters[] = {
  foreach_atl_tx_node_counter
};
#undef _

VLIB_REGISTER_LOG_CLASS (atl_log, static) = {
  .class_name = "atlantic",
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, atl_log.class, "%U" f, format_vnet_dev_log, \
	    (dev), clib_string_skip_prefix (__func__, "atl_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_INFO, atl_log.class, "%U: " f,                     \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, atl_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, atl_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, atl_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)

static const struct
{
  u16 device_id;
  char *description;
} atl_dev_types[] = {
  { 0x04c0, "Marvell Scalable mGig AQC113" },
  { 0x00c0, "Marvell Scalable mGig AQC114" },
  { 0x93c0, "Marvell Scalable mGig AQC114CS" },
};

vnet_dev_node_t atl_rx_node = {
  .format_trace = atl_rx_trace,
};

vnet_dev_node_t atl_tx_node = {
  .format_trace = atl_tx_trace,
  .error_counters = atl_tx_node_counters,
  .n_error_counters = ARRAY_LEN (atl_tx_node_counters),
};

static u8 *
atl_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;

  if (di->vendor_id != PCI_VENDOR_ID_AQUANTIA)
    return 0;

  for (int i = 0; i < ARRAY_LEN (atl_dev_types); i++)
    {
      if (atl_dev_types[i].device_id == di->device_id)
	return format (0, "%s", atl_dev_types[i].description);
    }

  return 0;
}

static int
atl_fw_softreset (vnet_dev_t *dev)
{
  vlib_main_t *vm = vlib_get_main ();
  atl_aq2_mif_boot_reg boot;
  atl_aq2_mcp_host_req_int_reg host_req;
  char *err_str = 0;
  f64 t0;

  atl_reg_wr (dev, AQ2_MCP_HOST_REQ_INT_CLR_REG, 1);
  atl_reg_wr (dev, AQ2_MIF_BOOT_REG, 1); /* reboot request */

  t0 = vlib_time_now (vm);
  while (vlib_time_now (vm) < t0 + 2.0)
    {
      boot.as_u32 = atl_reg_rd (dev, AQ2_MIF_BOOT_REG);
      if (boot.boot_started && boot.as_u32 != 0xffffffff)
	goto boot_started;
      vlib_process_suspend (vm, 1e-1);
    }

  log_err (dev, "FW reboot timeout");
  return VNET_DEV_ERR_TIMEOUT;

boot_started:
  t0 = vlib_time_now (vm);
  while (vlib_time_now (vm) < t0 + 20.0)
    {
      boot.as_u32 = atl_reg_rd (dev, AQ2_MIF_BOOT_REG);
      if (boot.fw_init_failed || boot.fw_init_comp_success)
	goto restart_check;
      host_req.as_u32 = atl_reg_rd (dev, AQ2_MCP_HOST_REQ_INT_REG);
      if (host_req.ready)
	goto restart_check;
      vlib_process_suspend (vm, 1e-1);
    }

  log_err (dev, "FW restart timeout");
  return VNET_DEV_ERR_TIMEOUT;

restart_check:
  boot.as_u32 = atl_reg_rd (dev, AQ2_MIF_BOOT_REG);
  if (boot.fw_init_failed)
    err_str = "FW restart failed";
  else if (boot.boot_code_failed)
    err_str = "FW boot code failed";
  else if (boot.crash_init)
    err_str = "FW crash init";

  if (err_str)
    {
      log_err (dev, "%s", err_str);
      return VNET_DEV_ERR_DEVICE_NO_REPLY;
    }

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
atl_aq2_interface_buffer_read (vnet_dev_t *dev, u32 reg0, u32 *data0,
			       u32 size0)
{
  vlib_main_t *vm = vlib_get_main ();
  atl_aq2_fw_interface_out_transaction_id_reg tid0, tid1;
  f64 t0;
  u32 reg, sz;
  u32 *data;

  t0 = vlib_time_now (vm);
  while (vlib_time_now (vm) < t0 + 0.1)
    {
      tid0.as_u32 = atl_reg_rd (dev, AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_REG);
      if (tid0.id_a != tid0.id_b)
	goto wait;

      for (reg = reg0, data = data0, sz = size0; sz >= 4;
	   reg += 4, data++, sz -= 4)
	*data = atl_reg_rd (dev, reg);

      tid1.as_u32 = atl_reg_rd (dev, AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_REG);
      if (tid0.as_u32 == tid1.as_u32)
	return VNET_DEV_OK;

    wait:
      vlib_process_suspend (vm, 1e-5);
    }

  log_err (dev, "interface buffer read timeout");
  return VNET_DEV_ERR_TIMEOUT;
}

static vnet_dev_rv_t
atl_read_mac (vnet_dev_t *dev, u8 mac[6])
{
  u32 mac_addr[2];

  mac_addr[0] = atl_reg_rd (dev, AQ2_FW_INTERFACE_IN_MAC_ADDRESS_REG);
  mac_addr[1] = atl_reg_rd (dev, AQ2_FW_INTERFACE_IN_MAC_ADDRESS_REG + 4);

  if (mac_addr[0] == 0 && mac_addr[1] == 0)
    return VNET_DEV_ERR_DEVICE_NO_REPLY;

  clib_memcpy (mac, mac_addr, 6);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
atl_aq2_read_fw_version (vnet_dev_t *dev)
{
  atl_device_t *ad = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  atl_fw_version_t bundle_reg;
  atl_aq2_fw_interface_out_version_iface_reg iface_reg;
  const char *iface;

  rv = atl_aq2_interface_buffer_read (
    dev, AQ2_FW_INTERFACE_OUT_VERSION_BUNDLE_REG, &bundle_reg.as_u32,
    sizeof (bundle_reg.as_u32));
  if (rv != VNET_DEV_OK)
    return rv;

  ad->fw_version = bundle_reg;

  rv = atl_aq2_interface_buffer_read (
    dev, AQ2_FW_INTERFACE_OUT_VERSION_IFACE_REG, &iface_reg.as_u32,
    sizeof (iface_reg.as_u32));

  if (rv != VNET_DEV_OK)
    return rv;

  switch (iface_reg.iface_ver)
    {
    case 0:
      iface = "A0";
      break;
    case 1:
      iface = "B0";
      break;
    default:
      iface = "unknown";
      break;
    }

  log_info (dev, "Atlantic2 %s, FW version %u.%u.%u", iface,
	    ad->fw_version.major, ad->fw_version.minor, ad->fw_version.build);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
atl_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  atl_device_t *ad = vnet_dev_get_data (dev);
  vlib_pci_config_hdr_t pci_hdr;
  vnet_dev_rv_t rv;
  u32 ver_mac, ver_phy, iface, filter_caps;

  rv = vnet_dev_pci_read_config_header (vm, dev, &pci_hdr);
  if (rv != VNET_DEV_OK)
    return rv;

  if (pci_hdr.vendor_id != PCI_VENDOR_ID_AQUANTIA)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  for (int i = 0; i < ARRAY_LEN (atl_dev_types); i++)
    if (atl_dev_types[i].device_id == pci_hdr.device_id)
      {
	rv = VNET_DEV_OK;
	break;
      }

  if (rv != VNET_DEV_OK)
    return rv;

  /* map BAR0 */
  if (ad->bar0 == 0)
    {
      rv = vnet_dev_pci_map_region (vm, dev, 0, &ad->bar0);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  if (atl_fw_softreset (dev))
    return VNET_DEV_ERR_INIT_FAILED;

  rv = atl_aq2_read_fw_version (dev);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = atl_read_mac (dev, ad->mac);
  if (rv != VNET_DEV_OK)
    return rv;

  log_notice (dev, "MAC %U", format_ethernet_address, ad->mac);

  u32 hwrev = atl_reg_rd (dev, AQ_HW_REVISION_REG);
  log_notice (dev, "HW rev 0x%08x (rev_id 0x%x)", hwrev, hwrev & 0x0f);

  ver_mac = atl_reg_rd (dev, AQ2_FW_INTERFACE_OUT_VERSION_MAC_REG);
  ver_phy = atl_reg_rd (dev, AQ2_FW_INTERFACE_OUT_VERSION_PHY_REG);
  iface = atl_reg_rd (dev, AQ2_FW_INTERFACE_OUT_VERSION_IFACE_REG);
  filter_caps = atl_reg_rd (dev, AQ2_FW_INTERFACE_OUT_FILTER_CAPS_REG);

  atl_fw_version_t mac_ver = { .as_u32 = ver_mac };
  atl_fw_version_t phy_ver = { .as_u32 = ver_phy };
  const char *iface_str = "unknown";
  switch (iface & 0xf)
    {
    case 0:
      iface_str = "A0";
      break;
    case 1:
      iface_str = "B0";
      break;
    }

  log_notice (dev, "FW iface versions: MAC %u.%u.%u PHY %u.%u.%u IFACE %s",
	      mac_ver.major, mac_ver.minor, mac_ver.build, phy_ver.major,
	      phy_ver.minor, phy_ver.build, iface_str);

  u32 resolver_base =
    ((filter_caps & AQ2_FW_INTERFACE_OUT_FILTER_CAPS3_RESOLVER_BASE_INDEX) >>
     AQ2_FW_INTERFACE_OUT_FILTER_CAPS3_RESOLVER_BASE_INDEX_SHIFT) *
    8;
  log_notice (dev, "FW filter caps 0x%08x resolver_base %u", filter_caps,
	      resolver_base);

  vnet_dev_port_add_args_t port = {
    .port = {
      .attr = {
	.type = VNET_DEV_PORT_TYPE_ETHERNET,
	.max_rx_queues = 4,
	.max_tx_queues = 4,
	.max_supported_rx_frame_size = 16352,
      },
      .ops = {
	.init = atl_port_init,
	.start = atl_port_start,
	.stop = atl_port_stop,
	.format_status = atl_port_format_status,
	.config_change = atl_port_cfg_change,
	.config_change_validate = atl_port_cfg_change_validate,
      },
      .data_size = sizeof (atl_port_t),
    },
    .rx_node = &atl_rx_node,
    .tx_node = &atl_tx_node,
    .rx_queue = {
      .config = {
	.data_size = sizeof (atl_rxq_t),
	.default_size = 512,
	.multiplier = 8,
	.min_size = 64,
	.max_size = 8184,
      },
      .ops = {
	.alloc = atl_rx_queue_alloc,
	.free = atl_rx_queue_free,
      },
    },
    .tx_queue = {
      .config = {
	.data_size = sizeof (atl_txq_t),
	.default_size = 512,
	.multiplier = 8,
	.min_size = 64,
	.max_size = 8184,
      },
      .ops = {
	.alloc = atl_tx_queue_alloc,
	.free = atl_tx_queue_free,
      },
    },
  };

  clib_memcpy (port.port.attr.hw_addr.eth_mac, ad->mac, 6);

  ad->avail_rxq_bmp = pow2_mask (port.port.attr.max_rx_queues);
  ad->avail_txq_bmp = pow2_mask (port.port.attr.max_tx_queues);

  return vnet_dev_port_add (vm, dev, 0, &port);
}

VNET_DEV_REGISTER_DRIVER (atl) = {
  .name = "atlantic",
  .bus = "pci",
  .device_data_sz = sizeof (atl_device_t),
  .ops = {
    .init = atl_init,
    .probe = atl_probe,
  },
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_atlantic",
};
