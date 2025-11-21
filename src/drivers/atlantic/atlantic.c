/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/pci.h>
#include <atlantic.h>
#include <vnet/ethernet/ethernet.h>

#define _(f, n, s, d) { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },
static vlib_error_desc_t atl_rx_node_counters[] = { foreach_atl_rx_node_counter };
static vlib_error_desc_t atl_tx_node_counters[] = { foreach_atl_tx_node_counter };
#undef _

VLIB_REGISTER_LOG_CLASS (atl_log, static) = {
  .class_name = "atlantic",
};

static const u8 atl_default_rss_key[40] = {
  0x1e, 0xad, 0x71, 0x87, 0x65, 0xfc, 0x26, 0x7d, 0x0d, 0x45, 0x67, 0x74, 0xcd, 0x06,
  0x1a, 0x18, 0xb6, 0xc1, 0xf0, 0xc7, 0xbb, 0x18, 0xbe, 0xf8, 0x19, 0x13, 0x4b, 0xa9,
  0xd0, 0x3e, 0xfe, 0x70, 0x25, 0x03, 0xab, 0x50, 0x6a, 0x8b, 0x82, 0x0c,
};

static const struct
{
  u16 device_id;
  char *description;
} atl_dev_types[] = {
  { 0x00c0, "Marvell Scalable mGig AQC113DEV" }, { 0x04c0, "Marvell Scalable mGig AQC113" },
  { 0x94c0, "Marvell Scalable mGig AQC113CS" },	 { 0x93c0, "Marvell Scalable mGig AQC114CS" },
  { 0x14c0, "Marvell Scalable mGig AQC113C" },	 { 0x12c0, "Marvell Scalable mGig AQC115C" },
  { 0x34c0, "Marvell Scalable mGig AQC113CA" },	 { 0x11c0, "Marvell Scalable mGig AQC116C" },
};

vnet_dev_node_t atl_rx_node = {
  .format_trace = atl_rx_trace,
  .error_counters = atl_rx_node_counters,
  .n_error_counters = ARRAY_LEN (atl_rx_node_counters),
};

vnet_dev_node_t atl_tx_node = {
  .format_trace = atl_tx_trace,
  .error_counters = atl_tx_node_counters,
  .n_error_counters = ARRAY_LEN (atl_tx_node_counters),
};

static u8 *
atl_probe (vlib_main_t *vm __clib_unused, vnet_dev_probe_args_t *pa)
{
  vnet_dev_bus_pci_device_info_t *di = pa->device_info;

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
  atl_reg_aq2_mif_boot_t boot;
  atl_reg_aq2_mcp_host_req_int_t host_req;
  char *err_str = 0;
  f64 t0;

  atl_reg_wr_u32 (dev, ATL_REG_AQ2_MCP_HOST_REQ_INT_CLR, 1);
  atl_reg_wr_u32 (dev, ATL_REG_AQ2_MIF_BOOT, 1);

  t0 = vlib_time_now (vm);
  while (vlib_time_now (vm) < t0 + 2.0)
    {
      boot.as_u32 = atl_reg_rd_u32 (dev, ATL_REG_AQ2_MIF_BOOT);
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
      boot.as_u32 = atl_reg_rd_u32 (dev, ATL_REG_AQ2_MIF_BOOT);
      if (boot.fw_init_failed || boot.fw_init_comp_success)
	goto restart_check;
      host_req.as_u32 = atl_reg_rd_u32 (dev, ATL_REG_AQ2_MCP_HOST_REQ_INT);
      if (host_req.ready)
	goto restart_check;
      vlib_process_suspend (vm, 1e-1);
    }

  log_err (dev, "FW restart timeout");
  return VNET_DEV_ERR_TIMEOUT;

restart_check:
  boot.as_u32 = atl_reg_rd_u32 (dev, ATL_REG_AQ2_MIF_BOOT);
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
atl_read_mac (vnet_dev_t *dev, u8 mac[6])
{
  u32 mac_addr[2];

  mac_addr[0] = atl_reg_rd_u32 (dev, ATL_REG_AQ2_FW_INTERFACE_IN_MAC_ADDRESS);
  mac_addr[1] = atl_reg_rd_u32 (dev, ATL_REG_AQ2_FW_INTERFACE_IN_MAC_ADDRESS + 4);

  if (mac_addr[0] == 0 && mac_addr[1] == 0)
    return VNET_DEV_ERR_DEVICE_NO_REPLY;

  clib_memcpy (mac, mac_addr, 6);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
atl_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  atl_device_t *ad = vnet_dev_get_data (dev);
  vlib_pci_config_hdr_t pci_hdr;
  atl_iface_ver_t iface_ver;
  vnet_dev_rv_t rv;
  u32 ver_data[3];

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

  rv = vnet_dev_pci_bus_master_enable (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_VERSION_BUNDLE,
				      &ad->fw_version.as_u32, 1);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = atl_read_mac (dev, ad->mac);
  if (rv != VNET_DEV_OK)
    return rv;

  log_info (dev, "MAC %U", format_ethernet_address, ad->mac);

  atl_reg_glb_mif_id_t hwrev = { .as_u32 = atl_reg_rd_u32 (dev, ATL_REG_HW_REVISION) };
  log_info (dev, "HW rev 0x%08x (mif_id 0x%x)", hwrev.as_u32, hwrev.mif_id);

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_VERSION_MAC, ver_data, 3);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_FILTER_CAPS,
				      ad->caps.as_u32, ARRAY_LEN (ad->caps.as_u32));
  if (rv != VNET_DEV_OK)
    return rv;

  iface_ver.as_u32 = ver_data[2];

  if (iface_ver.iface_ver != 1)
    {
      log_err (dev, "unsupported FW interface version %u", iface_ver.iface_ver);
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
    }

  log_info (dev, "FW version: %U (bundle) %U (mac) %U (phy) %U (iface)", format_atl_fw_version,
	    ad->fw_version.as_u32, format_atl_fw_version, ver_data[0], format_atl_fw_version,
	    ver_data[1], format_atl_iface_version, iface_ver.as_u32);

  log_info (dev,
	    "FW filter caps 0x%08x 0x%08x 0x%08x\n"
	    "  l2 base %u count %u\n"
	    "  ethertype base %u count %u\n"
	    "  vlan base %u count %u\n"
	    "  l3_ip4 base %u count %u\n"
	    "  l3_ip6 base %u count %u\n"
	    "  l4 base %u count %u\n"
	    "  l4_flex base %u count %u\n"
	    "  resolver base %u count %u",
	    ad->caps.as_u32[0], ad->caps.as_u32[1], ad->caps.as_u32[2], ad->caps.l2_base_index,
	    ad->caps.l2_count, ad->caps.ethertype_base_index, ad->caps.ethertype_count,
	    ad->caps.vlan_base_index, ad->caps.vlan_count, ad->caps.l3_ip4_base_index,
	    ad->caps.l3_ip4_count, ad->caps.l3_ip6_base_index, ad->caps.l3_ip6_count,
	    ad->caps.l4_base_index, ad->caps.l4_count, ad->caps.l4_flex_base_index,
	    ad->caps.l4_flex_count, ad->caps.resolver_base_index, ad->caps.resolver_count);

  vnet_dev_port_add_args_t port = {
    .port = {
      .attr = {
	.type = VNET_DEV_PORT_TYPE_ETHERNET,
	.max_rx_queues = 4,
	.max_tx_queues = 4,
	.max_supported_rx_frame_size = 16352,
	.caps = {
	  .rss = 1,
	},
      },
      .ops = {
	.init = atl_port_init,
	.start = atl_port_start,
	.stop = atl_port_stop,
	.format_status = format_atl_port_status,
	.config_change = atl_port_cfg_change,
	.config_change_validate = atl_port_cfg_change_validate,
      },
      .data_size = sizeof (atl_port_t),
      .default_rss_key = {
	.length = sizeof (atl_default_rss_key),
      },
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
  clib_memcpy (port.port.default_rss_key.key, atl_default_rss_key, sizeof (atl_default_rss_key));

  ad->avail_rxq_bmp = pow2_mask (port.port.attr.max_rx_queues);
  ad->avail_txq_bmp = pow2_mask (port.port.attr.max_tx_queues);

  return vnet_dev_port_add (vm, dev, 0, &port);
}

VNET_DEV_REGISTER_DRIVER (atl) = {
  .name = "atlantic",
  .bus = "pci",
  .device = {
    .data_sz = sizeof (atl_device_t),
    .ops = {
      .init = atl_init,
      .probe = atl_probe,
      .format_info = format_atl_dev_info,
    },
  },
};
