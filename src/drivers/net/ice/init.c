/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/dev/bus/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <ice.h>

VLIB_REGISTER_LOG_CLASS (ice_log, static) = {
  .class_name = "ice",
  .subclass_name = "init",
};

#define _(f, n, s, d) { .name = #n, .desc = (d), .severity = VL_COUNTER_SEVERITY_##s },
static vlib_error_desc_t ice_rx_counters[] = { foreach_ice_rx_node_counter };
static vlib_error_desc_t ice_tx_counters[] = { foreach_ice_tx_node_counter };
#undef _

vnet_dev_node_t ice_rx_node = {
  .format_trace = format_ice_rx_trace,
  .error_counters = ice_rx_counters,
  .n_error_counters = ARRAY_LEN (ice_rx_counters),
};

vnet_dev_node_t ice_tx_node = {
  .format_trace = format_ice_tx_trace,
  .error_counters = ice_tx_counters,
  .n_error_counters = ARRAY_LEN (ice_tx_counters),
};

static const ice_config_t ice_configs[] = {
  [ICE_DEVICE_FAMILY_E810] = {
    .aqc_link_status_size = ICE_AQC_LINK_STATUS_V1_SIZE,
    .mac_tx_tmr_reg = ICE_E810_PRTMAC_TX_PS_QNT_LFC,
    .mac_fc_refresh_reg = ICE_E810_PRTMAC_TX_PS_RFSH_LFC,
  },
  [ICE_DEVICE_FAMILY_E830] = {
    .aqc_link_status_size = ICE_AQC_LINK_STATUS_V2_SIZE,
    .mac_tx_tmr_reg = ICE_E830_PRTMAC_CL01_PS_QNT,
    .mac_fc_refresh_reg = ICE_E830_PRTMAC_CL01_QNT_THR,
    .has_mdd_fifo = 1,
  },
  [ICE_DEVICE_FAMILY_E835] = {
    .aqc_link_status_size = ICE_AQC_LINK_STATUS_V2_SIZE,
    .mac_tx_tmr_reg = ICE_E830_PRTMAC_CL01_PS_QNT,
    .mac_fc_refresh_reg = ICE_E830_PRTMAC_CL01_QNT_THR,
    .has_mdd_fifo = 1,
  },
};

static const struct
{
  u16 id;
  ice_device_family_t family;
  const char *name;
} ice_devices[] = {
  { 0x1591, ICE_DEVICE_FAMILY_E810, "Intel E810-C backplane" },
  { 0x1592, ICE_DEVICE_FAMILY_E810, "Intel E810-C QSFP" },
  { 0x1593, ICE_DEVICE_FAMILY_E810, "Intel E810-C SFP" },
  { 0x1599, ICE_DEVICE_FAMILY_E810, "Intel E810-XXV backplane" },
  { 0x159a, ICE_DEVICE_FAMILY_E810, "Intel E810-XXV QSFP" },
  { 0x159b, ICE_DEVICE_FAMILY_E810, "Intel E810-XXV SFP" },
  { 0x1248, ICE_DEVICE_FAMILY_E835, "Intel E835CC backplane" },
  { 0x1249, ICE_DEVICE_FAMILY_E835, "Intel E835CC QSFP56" },
  { 0x124a, ICE_DEVICE_FAMILY_E835, "Intel E835CC SFP" },
  { 0x1261, ICE_DEVICE_FAMILY_E835, "Intel E835C backplane" },
  { 0x1262, ICE_DEVICE_FAMILY_E835, "Intel E835C QSFP" },
  { 0x1263, ICE_DEVICE_FAMILY_E835, "Intel E835C SFP" },
  { 0x1265, ICE_DEVICE_FAMILY_E835, "Intel E835-L backplane" },
  { 0x1266, ICE_DEVICE_FAMILY_E835, "Intel E835-L QSFP" },
  { 0x1267, ICE_DEVICE_FAMILY_E835, "Intel E835-L SFP" },
  { 0x12d1, ICE_DEVICE_FAMILY_E830, "Intel E830-CC backplane" },
  { 0x12d2, ICE_DEVICE_FAMILY_E830, "Intel E830-CC QSFP56" },
  { 0x12d3, ICE_DEVICE_FAMILY_E830, "Intel E830-CC SFP" },
  { 0x12d5, ICE_DEVICE_FAMILY_E830, "Intel E830-C backplane" },
  { 0x12d8, ICE_DEVICE_FAMILY_E830, "Intel E830-C QSFP" },
  { 0x12da, ICE_DEVICE_FAMILY_E830, "Intel E830-C SFP" },
  { 0x12dc, ICE_DEVICE_FAMILY_E830, "Intel E830-L backplane" },
  { 0x12dd, ICE_DEVICE_FAMILY_E830, "Intel E830-L QSFP" },
  { 0x12de, ICE_DEVICE_FAMILY_E830, "Intel E830-L SFP" },
};

static u8 *
ice_probe (vlib_main_t *vm __clib_unused, vnet_dev_probe_args_t *a)
{
  vnet_dev_bus_pci_device_info_t *di = a->device_info;

  if (di->vendor_id != 0x8086)
    return 0;

  FOREACH_ARRAY_ELT (d, ice_devices)
    if (d->id == di->device_id)
      return format (0, "%s", d->name);

  return 0;
}

static u8
ice_global_reset_done (vnet_dev_t *dev)
{
  const ice_reg_glnvm_uld_t mask = {
    .pcier_done = 1,
    .pcier_done_1 = 1,
    .corer_done = 1,
    .globr_done = 1,
    .por_done = 1,
    .por_done_1 = 1,
    .pcier_done_2 = 1,
  };
  ice_reg_glgen_rstat_t r = {
    .as_u32 = ice_reg_read (dev, ICE_GLGEN_RSTAT),
  };
  ice_reg_glnvm_uld_t uld = {
    .as_u32 = ice_reg_read (dev, ICE_GLNVM_ULD),
  };

  return r.devstate == ICE_DEVICE_STATE_ACTIVE && (uld.as_u32 & mask.as_u32) == mask.as_u32;
}

static vnet_dev_rv_t
ice_wait_global_reset (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_reg_glgen_rstctl_t rstctl = {
    .as_u32 = ice_reg_read (dev, ICE_GLGEN_RSTCTL),
  };
  f64 start = vlib_time_now (vm);
  f64 active_timeout =
    (rstctl.global_reset_delay + ICE_RESET_DELAY_BIAS) * ICE_RESET_DELAY_UNIT_SECONDS;

  while (vlib_time_now (vm) - start < active_timeout)
    {
      ice_reg_glgen_rstat_t rstat = {
	.as_u32 = ice_reg_read (dev, ICE_GLGEN_RSTAT),
      };

      if (rstat.devstate == ICE_DEVICE_STATE_ACTIVE)
	break;

      vlib_process_suspend (vm, 0.1);
    }

  ice_reg_glgen_rstat_t rstat = {
    .as_u32 = ice_reg_read (dev, ICE_GLGEN_RSTAT),
  };

  if (rstat.devstate != ICE_DEVICE_STATE_ACTIVE)
    {
      log_err (dev, "global reset timeout, GLGEN_RSTAT 0x%08x", rstat.as_u32);
      return VNET_DEV_ERR_TIMEOUT;
    }

  start = vlib_time_now (vm);

  while (vlib_time_now (vm) - start < 20.0)
    {
      if (ice_global_reset_done (dev))
	{
	  log_debug (dev, "global reset processes complete");
	  return VNET_DEV_OK;
	}

      vlib_process_suspend (vm, 1e-2);
    }

  log_err (dev, "global reset processes timeout, GLNVM_ULD 0x%08x",
	   ice_reg_read (dev, ICE_GLNVM_ULD));
  return VNET_DEV_ERR_TIMEOUT;
}

static vnet_dev_rv_t
ice_wait_pf_reset (vlib_main_t *vm, vnet_dev_t *dev)
{
  f64 start = vlib_time_now (vm);

  while (vlib_time_now (vm) - start < 5.0)
    {
      ice_reg_pfgen_ctrl_t ctrl = {
	.as_u32 = ice_reg_read (dev, ICE_PFGEN_CTRL),
      };

      if (!ctrl.pf_sw_reset)
	{
	  log_debug (dev, "PF software reset completed");
	  return VNET_DEV_OK;
	}

      vlib_process_suspend (vm, 1e-3);
    }

  log_err (dev, "PF software reset timeout, PFGEN_CTRL 0x%08x", ice_reg_read (dev, ICE_PFGEN_CTRL));
  return VNET_DEV_ERR_TIMEOUT;
}

static vnet_dev_rv_t
ice_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_port_t port_data = {};
  ice_dev_info_t info = {};
  vlib_pci_config_hdr_t hdr;
  ice_reg_pf_func_rid_t rid;
  ice_reg_rxq_alloc_t rx_alloc;
  ice_reg_txq_alloc_t tx_alloc;
  vnet_dev_rv_t rv;
  u32 max_frame_size = 0, speed_caps;
  u16 rxq_count;
  u16 txq_count;
  u32 data_size = vlib_buffer_get_default_data_size (vm);
  u8 default_mac[6] = {};

  rv = vnet_dev_pci_read_config_header (vm, dev, &hdr);
  if (rv)
    {
      log_err (dev, "PCI configuration read failed: %U", format_vnet_dev_rv, rv);
      return rv;
    }

  if (hdr.vendor_id != 0x8086)
    {
      log_err (dev, "unsupported PCI vendor 0x%04x device 0x%04x", hdr.vendor_id, hdr.device_id);
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
    }

  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  FOREACH_ARRAY_ELT (d, ice_devices)
    if (d->id == hdr.device_id)
      {
	id->family = d->family;
	id->config = ice_configs[d->family];
	rv = VNET_DEV_OK;
	break;
      }

  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "unsupported Intel PCI device 0x%04x", hdr.device_id);
      return rv;
    }

  log_debug (dev, "PCI device 8086:%04x family %U", hdr.device_id, format_ice_family, id->family);

  rv = vnet_dev_pci_map_region (vm, dev, 0, &id->bar0);
  if (rv)
    {
      log_err (dev, "BAR0 mapping failed: %U", format_vnet_dev_rv, rv);
      return rv;
    }

  log_debug (dev, "mapped BAR0 at %p", id->bar0);

  rv = vnet_dev_pci_bus_master_enable (vm, dev);
  if (rv)
    {
      log_err (dev, "PCI bus-master enable failed: %U", format_vnet_dev_rv, rv);
      return rv;
    }

  log_debug (dev, "PCI bus mastering enabled");
  log_debug (dev, "hw initialization: reset-state 0x%08x NVM-load-state 0x%08x",
	     ice_reg_read (dev, ICE_GLGEN_RSTAT), ice_reg_read (dev, ICE_GLNVM_ULD));

  if (!ice_global_reset_done (dev))
    {
      log_debug (dev, "global reset in progress");

      rv = ice_wait_global_reset (vm, dev);
      if (rv)
	return rv;
    }
  else
    {
      ice_reg_pfgen_ctrl_t ctrl = {
	.as_u32 = ice_reg_read (dev, ICE_PFGEN_CTRL),
      };
      log_debug (dev, "requesting PF software reset");
      ctrl.pf_sw_reset = 1;
      ice_reg_write (dev, ICE_PFGEN_CTRL, ctrl.as_u32);
      ice_reg_flush (dev);

      rv = ice_wait_pf_reset (vm, dev);
      if (rv)
	return rv;
    }

  rv = ice_aq_start (vm, dev);
  if (rv)
    return rv;

  rid.as_u32 = ice_reg_read (dev, ICE_PF_FUNC_RID);
  id->pf_id = rid.function_number;
  rx_alloc.as_u32 = ice_reg_read (dev, ICE_PFLAN_RX_QALLOC);
  tx_alloc.as_u32 = ice_reg_read (dev, ICE_PFLAN_TX_QALLOC + id->pf_id * sizeof (u32));

  if (!rx_alloc.valid || !tx_alloc.valid || rx_alloc.last_queue < rx_alloc.first_queue ||
      tx_alloc.last_queue < tx_alloc.first_queue)
    {
      log_err (dev, "PF %u invalid queue allocation: RX 0x%08x TX 0x%08x", id->pf_id,
	       rx_alloc.as_u32, tx_alloc.as_u32);
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  rxq_count = rx_alloc.last_queue - rx_alloc.first_queue + 1;
  txq_count = tx_alloc.last_queue - tx_alloc.first_queue + 1;
  log_debug (dev, "PF %u queue allocation: RX %u-%u (%u), TX %u-%u (%u)", id->pf_id,
	     rx_alloc.first_queue, rx_alloc.last_queue, rxq_count, tx_alloc.first_queue,
	     tx_alloc.last_queue, txq_count);

  rv = ice_aq_configure (vm, dev, &port_data, rxq_count, default_mac);
  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "PF %u hardware configuration failed: %U", id->pf_id, format_vnet_dev_rv, rv);
      ice_aq_stop (vm, dev, &port_data);
      vec_free (port_data.vsi.sw_rules);
      return rv;
    }

  rv = ice_aq_get_dev_info (vm, dev, &info);

  if (rv == VNET_DEV_OK)
    {
      for (u32 i = 0; i < vec_len (info.dev_caps); i++)
	if (info.dev_caps[i].cap == ICE_AQC_CAPS_MAX_MTU)
	  max_frame_size = info.dev_caps[i].number;
    }

  if (rv == VNET_DEV_OK)
    for (u32 i = 0; i < vec_len (info.pkg_info); i++)
      if (info.pkg_info[i].is_active && !info.pkg_info[i].is_in_nvm)
	{
	  rv = ice_aq_use_active_ddp (vm, dev);
	  break;
	}

  vec_free (info.dev_caps);
  vec_free (info.pkg_info);

  if (rv == VNET_DEV_OK)
    rv = ice_aq_get_speed_caps (vm, dev, port_data.lport, &speed_caps);

  if (rv != VNET_DEV_OK || max_frame_size == 0)
    {
      if (rv == VNET_DEV_OK)
	{
	  log_err (dev, "maximum frame size capability not found");
	  rv = VNET_DEV_ERR_DEVICE_NO_REPLY;
	}

      ice_aq_stop (vm, dev, &port_data);
      vec_free (port_data.vsi.sw_rules);
      return rv;
    }

  log_debug (dev,
	     "hw capabilities: max frame %u rxqs %u txqs %u "
	     "MSI-X vecs %u default MAC %U",
	     max_frame_size, rxq_count, txq_count, vnet_dev_get_pci_n_msix_interrupts (dev),
	     format_ethernet_address, default_mac);
  max_frame_size = clib_min (max_frame_size, ICE_RX_DESC_MAX_CHAIN_LENGTH * data_size);

  vnet_dev_port_add_args_t args = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
	.max_rx_queues = clib_min (rxq_count, ICE_RSS_MAX_QUEUES),
	.max_tx_queues = txq_count,
	.max_supported_rx_frame_size = max_frame_size,
	.speed_caps = speed_caps,
	.caps = {
	  .rss = 1,
	  .interrupt_mode = 1,
	  .change_max_rx_frame_size = 1,
	},
	.rx_offloads = {
	  .ip4_cksum = 1,
	},
	.tx_offloads = {
	  .ip4_cksum = 1,
	  .tcp_cksum = 1,
	  .udp_cksum = 1,
	  .tcp_gso = data_size * ICE_TX_DESC_MAX_GSO_CHAIN_LENGTH >= CLIB_U16_MAX,
	  .udp_gso = data_size * ICE_TX_DESC_MAX_GSO_CHAIN_LENGTH >= CLIB_U16_MAX,
	},
      },
      .ops = {
        .init = ice_port_init,
        .deinit = ice_port_deinit,
        .start = ice_port_start,
        .stop = ice_port_stop,
        .format_status = format_ice_port_status,
        .config_change = ice_port_cfg_change,
        .config_change_validate = ice_port_cfg_change_validate,
        .get_module_eeprom = ice_port_get_module_eeprom,
      },
      .data_size = sizeof (ice_port_t),
      .initial_data = &port_data,
      .default_rss_config = {
	.key = {
	  0x94, 0xff, 0xfe, 0x8c, 0x39, 0xdf, 0x01, 0xb6, 0x9e, 0x88,
	  0x5f, 0xf2, 0x9c, 0x78, 0x71, 0xe0, 0xfc, 0x1b, 0x94, 0xd1,
	  0xb9, 0x41, 0x06, 0x96, 0x4e, 0x5b, 0x23, 0xdf, 0x26, 0x23,
	  0x0f, 0xcd, 0x32, 0x49, 0x0c, 0xa3, 0xd9, 0xa7, 0x70, 0x97,
	},
	.key_len = ICE_RSS_KEY_SIZE,
	.set_key = 1,
      },
    },
    .rx_node = &ice_rx_node,
    .tx_node = &ice_tx_node,
    .rx_queue = {
      .config = {
        .data_size = sizeof (ice_rxq_t),
        .default_size = 512,
        .size_is_power_of_two = 1,
        .min_size = VLIB_FRAME_SIZE,
        .max_size = 4096,
      },
      .ops = {
	.alloc = ice_rx_queue_alloc,
	.free = ice_rx_queue_free,
	.format_info = format_ice_rx_queue_info,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (ice_txq_t),
        .default_size = 512,
        .size_is_power_of_two = 1,
        .min_size = VLIB_FRAME_SIZE,
        .max_size = 4096,
      },
      .ops = {
	.alloc = ice_tx_queue_alloc,
	.free = ice_tx_queue_free,
	.format_info = format_ice_tx_queue_info,
      },
    },
  };

  clib_memcpy (args.port.attr.hw_addr.eth_mac, default_mac, 6);

  if (vlib_get_n_threads () <= vnet_dev_get_pci_n_msix_interrupts (dev) - 1)
    port_data.n_rx_vectors = vlib_get_n_threads ();
  else
    {
      log_notice (dev,
		  "number of threads (%u) exceeds number of available interrupt vectors (%u), "
		  "RX interrupt-mode capability disabled",
		  vlib_get_n_threads (), vnet_dev_get_pci_n_msix_interrupts (dev));
      args.port.attr.caps.interrupt_mode = 0;
      port_data.n_rx_vectors = 1;
    }

  log_debug (dev, "adding Ethernet port 0 with max frame %u and up to %u RX and %u txqs",
	     max_frame_size, rxq_count, txq_count);

  rv = vnet_dev_port_add (vm, dev, 0, &args);
  if (rv)
    {
      log_err (dev, "Ethernet port registration failed: %U", format_vnet_dev_rv, rv);
      return rv;
    }

  rv = ice_aq_events_start (vm, dev);

  if (rv != VNET_DEV_OK)
    log_err (dev, "AdminQ event initialization failed: %U", format_vnet_dev_rv, rv);
  else
    log_debug (dev, "device initialized: PF %u lport %u VSI %u max frame %u RX vecs %u", id->pf_id,
	       port_data.lport, port_data.vsi.num, max_frame_size, port_data.n_rx_vectors);

  return rv;
}

static void
ice_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);
  ice_port_t *ip = port ? vnet_dev_get_port_data (port) : 0;

  log_debug (dev, "deinitializing device");

  if (ip)
    ice_rss_free (vm, port);

  if (id->bar0)
    ice_aq_stop (vm, dev, ip);

  if (ip)
    {
      if (ip->rss)
	ice_rss_profiles_dispose (port);

      vec_free (ip->counter_values);
      vec_free (ip->vsi.sw_rules);
    }

  log_debug (dev, "device deinitialized");
}

VNET_DEV_REGISTER_DRIVER (ice) = {
  .name = "ice",
  .description = "Intel E810, E830 and E835 Ethernet controllers",
  .bus = "pci",
  .device = {
    .data_sz = sizeof (ice_dev_t),
    .ops = {
      .alloc = ice_aq_alloc,
      .init = ice_init,
      .deinit = ice_deinit,
      .free = ice_aq_free,
      .probe = ice_probe,
      .format_info = format_ice_dev_info,
    },
  },
};
