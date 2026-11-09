/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023-2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/ethernet/ethernet.h>
#include <octeon.h>

oct_main_t oct_main;

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "net-init",
};

#define OCT_BATCH_ALLOC_FINI_WAIT_US (100 * 1000)

#define _(f, n, s, d)                                                         \
  { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },

vlib_error_desc_t oct_rx_node_counters[] = { foreach_oct_rx_node_counter };
vlib_error_desc_t oct_tx_node_counters[] = { foreach_oct_tx_node_counter };
#undef _

vnet_dev_node_t oct_rx_node = {
  .format_trace = format_oct_rx_trace,
  .error_counters = oct_rx_node_counters,
  .n_error_counters = ARRAY_LEN (oct_rx_node_counters),
};

vnet_dev_node_t oct_tx_node = {
  .format_trace = format_oct_tx_trace,
  .error_counters = oct_tx_node_counters,
  .n_error_counters = ARRAY_LEN (oct_tx_node_counters),
};

vnet_dev_node_t oct_tx_tm_node = {
  .format_trace = format_oct_tx_trace,
  .error_counters = oct_tx_node_counters,
  .n_error_counters = ARRAY_LEN (oct_tx_node_counters),
};

static clib_arg_t oct_drv_args[] = {
  {
    .name = "npa_max_pools",
    .desc = "Max NPA pools",
    .type = CLIB_ARG_TYPE_UINT32,
    .default_val.uint32 = 128,
  },
  {
    .name = "end",
    .desc = "Argument end",
    .type = CLIB_ARG_END,
  },
};

static clib_arg_t oct_port_args[] = {
  {
    .name = "eth_pause_frame",
    .desc = "Enable ethernet pause frame support",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = false,
  },
  {
    .name = "rss_flow_key",
    .desc = "RSS Flow Key Bitmap",
    .type = CLIB_ARG_TYPE_HEX32,
    .default_val.uint32 = FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 |
			  FLOW_KEY_TYPE_TCP | FLOW_KEY_TYPE_UDP |
			  FLOW_KEY_TYPE_SCTP,
  },
  {
    .name = "switch_header_type",
    .desc = "Type of header used by underlying switch (none, edsa, higig, "
	    "len_90b, exdsa, vlan_exdsa)",
    .type = CLIB_ARG_TYPE_ENUM,
    .enum_vals = CLIB_ARG_ENUM_VALS (
      { .val = ROC_PRIV_FLAGS_DEFAULT, .name = "none" },
      { .val = ROC_PRIV_FLAGS_EDSA, .name = "edsa" },
      { .val = ROC_PRIV_FLAGS_HIGIG, .name = "higig" },
      { .val = ROC_PRIV_FLAGS_LEN_90B, .name = "len_90b" },
      { .val = ROC_PRIV_FLAGS_EXDSA, .name = "exdsa" },
      { .val = ROC_PRIV_FLAGS_VLAN_EXDSA, .name = "vlan_exdsa" }, ),
    .default_val.enum_val = ROC_PRIV_FLAGS_DEFAULT,
  },
  {
    .type = CLIB_ARG_END,
  },
};

static clib_arg_t oct_port_args_rvu_vf[] = {
  {
    .name = "eth_pause_frame",
    .desc = "Enable ethernet pause frame support",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = false,
  },
  {
    .name = "rss_flow_key",
    .desc = "RSS Flow Key Bitmap",
    .type = CLIB_ARG_TYPE_HEX32,
    .default_val.uint32 = FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP |
			  FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_SCTP,
  },
  {
    .type = CLIB_ARG_END,
  },
};

static clib_arg_t oct_port_args_lbk_sdp[] = {
  {
    .name = "rss_flow_key",
    .desc = "RSS Flow Key Bitmap",
    .type = CLIB_ARG_TYPE_HEX32,
    .default_val.uint32 = FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP |
			  FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_SCTP,
  },
  {
    .type = CLIB_ARG_END,
  },
};

static clib_arg_t oct_dev_args[] = {
  {
    .name = "egress_tm",
    .desc = "Egress traffic manager enable (network devices only)",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = false,
  },
  {
    .name = "end",
    .desc = "Argument end",
    .type = CLIB_ARG_END,
  },
};

static const u32 oct_mac_modes[CGX_MODE_MAX + 1] = {
  [CGX_MODE_SGMII] = VNET_HW_IF_SPEED_1G,
  [CGX_MODE_1000_BASEX] = VNET_HW_IF_SPEED_1G,
  [CGX_MODE_QSGMII] = VNET_HW_IF_SPEED_1G,
  [CGX_MODE_10G_C2C] = VNET_HW_IF_SPEED_10G,
  [CGX_MODE_10G_C2M] = VNET_HW_IF_SPEED_10G,
  [CGX_MODE_10G_KR] = VNET_HW_IF_SPEED_10G,
  [CGX_MODE_20G_C2C] = VNET_HW_IF_SPEED_20G,
  [CGX_MODE_25G_C2C] = VNET_HW_IF_SPEED_25G,
  [CGX_MODE_25G_C2M] = VNET_HW_IF_SPEED_25G,
  [CGX_MODE_25G_2_C2C] = VNET_HW_IF_SPEED_25G,
  [CGX_MODE_25G_CR] = VNET_HW_IF_SPEED_25G,
  [CGX_MODE_25G_KR] = VNET_HW_IF_SPEED_25G,
  [CGX_MODE_40G_C2C] = VNET_HW_IF_SPEED_40G,
  [CGX_MODE_40G_C2M] = VNET_HW_IF_SPEED_40G,
  [CGX_MODE_40G_CR4] = VNET_HW_IF_SPEED_40G,
  [CGX_MODE_40G_KR4] = VNET_HW_IF_SPEED_40G,
  [CGX_MODE_40GAUI_C2C] = VNET_HW_IF_SPEED_40G,
  [CGX_MODE_50G_C2C] = VNET_HW_IF_SPEED_50G,
  [CGX_MODE_50G_C2M] = VNET_HW_IF_SPEED_50G,
  [CGX_MODE_50G_4_C2C] = VNET_HW_IF_SPEED_50G,
  [CGX_MODE_50G_CR] = VNET_HW_IF_SPEED_50G,
  [CGX_MODE_50G_KR] = VNET_HW_IF_SPEED_50G,
  [CGX_MODE_80GAUI_C2C] = 0, /* No define for 80G */
  [CGX_MODE_100G_C2C] = VNET_HW_IF_SPEED_100G,
  [CGX_MODE_100G_C2M] = VNET_HW_IF_SPEED_100G,
  [CGX_MODE_100G_CR4] = VNET_HW_IF_SPEED_100G,
  [CGX_MODE_100G_KR4] = VNET_HW_IF_SPEED_100G,
  [CGX_MODE_LAUI_2_C2C_BIT] = VNET_HW_IF_SPEED_50G,
  [CGX_MODE_LAUI_2_C2M_BIT] = VNET_HW_IF_SPEED_50G,
  [CGX_MODE_50GBASE_CR2_C_BIT] = VNET_HW_IF_SPEED_50G,
  [CGX_MODE_50GBASE_KR2_C_BIT] = VNET_HW_IF_SPEED_50G,
  [CGX_MODE_100GAUI_2_C2C_BIT] = VNET_HW_IF_SPEED_100G,
  [CGX_MODE_100GAUI_2_C2M_BIT] = VNET_HW_IF_SPEED_100G,
  [CGX_MODE_100GBASE_CR2_BIT] = VNET_HW_IF_SPEED_100G,
  [CGX_MODE_100GBASE_KR2_BIT] = VNET_HW_IF_SPEED_100G,
  [CGX_MODE_SFI_1G_BIT] = VNET_HW_IF_SPEED_1G,
  [CGX_MODE_25GBASE_CR_C_BIT] = VNET_HW_IF_SPEED_25G,
  [CGX_MODE_25GBASE_KR_C_BIT] = VNET_HW_IF_SPEED_25G,
  [ETH_MODE_SGMII_10M_BIT] = VNET_HW_IF_SPEED_10M,
  [ETH_MODE_SGMII_100M_BIT] = VNET_HW_IF_SPEED_100M,
  [40] = 0,
  [41] = 0,
  [ETH_MODE_2500_BASEX_BIT] = VNET_HW_IF_SPEED_2_5G,
  [ETH_MODE_5000_BASEX_BIT] = VNET_HW_IF_SPEED_5G,
  [ETH_MODE_O_USGMII_BIT] = VNET_HW_IF_SPEED_100M,
  [ETH_MODE_Q_USGMII_BIT] = VNET_HW_IF_SPEED_1G,
  [ETH_MODE_2_5G_USXGMII_BIT] = VNET_HW_IF_SPEED_2_5G,
  [ETH_MODE_5G_USXGMII_BIT] = VNET_HW_IF_SPEED_5G,
  [ETH_MODE_10G_SXGMII_BIT] = VNET_HW_IF_SPEED_10G,
  [ETH_MODE_10G_DXGMII_BIT] = VNET_HW_IF_SPEED_10G,
  [ETH_MODE_10G_QXGMII_BIT] = VNET_HW_IF_SPEED_10G,
};

static u8 *
oct_probe (vlib_main_t *vm, vnet_dev_probe_args_t *args)
{
  return oct_dev_probe (args, 0);
}

static vnet_dev_rv_t
oct_config_args (vlib_main_t *vm, vnet_dev_driver_t *drv)
{
  if (!oct_main.is_config_done)
    {
      if (drv->args)
	oct_main.npa_max_pools =
	  clib_args_get_uint32_val_by_name (drv->args, "npa_max_pools");
      oct_main.is_config_done = 1;
    }
  else
    {
      log_err (NULL, "Driver config arguments are already initialized or "
		     "devices are already initialized");
      return VNET_DEV_ERR_UNSUPPORTED_CONFIG;
    }

  return 0;
}

static clib_arg_t *
oct_dev_get_port_args (oct_device_t *cd)
{
  if (roc_nix_is_lbk (cd->nix) || roc_nix_is_sdp (cd->nix))
    return oct_port_args_lbk_sdp;
  else if (!roc_nix_is_pf (cd->nix))
    return oct_port_args_rvu_vf;
  else
    return oct_port_args;
}

static vnet_dev_rv_t
oct_alloc (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_device_t *cd = vnet_dev_get_data (dev);
  cd->nix =
    clib_mem_alloc_aligned (sizeof (struct roc_nix), CLIB_CACHE_LINE_BYTES);
  return VNET_DEV_OK;
}

static inline uint32_t
oct_nix_get_speed_capa (vnet_dev_t *dev)
{
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix_mac_fwdata fwdata;
  uint32_t speed_capa = VNET_HW_IF_SPEED_UNKNOWN;
  uint8_t mode;
  int rc;

  /* Auto negotiation disabled */
  if (!roc_nix_is_vf_or_sdp (cd->nix) && !roc_nix_is_lbk (cd->nix))
    {
      memset (&fwdata, 0, sizeof (fwdata));
      rc = roc_nix_mac_fwdata_get (cd->nix, &fwdata);
      if (rc)
	{
	  log_err (dev, "Failed to get MAC firmware data");
	  return speed_capa;
	}

      if (fwdata.supported_an)
	speed_capa = 0;

      /* Translate advertised modes to speed_capa */
      for (mode = 0; mode < CGX_MODE_MAX; mode++)
	{
	  if (fwdata.supported_link_modes & BIT_ULL (mode))
	    speed_capa |= oct_mac_modes[mode];
	}
    }

  return speed_capa;
}

static vnet_dev_rv_t
oct_init_nix (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_device_t *cd = vnet_dev_get_data (dev);
  u8 mac_addr[6];
  int rrv;
  oct_port_t oct_port = {};

  *cd->nix = (struct roc_nix) {
    .reta_sz = ROC_NIX_RSS_RETA_SZ_256,
    .max_sqb_count = 512,
    .pci_dev = &cd->common.plt_pci_dev,
    .hw_vlan_ins = true,
  };

  if ((rrv = roc_nix_dev_init (cd->nix)))
    return cnx_return_roc_err (dev, rrv, "roc_nix_dev_init");
  cd->nix_initialized = 1;

  if ((rrv = roc_nix_npc_mac_addr_get (cd->nix, mac_addr)))
    return cnx_return_roc_err (dev, rrv, "roc_nix_npc_mac_addr_get");

  vnet_dev_port_add_args_t port_add_args = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
        .max_rx_queues = 64,
        .max_tx_queues = 64,
        .max_supported_rx_frame_size = roc_nix_max_pkt_len (cd->nix) + VNET_DEV_ETH_FCS_LEN,
	.caps = {
	  .rss = 1,
	},
	.speed_caps = oct_nix_get_speed_capa (dev),
	.rx_offloads = {
	  .ip4_cksum = 1,
	},
	.tx_offloads = {
	  .ip4_cksum = 1,
	  .tcp_cksum = 1,
	  .udp_cksum = 1,
	},

      },
      .default_rss_config = {
	.key = {
          0xfe, 0xed, 0x0b, 0xad, 0xfe, 0xed, 0x0b, 0xad, 0xad, 0x0b, 0xed, 0xfe,
          0xad, 0x0b, 0xed, 0xfe, 0x13, 0x57, 0x9b, 0xef, 0x24, 0x68, 0xac, 0x0e,
          0x91, 0x72, 0x53, 0x11, 0x82, 0x64, 0x20, 0x44, 0x12, 0xef, 0x34, 0xcd,
          0x56, 0xbc, 0x78, 0x9a, 0x9a, 0x78, 0xbc, 0x56, 0xcd, 0x34, 0xef, 0x12,
        },
	.key_len = ROC_NIX_RSS_KEY_LEN,
	.set_key = 1,
      },
      .ops = {
        .init = oct_port_init,
        .deinit = oct_port_deinit,
        .start = oct_port_start,
        .stop = oct_port_stop,
        .config_change = oct_port_cfg_change,
        .config_change_validate = oct_port_cfg_change_validate,
        .format_status = format_oct_port_status,
        .format_flow = format_oct_port_flow,
        .clear_counters = oct_port_clear_counters,
      },
      .data_size = sizeof (oct_port_t),
      .initial_data = &oct_port,
      .args = oct_dev_get_port_args (cd),
    },
    .rx_node = &oct_rx_node,
    .tx_node = &oct_tx_node,
    .rx_queue = {
      .config = {
        .data_size = sizeof (oct_rxq_t),
        .default_size = 1024,
        .multiplier = 32,
        .min_size = 256,
        .max_size = 16384,
      },
      .ops = {
        .alloc = oct_rx_queue_alloc,
        .free = oct_rx_queue_free,
	.format_info = format_oct_rxq_info,
        .clear_counters = oct_rxq_clear_counters,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (oct_txq_t),
        .default_size = 1024,
        .multiplier = 32,
        .min_size = 256,
        .max_size = 16384,
      },
      .ops = {
        .alloc = oct_tx_queue_alloc,
        .free = oct_tx_queue_free,
	.format_info = format_oct_txq_info,
        .clear_counters = oct_txq_clear_counters,
      },
    },
  };

  vnet_dev_set_hw_addr_eth_mac (&port_add_args.port.attr.hw_addr, mac_addr);

  log_info (dev, "MAC address is %U", format_ethernet_address, mac_addr);

  /* Enable TM-specific tx node if requested */
  if (clib_args_get_bool_val_by_name (dev->args, "egress_tm"))
    {
      cd->egress_tm = 1;
      port_add_args.tx_node = &oct_tx_tm_node;
    }

  return vnet_dev_port_add (vm, dev, 0, &port_add_args);
}

static vnet_dev_rv_t
oct_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 sz = sizeof (void *) * ROC_CN10K_NPA_BATCH_ALLOC_MAX_PTRS;
  struct npa_pool_s npapool = { .nat_align = 1 };
  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, 0);
  struct npa_aura_s aura = {};
  oct_device_t *cd = vnet_dev_get_data (dev);
  oct_per_thread_data_t *ptd;
  vnet_dev_rv_t rv;

  /*
   * Drivers config arguments should be initialized by this time
   * otherwise don't allow to set after device init
   */
  if (!oct_main.is_config_done)
    oct_main.is_config_done = 1;

  rv = oct_dev_pci_init (vm, dev, 0);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = oct_init_nix (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  vec_validate_aligned (cd->per_thread_data, tm->n_vlib_mains - 1, CLIB_CACHE_LINE_BYTES);
  for (int i = 0; i < tm->n_vlib_mains; i++)
    {
      ptd = vec_elt_at_index (cd->per_thread_data, i);
      ptd->ba_buffer = oct_plt_init_param.oct_plt_zmalloc (sz, 128);

      if (ptd->ba_buffer == NULL)
	{
	  log_err (dev, "Failed to allocate memory for batch buffers");
	  return VNET_DEV_ERR_DMA_MEM_ALLOC_FAIL;
	}

      clib_memset_u64 (ptd->ba_buffer, OCT_BATCH_ALLOC_IOVA0_MASK,
		       ROC_CN10K_NPA_BATCH_ALLOC_MAX_PTRS);
      if ((rv = roc_npa_pool_create (&ptd->aura_handle, bp->alloc_size, bp->n_buffers, &aura,
				     &npapool, 0)))
	{
	  return cnx_return_roc_err (dev, rv, "roc_npa_pool_create() failed");
	}
      ptd->npa_pool_initialized = 1;
      ptd->hdr_off = vm->buffer_main->ext_hdr_size;
      log_notice (dev, "NPA pool created, tx aura_handle = 0x%lx", ptd->aura_handle);
    }

  return rv;
}

static int
oct_tx_pending_batch_free (vlib_main_t *vm __clib_unused, oct_per_thread_data_t *ptd __clib_unused)
{
#ifndef PLATFORM_OCTEON9
  u64 buffers[ROC_CN10K_NPA_BATCH_ALLOC_MAX_PTRS];
  u32 bi[ROC_CN10K_NPA_BATCH_ALLOC_MAX_PTRS];
  oct_npa_batch_alloc_cl128_t *cl;
  u32 n;

  if (ptd->ba_num_cl == 0)
    return 0;

  cl = ptd->ba_buffer + ptd->ba_first_cl;
  for (u32 i = 0; i < ptd->ba_num_cl; i++)
    {
      oct_npa_batch_alloc_status_t st;

      roc_npa_batch_alloc_wait (cl[i].iova, OCT_BATCH_ALLOC_FINI_WAIT_US);
      st.as_u64 = __atomic_load_n (cl[i].iova, __ATOMIC_ACQUIRE);
      if (st.status.ccode == ALLOC_CCODE_INVAL)
	return -1;
    }

  n = roc_npa_aura_batch_alloc_extract (buffers, (u64 *) cl, ptd->ba_num_cl * ARRAY_LEN (cl->iova));
  if (n)
    {
      vlib_get_buffer_indices_with_offset (vm, (void **) buffers, bi, n, ptd->hdr_off);
      vlib_buffer_free_no_next (vm, bi, n);
    }

  ptd->ba_num_cl = ptd->ba_first_cl = 0;
#endif
  return 0;
}

static void
oct_tx_completion_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_device_t *cd = vnet_dev_get_data (dev);
  oct_per_thread_data_t *ptd;
  int cleanup_failed = 0;

  if (cd->txq_fini_failed)
    {
      log_err (dev, "TX queue finalization failed, preserving completion auras");
      return;
    }

  vec_foreach (ptd, cd->per_thread_data)
    {
      if (ptd->npa_pool_initialized)
	{
	  if (oct_tx_pending_batch_free (vm, ptd))
	    {
	      log_err (dev, "Timed out waiting for pending TX batch allocation");
	      cleanup_failed = 1;
	      continue;
	    }

	  oct_aura_free_all_buffers (vm, ptd->aura_handle, ptd->hdr_off, 0);
	  if (roc_npa_pool_destroy (ptd->aura_handle))
	    {
	      log_err (dev, "roc_npa_pool_destroy() failed for TX completion aura");
	      cleanup_failed = 1;
	      continue;
	    }
	  ptd->npa_pool_initialized = 0;
	}

      if (ptd->ba_buffer)
	{
	  oct_plt_init_param.oct_plt_free (ptd->ba_buffer);
	  ptd->ba_buffer = 0;
	}
    }

  if (!cleanup_failed)
    vec_free (cd->per_thread_data);
}

static void
oct_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_device_t *cd = vnet_dev_get_data (dev);
  int rrv;

  oct_tx_completion_deinit (vm, dev);
  if (cd->nix_initialized)
    {
      rrv = roc_nix_dev_fini (cd->nix);
      if (rrv == 0)
	cd->nix_initialized = 0;
    }
}

static void
oct_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_device_t *cd = vnet_dev_get_data (dev);

  if (cd->nix_initialized)
    roc_nix_dev_fini (cd->nix);
}

static int
oct_npa_max_pools_set_cb (struct plt_pci_device *pci_dev)
{
  roc_idev_npa_maxpools_set (oct_main.npa_max_pools);
  return 0;
}

static vnet_dev_rv_t
oct_driver_init (vlib_main_t *vm, vnet_dev_driver_t *drv __clib_unused)
{
  vnet_dev_rv_t rv;

  rv = oct_roc_init ();
  if (rv != VNET_DEV_OK)
    return rv;

  /* set default values in oct_main */
  oct_main.npa_max_pools = OCT_NPA_MAX_POOLS;

  roc_npa_lf_init_cb_register (oct_npa_max_pools_set_cb);

  return VNET_DEV_OK;
}

VNET_DEV_REGISTER_DRIVER (octeon_net) = {
  .name = "octeon_net",
  .description = "Marvell Octeon network",
  .bus = "pci",
  .device = {
    .data_sz = sizeof (oct_device_t),
    .ops = {
      .config_args = oct_config_args,
      .alloc = oct_alloc,
      .init = oct_init,
      .deinit = oct_deinit,
      .free = oct_free,
      .probe = oct_probe,
    },
    .args = oct_dev_args,
  },
  .driver = {
    .ops.init = oct_driver_init,
    .args = oct_drv_args,
  },
};
