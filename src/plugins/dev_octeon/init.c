/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/dev/counters.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dev_octeon/octeon.h>
#include <dev_octeon/crypto.h>

#include <base/roc_api.h>
#include <common.h>

struct roc_model oct_model;
oct_main_t oct_main;
extern oct_plt_init_param_t oct_plt_init_param;

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "init",
};

#define _(f, n, s, d)                                                         \
  { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },

vlib_error_desc_t oct_tx_node_counters[] = { foreach_oct_tx_node_counter };
#undef _

vnet_dev_node_t oct_rx_node = {
  .format_trace = format_oct_rx_trace,
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

static struct
{
  u16 device_id;
  oct_device_type_t type;
  char *description;
} oct_dev_types[] = {

#define _(id, device_type, desc)                                              \
  {                                                                           \
    .device_id = (id), .type = OCT_DEVICE_TYPE_##device_type,                 \
    .description = (desc)                                                     \
  }

  _ (0xa063, RVU_PF, "Marvell Octeon Resource Virtualization Unit PF"),
  _ (0xa064, RVU_VF, "Marvell Octeon Resource Virtualization Unit VF"),
  _ (0xa0f8, LBK_VF, "Marvell Octeon Loopback Unit VF"),
  _ (0xa0f7, SDP_VF, "Marvell Octeon System DPI Packet Interface Unit VF"),
  _ (0xa0f3, O10K_CPT_VF,
     "Marvell Octeon-10 Cryptographic Accelerator Unit VF"),
  _ (0xa0fe, O9K_CPT_VF, "Marvell Octeon-9 Cryptographic Accelerator Unit VF"),
#undef _
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
    .name = "n_desc",
    .desc = "number of cpt descriptors, applicable to cpt devices only",
    .type = CLIB_ARG_TYPE_UINT32,
    .min = OCT_CPT_LF_MIN_NB_DESC,
    .max = OCT_CPT_LF_MAX_NB_DESC,
    .default_val.uint32 = OCT_CPT_LF_DEF_NB_DESC,
  },
  {
    .id = OCT_DEV_ARG_EGRESS_TM,
    .name = "egress_tm",
    .desc = "Egress traffic manager enable (network devices only)",
    .type = VNET_DEV_ARG_TYPE_BOOL,
    .default_val.boolean = false,
  },
  {
    .id = OCT_DEV_ARG_END,
    .name = "end",
    .desc = "Argument end",
    .type = CLIB_ARG_END,
  },
};

static u8 *
oct_probe (vlib_main_t *vm, vnet_dev_probe_args_t *args)
{
  vnet_dev_bus_pci_device_info_t *di = args->device_info;

  if (di->vendor_id != 0x177d) /* Cavium */
    return 0;

  FOREACH_ARRAY_ELT (dt, oct_dev_types)
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

static vnet_dev_rv_t
oct_init_nix (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_device_t *cd = vnet_dev_get_data (dev);
  u8 mac_addr[6];
  int rrv;
  oct_port_t oct_port = {};

  *cd->nix = (struct roc_nix){
    .reta_sz = ROC_NIX_RSS_RETA_SZ_256,
    .max_sqb_count = 512,
    .pci_dev = &cd->plt_pci_dev,
    .hw_vlan_ins = true,
  };

  if ((rrv = roc_nix_dev_init (cd->nix)))
    return cnx_return_roc_err (dev, rrv, "roc_nix_dev_init");

  if ((rrv = roc_nix_npc_mac_addr_get (cd->nix, mac_addr)))
    return cnx_return_roc_err (dev, rrv, "roc_nix_npc_mac_addr_get");

  vnet_dev_port_add_args_t port_add_args = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
        .max_rx_queues = 64,
        .max_tx_queues = 64,
        .max_supported_rx_frame_size = roc_nix_max_pkt_len (cd->nix),
	.caps = {
	  .rss = 1,
	},
	.rx_offloads = {
	  .ip4_cksum = 1,
	},
	.tx_offloads = {
	  .ip4_cksum = 1,
	},

      },
      .default_rss_key = {
        .key = {
          0xfe, 0xed, 0x0b, 0xad, 0xfe, 0xed, 0x0b, 0xad, 0xad, 0x0b, 0xed, 0xfe,
          0xad, 0x0b, 0xed, 0xfe, 0x13, 0x57, 0x9b, 0xef, 0x24, 0x68, 0xac, 0x0e,
          0x91, 0x72, 0x53, 0x11, 0x82, 0x64, 0x20, 0x44, 0x12, 0xef, 0x34, 0xcd,
          0x56, 0xbc, 0x78, 0x9a, 0x9a, 0x78, 0xbc, 0x56, 0xcd, 0x34, 0xef, 0x12,
        },
        .length = 48,
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
  foreach_vnet_dev_args (arg, dev)
    {
      if (arg->id == OCT_DEV_ARG_EGRESS_TM && vnet_dev_arg_get_bool (arg))
	{
	  cd->egress_tm = 1;
	  port_add_args.tx_node = &oct_tx_tm_node;
	  break;
	}
    }

  return vnet_dev_port_add (vm, dev, 0, &port_add_args);
}

static int
oct_conf_cpt (vlib_main_t *vm, vnet_dev_t *dev, oct_crypto_dev_t *ocd,
	      int nb_lf)
{
  struct roc_cpt *roc_cpt = ocd->roc_cpt;
  int rrv;

  if ((rrv = roc_cpt_eng_grp_add (roc_cpt, CPT_ENG_TYPE_SE)) < 0)
    {
      log_err (dev, "Could not add CPT SE engines");
      return cnx_return_roc_err (dev, rrv, "roc_cpt_eng_grp_add");
    }
  if ((rrv = roc_cpt_eng_grp_add (roc_cpt, CPT_ENG_TYPE_IE)) < 0)
    {
      log_err (dev, "Could not add CPT IE engines");
      return cnx_return_roc_err (dev, rrv, "roc_cpt_eng_grp_add");
    }
  if (roc_cpt->eng_grp[CPT_ENG_TYPE_IE] != ROC_LEGACY_CPT_DFLT_ENG_GRP_SE_IE)
    {
      log_err (dev, "Invalid CPT IE engine group configuration");
      return -1;
    }
  if (roc_cpt->eng_grp[CPT_ENG_TYPE_SE] != ROC_LEGACY_CPT_DFLT_ENG_GRP_SE)
    {
      log_err (dev, "Invalid CPT SE engine group configuration");
      return -1;
    }
  if ((rrv = roc_cpt_dev_configure (roc_cpt, nb_lf, false, 0)) < 0)
    {
      log_err (dev, "could not configure crypto device %U",
	       format_vlib_pci_addr, roc_cpt->pci_dev->addr);
      return cnx_return_roc_err (dev, rrv, "roc_cpt_dev_configure");
    }
  return 0;
}

static vnet_dev_rv_t
oct_conf_cpt_queue (vlib_main_t *vm, vnet_dev_t *dev, oct_crypto_dev_t *ocd)
{
  struct roc_cpt *roc_cpt = ocd->roc_cpt;
  struct roc_cpt_lmtline *cpt_lmtline;
  struct roc_cpt_lf *cpt_lf;
  int rrv;

  cpt_lf = &ocd->lf;
  cpt_lmtline = &ocd->lmtline;

  cpt_lf->nb_desc = ocd->n_desc;
  cpt_lf->lf_id = 0;
  if ((rrv = roc_cpt_lf_init (roc_cpt, cpt_lf)) < 0)
    return cnx_return_roc_err (dev, rrv, "roc_cpt_lf_init");

  roc_cpt_iq_enable (cpt_lf);

  if ((rrv = roc_cpt_lmtline_init (roc_cpt, cpt_lmtline, 0, false) < 0))
    return cnx_return_roc_err (dev, rrv, "roc_cpt_lmtline_init");

  return 0;
}

static vnet_dev_rv_t
oct_init_cpt (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_crypto_main_t *ocm = &oct_crypto_main;
  extern oct_plt_init_param_t oct_plt_init_param;
  oct_device_t *cd = vnet_dev_get_data (dev);
  oct_crypto_dev_t *ocd = NULL;
  int rrv;

  if (ocm->n_cpt == OCT_MAX_N_CPT_DEV || ocm->started)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  ocd = oct_plt_init_param.oct_plt_zmalloc (sizeof (oct_crypto_dev_t),
					    CLIB_CACHE_LINE_BYTES);

  ocd->roc_cpt = oct_plt_init_param.oct_plt_zmalloc (sizeof (struct roc_cpt),
						     CLIB_CACHE_LINE_BYTES);
  ocd->roc_cpt->pci_dev = &cd->plt_pci_dev;

  ocd->dev = dev;
  ocd->n_desc = clib_args_get_uint32_val_by_name (dev->args, "n_desc");

  if ((rrv = roc_cpt_dev_init (ocd->roc_cpt)))
    return cnx_return_roc_err (dev, rrv, "roc_cpt_dev_init");

  if ((rrv = oct_conf_cpt (vm, dev, ocd, 1)))
    return rrv;

  if ((rrv = oct_conf_cpt_queue (vm, dev, ocd)))
    return rrv;

  if (!ocm->n_cpt)
    {
      /*
       * Initialize s/w queues, which are common across multiple
       * crypto devices
       */
      oct_conf_sw_queue (vm, dev, ocd);

      ocm->crypto_dev[0] = ocd;
    }

  ocm->crypto_dev[1] = ocd;

  oct_init_crypto_engine_handlers (vm, dev);

  ocm->n_cpt++;

  return VNET_DEV_OK;
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
  vlib_pci_config_hdr_t pci_hdr;
  vnet_dev_rv_t rv;

  /*
   * Drivers config arguments should be initialized by this time
   * otherwise don't allow to set after device init
   */
  if (!oct_main.is_config_done)
    oct_main.is_config_done = 1;

  rv = vnet_dev_pci_read_config_header (vm, dev, &pci_hdr);
  if (rv != VNET_DEV_OK)
    return rv;

  if (pci_hdr.vendor_id != 0x177d)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  FOREACH_ARRAY_ELT (dt, oct_dev_types)
    {
      if (dt->device_id == pci_hdr.device_id)
	cd->type = dt->type;
    }

  if (cd->type == OCT_DEVICE_TYPE_UNKNOWN)
    return rv;

  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  cd->plt_pci_dev = (struct plt_pci_device){
    .id.vendor_id = pci_hdr.vendor_id,
    .id.device_id = pci_hdr.device_id,
    .id.class_id = pci_hdr.class << 16 | pci_hdr.subclass,
    .pci_handle = vnet_dev_get_pci_handle (dev),
  };
  cd->msix_handler = NULL;

  foreach_int (i, 2, 4)
    {
      rv = vnet_dev_pci_map_region (vm, dev, i,
				    &cd->plt_pci_dev.mem_resource[i].addr);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  STATIC_ASSERT (sizeof (cd->plt_pci_dev.name) == sizeof (dev->device_id), "");

  if ((rv = vnet_dev_pci_bus_master_enable (vm, dev)))
    return rv;

  strncpy ((char *) cd->plt_pci_dev.name, dev->device_id,
	   sizeof (dev->device_id));

  cd->plt_pci_dev.intr_handle = malloc (sizeof (struct oct_pci_intr_handle));
  if (!cd->plt_pci_dev.intr_handle)
    return VNET_DEV_ERR_DMA_MEM_ALLOC_FAIL;
  memset (cd->plt_pci_dev.intr_handle, 0x0,
	  sizeof (struct oct_pci_intr_handle));
  cd->plt_pci_dev.intr_handle->pci_handle = cd->plt_pci_dev.pci_handle;

  switch (cd->type)
    {
    case OCT_DEVICE_TYPE_RVU_PF:
    case OCT_DEVICE_TYPE_RVU_VF:
    case OCT_DEVICE_TYPE_LBK_VF:
    case OCT_DEVICE_TYPE_SDP_VF:
      rv = oct_init_nix (vm, dev);
      break;

    case OCT_DEVICE_TYPE_O10K_CPT_VF:
    case OCT_DEVICE_TYPE_O9K_CPT_VF:
      rv = oct_init_cpt (vm, dev);
      break;

    default:
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
    }

  if (!vec_len (oct_main.per_thread_data))
    {
      vec_validate_aligned (oct_main.per_thread_data, tm->n_vlib_mains - 1,
			    CLIB_CACHE_LINE_BYTES);
      for (int i = 0; i < tm->n_vlib_mains; i++)
	{
	  oct_per_thread_data_t *ptd =
	    vec_elt_at_index (oct_main.per_thread_data, i);
	  ptd->ba_buffer = oct_plt_init_param.oct_plt_zmalloc (sz, 128);

	  if (ptd->ba_buffer == NULL)
	    {
	      log_err (dev, "Failed to allocate memory for batch buffers");
	      return VNET_DEV_ERR_DMA_MEM_ALLOC_FAIL;
	    }

	  clib_memset_u64 (ptd->ba_buffer, OCT_BATCH_ALLOC_IOVA0_MASK,
			   ROC_CN10K_NPA_BATCH_ALLOC_MAX_PTRS);
	  if ((rv = roc_npa_pool_create (&ptd->aura_handle, bp->alloc_size,
					 bp->n_buffers, &aura, &npapool, 0)))
	    {
	      return cnx_return_roc_err (dev, rv,
					 "roc_npa_pool_create() failed");
	    }
	  ptd->npa_pool_initialized = 1;
	  ptd->hdr_off = vm->buffer_main->ext_hdr_size;
	  log_notice (dev, "NPA pool created, tx aura_handle = 0x%lx",
		      ptd->aura_handle);
	}
    }

  return rv;
}

static void
oct_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_device_t *cd = vnet_dev_get_data (dev);

  if (cd->nix_initialized)
    roc_nix_dev_fini (cd->nix);
}

static void
oct_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_device_t *cd = vnet_dev_get_data (dev);

  if (cd->nix_initialized)
    roc_nix_dev_fini (cd->nix);
}

VNET_DEV_REGISTER_DRIVER (octeon) = {
  .name = "octeon",
  .description = "Marvell Octeon",
  .bus = "pci",
  .device_data_sz = sizeof (oct_device_t),
  .ops = {
    .config_args = oct_config_args,
    .alloc = oct_alloc,
    .init = oct_init,
    .deinit = oct_deinit,
    .free = oct_free,
    .probe = oct_probe,
  },
  .args = oct_dev_args,
  .drv_args = oct_drv_args,
};

static int
oct_npa_max_pools_set_cb (struct plt_pci_device *pci_dev)
{
  roc_idev_npa_maxpools_set (oct_main.npa_max_pools);
  return 0;
}

static clib_error_t *
oct_plugin_init (vlib_main_t *vm)
{
  int rv;

  rv = oct_plt_init (&oct_plt_init_param);
  if (rv)
    return clib_error_return (0, "oct_plt_init failed");

  rv = roc_model_init (&oct_model);
  if (rv)
    return clib_error_return (0, "roc_model_init failed");

#ifdef PLATFORM_OCTEON9
  if (!roc_model_is_cn9k ())
    return clib_error_return (0, "OCTEON model is not OCTEON9");
#else
  if (!roc_model_is_cn10k ())
    return clib_error_return (0, "OCTEON model is not OCTEON10");
#endif

  /* set default values in oct_main */
  oct_main.npa_max_pools = OCT_NPA_MAX_POOLS;

  roc_npa_lf_init_cb_register (oct_npa_max_pools_set_cb);

  return 0;
}

VLIB_INIT_FUNCTION (oct_plugin_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_octeon",
};
