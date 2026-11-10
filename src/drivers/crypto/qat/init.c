/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <qat.h>

VLIB_REGISTER_LOG_CLASS (qat_log, static) = {
  .class_name = "qat",
  .subclass_name = "init",
};

static const vnet_crypto_alg_t qat_gen2_algs[] = {
#define _(n, ...) VNET_CRYPTO_ALG_##n,
  foreach_qat_gen2_alg
#undef _
};

static const vnet_crypto_alg_t qat_gen4_algs[] = {
#define _(n, ...) VNET_CRYPTO_ALG_##n,
  foreach_qat_gen4_alg
#undef _
};

static const qat_gen_config_t qat_gen_config[QAT_N_GENS] = {
  [QAT_GEN2] = {
    .group = "gen2-sym",
    .engine_desc = "Intel QuickAssist Technology gen2",
    .algs = qat_gen2_algs,
    .n_algs = ARRAY_LEN (qat_gen2_algs),
    .required_caps = QAT_CAP_SYM | QAT_CAP_CIPHER | QAT_CAP_AUTH,
    .bank_size = 0x1000,
    .ring_base_shift = 6,
  },
  [QAT_GEN4] = {
    .group = "gen4-sym",
    .engine_desc = "Intel QuickAssist Technology",
    .algs = qat_gen4_algs,
    .n_algs = ARRAY_LEN (qat_gen4_algs),
    .required_caps = QAT_CAP_SYM | QAT_CAP_CIPHER | QAT_CAP_AUTH | QAT_CAP_AESGCM_SPC |
		     QAT_CAP_CHACHA_POLY,
    .bank_size = 0x2000,
    .ring_cfg_offset = 0x1000,
    .has_ucs = 1,
  },
};

static const struct
{
  u16 device_id;
  qat_gen_t gen;
  const char *desc;
} qat_devices[] = {
  { 0x0443, QAT_GEN2, "Intel QuickAssist DH895xCC Virtual Function" },
  { 0x37c9, QAT_GEN2, "Intel QuickAssist C62x Virtual Function" },
  { 0x19e3, QAT_GEN2, "Intel QuickAssist C3xxx Virtual Function" },
  { 0x4941, QAT_GEN4, "Intel QuickAssist 4xxx Virtual Function" },
};

static u8 *
qat_probe (vlib_main_t *vm __clib_unused, vnet_dev_probe_args_t *a)
{
  vnet_dev_bus_pci_device_info_t *di = a->device_info;

  if (di->vendor_id != 0x8086)
    return 0;

  FOREACH_ARRAY_ELT (d, qat_devices)
    if (d->device_id == di->device_id)
      return format (0, "%s", d->desc);

  return 0;
}

static vnet_dev_rv_t
qat_set_gen (vlib_main_t *vm, vnet_dev_t *dev)
{
  qat_device_t *qd = vnet_dev_get_data (dev);
  vlib_pci_config_hdr_t cfg;
  clib_error_t *err;

  err = vlib_pci_read_write_config (vm, vnet_dev_get_pci_handle (dev), VLIB_READ, 0, &cfg,
				    sizeof (cfg));
  if (err)
    {
      log_err (dev, "PCI config read failed: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  FOREACH_ARRAY_ELT (d, qat_devices)
    if (d->device_id == cfg.device_id)
      {
	qd->gen = d->gen;
	qd->cfg = qat_gen_config + d->gen;
	return VNET_DEV_OK;
      }

  return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
}

static void
qat_add_sym_ring_pairs (qat_device_t *qd)
{
  if (qd->gen == QAT_GEN2)
    {
      for (u8 i = 0; i < QAT_GEN2_N_SYM_RINGS; i++)
	qd->sym_ring_pairs[qd->n_sym_ring_pairs++] = (qat_ring_pair_t) {
	  .tx_ring = QAT_GEN2_SYM_TX_RING0 + i,
	  .rx_ring = QAT_GEN2_SYM_TX_RING0 + i + QAT_GEN2_RX_RING_OFFSET,
	};
      return;
    }

  for (u8 i = 0; i < QAT_GEN4_VF_N_BANKS; i++)
    if (qat_ring_to_svc_map_get (qd->ring_to_svc_map, i) == QAT_SVC_SYM)
      qd->sym_ring_pairs[qd->n_sym_ring_pairs++] = (qat_ring_pair_t) {
	.bank = i,
	.tx_ring = QAT_GEN4_RING_TX,
	.rx_ring = QAT_GEN4_RING_RX,
      };
}

static vnet_dev_rv_t
qat_reset_sym_ring_pairs (vlib_main_t *vm, vnet_dev_t *dev)
{
  qat_device_t *qd = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;

  for (u32 i = 0; i < qd->n_sym_ring_pairs; i++)
    if ((rv = qat_ring_pair_reset (vm, dev, qd->sym_ring_pairs + i)) != VNET_DEV_OK)
      return rv;

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qat_check_caps (vlib_main_t *vm, vnet_dev_t *dev)
{
  qat_device_t *qd = vnet_dev_get_data (dev);
  u32 required = qd->cfg->required_caps;
  u32 missing;

  /* PF does not report capabilities */
  if (qat_pfvf_get_caps (vm, dev, &qd->caps) != VNET_DEV_OK ||
      qd->caps.len < QAT_BLKMSG_CAPS_V2_LEN)
    {
      log_warn (dev, "PF does not report capabilities");
      return VNET_DEV_OK;
    }

  if ((missing = required & ~qd->caps.capabilities))
    {
      log_err (dev, "missing capabilities: %U", format_qat_capabilities, missing);
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
    }

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qat_queue_group_add (vlib_main_t *vm, vnet_dev_t *dev)
{
  qat_device_t *qd = vnet_dev_get_data (dev);
  vnet_dev_driver_t *drv = pool_elt_at_index (vnet_dev_main.drivers, dev->driver_index);
  qat_driver_t *qdrv = vnet_dev_get_driver_data (drv);
  const qat_gen_config_t *gc = qd->cfg;
  int build_templates = qdrv->templates[qd->gen] == 0;
  vnet_dev_crypto_queue_group_add_args_t args = {
    .engine_desc = gc->engine_desc,
    .engine_priority = 100,
    .deq_node = &qat_deq_node,
    .key_change = qat_key_change,
    .key_data_sz = sizeof (qat_key_t),
    .multi_queue_per_thread = 1,
    .ops = {
      .init = qat_queue_init,
      .deinit = qat_queue_deinit,
      .start = qat_queue_start,
      .stop = qat_queue_stop,
      .format_queue_info = format_qat_queue_info,
    },
    .config = {
      .data_size = sizeof (qat_queue_t),
      .min_size = QAT_MIN_QUEUE_SIZE,
      .max_size = QAT_MAX_QUEUE_SIZE,
      .default_size = QAT_DEFAULT_QUEUE_SIZE,
      .size_is_power_of_two = 1,
    },
  };
  vnet_dev_rv_t rv;

  if (build_templates)
    vec_validate_aligned (qdrv->templates[qd->gen], VNET_CRYPTO_N_ALGS - 1, CLIB_CACHE_LINE_BYTES);

  for (u32 i = 0; i < gc->n_algs; i++)
    {
      vnet_dev_crypto_alg_handlers_t h = { .alg = gc->algs[i] };

      if (build_templates)
	{
	  qat_fw_la_req_t *t = qdrv->templates[qd->gen][h.alg].req;

	  qat_tmpl_build (t + VNET_CRYPTO_OP_TYPE_ENCRYPT, qat_algs + h.alg, 1, gc);
	  qat_tmpl_build (t + VNET_CRYPTO_OP_TYPE_DECRYPT, qat_algs + h.alg, 0, gc);
	}

      switch (qat_algs[h.alg].type)
	{
	case QAT_ALG_TYPE_CIPHER:
	  h.enc_node = &qat_enq_cipher_enc_node;
	  h.dec_node = &qat_enq_cipher_dec_node;
	  break;
	case QAT_ALG_TYPE_AEAD:
	  h.enc_node = &qat_enq_aead_enc_node;
	  h.dec_node = &qat_enq_aead_dec_node;
	  break;
	case QAT_ALG_TYPE_COMBINED:
	  h.enc_node = &qat_enq_combined_enc_node;
	  h.dec_node = &qat_enq_combined_dec_node;
	  break;
	case QAT_ALG_TYPE_NONE:
	  break;
	}

      vec_add1 (args.alg_handlers, h);
    }

  rv = vnet_dev_crypto_queue_group_add (vm, drv, &args, "%s", gc->group);
  vec_free (args.alg_handlers);
  return rv;
}

static vnet_dev_rv_t
qat_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  qat_device_t *qd = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;

  if ((rv = qat_set_gen (vm, dev)))
    return rv;

  if ((rv = vnet_dev_pci_map_region (vm, dev, 0, &qd->bar0)))
    return rv;

  if ((rv = vnet_dev_pci_map_region (vm, dev, 2, &qd->bar2)))
    return rv;

  if ((rv = vnet_dev_pci_bus_master_enable (vm, dev)))
    return rv;

  rv = qat_pfvf_init (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  qat_add_sym_ring_pairs (qd);

  if (qd->n_sym_ring_pairs == 0)
    {
      log_err (dev, "no ring pair is configured for symmetric crypto (ring map 0x%04x)",
	       qd->ring_to_svc_map.as_u16);
      qat_pfvf_shutdown (vm, dev);
      return VNET_DEV_ERR_UNSUPPORTED_CONFIG;
    }

  if (qd->gen == QAT_GEN4 && qd->n_sym_ring_pairs < QAT_GEN4_VF_N_BANKS)
    log_notice (dev,
		"symmetric crypto may be faster with the PF configured for 'sym' service only");

  rv = qat_check_caps (vm, dev);
  if (rv == VNET_DEV_OK)
    rv = qat_queue_group_add (vm, dev);
  if (rv == VNET_DEV_OK)
    rv = qat_reset_sym_ring_pairs (vm, dev);
  if (rv != VNET_DEV_OK)
    {
      qat_pfvf_shutdown (vm, dev);
      return rv;
    }

  /* one crypto queue per symmetric crypto ring pair */
  for (u32 i = 0; i < qd->n_sym_ring_pairs; i++)
    {
      qat_queue_t q = { .rp = qd->sym_ring_pairs[i] };
      vnet_dev_crypto_queue_add_args_t args = {
	.group = qd->cfg->group,
	.initial_data = &q,
      };

      if ((rv = vnet_dev_crypto_queue_add (vm, dev, &args)) != VNET_DEV_OK)
	return rv;
    }

  log_debug (dev, "%u symmetric crypto ring pairs", qd->n_sym_ring_pairs);
  return VNET_DEV_OK;
}

static void
qat_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  qat_device_t *qd = vnet_dev_get_data (dev);

  if (qd->pfvf_initialized == 0)
    return;

  qat_reset_sym_ring_pairs (vm, dev);
  qat_pfvf_shutdown (vm, dev);
}

static vnet_dev_rv_t
qat_driver_init (vlib_main_t *vm __clib_unused, vnet_dev_driver_t *drv __clib_unused)
{
  if (vnet_crypto_reserve_async_key_data (sizeof (qat_key_t)))
    return VNET_DEV_ERR_INIT_FAILED;

  return VNET_DEV_OK;
}

VNET_DEV_REGISTER_DRIVER (qat) = {
  .name = "qat",
  .description = "Intel QuickAssist Technology",
  .bus = "pci",
  .device = {
    .data_sz = sizeof (qat_device_t),
    .ops = {
      .init = qat_init,
      .deinit = qat_deinit,
      .probe = qat_probe,
      .format_info = format_qat_dev_info,
    },
  },
  .driver = {
    .data_sz = sizeof (qat_driver_t),
    .ops.init = qat_driver_init,
  },
};
