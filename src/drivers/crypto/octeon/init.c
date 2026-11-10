/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023-2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <octeon_common.h>
#include <crypto.h>

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "crypto-init",
};

static struct
{
  u16 device_id;
  char *description;
} oct_crypto_dev_ids[] = {
  { 0xa0f3, "Marvell Octeon-10 Cryptographic Accelerator Unit VF" },
  { 0xa0fe, "Marvell Octeon-9 Cryptographic Accelerator Unit VF" },
};

static int
oct_conf_cpt (vlib_main_t *vm, vnet_dev_t *dev, struct roc_cpt *roc_cpt, int nb_lf)
{
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
      log_err (dev, "could not configure crypto device %U", format_vlib_pci_addr,
	       roc_cpt->pci_dev->addr);
      return cnx_return_roc_err (dev, rrv, "roc_cpt_dev_configure");
    }
  return 0;
}

/* algorithms depend on engine capabilities, so each CPT revision gets its own group */
static vnet_dev_rv_t
oct_crypto_queue_group_add (vlib_main_t *vm, vnet_dev_t *dev, struct roc_cpt *rc, char *name)
{
  vnet_dev_driver_t *drv = pool_elt_at_index (vnet_dev_main.drivers, dev->driver_index);
  vnet_dev_crypto_queue_group_add_args_t args = {
    .engine_desc = "Octeon CPT Engine",
    .engine_priority = 100,
    .deq_node = &oct_crypto_deq_node,
    .key_change = oct_crypto_key_change_handler,
    .key_data_sz = sizeof (oct_crypto_key_t),
    .ops = {
      .init = oct_crypto_queue_init,
      .deinit = oct_crypto_queue_deinit,
      .stop = oct_crypto_queue_stop,
      .format_queue_info = format_oct_cpt_queue_info,
    },
    .config = {
      .data_size = sizeof (oct_crypto_queue_t),
      .min_size = OCT_CPT_LF_MIN_NB_DESC,
      .max_size = OCT_CPT_LF_MAX_NB_DESC,
      .default_size = OCT_CPT_LF_DEF_NB_DESC,
      .size_is_power_of_two = 1,
    },
  };
  vnet_dev_rv_t rv;

  args.alg_handlers = oct_crypto_get_alg_handlers (rc->hw_caps + CPT_ENG_TYPE_SE);
  rv = vnet_dev_crypto_queue_group_add (vm, drv, &args, "%s", name);
  vec_free (args.alg_handlers);
  return rv;
}

static vnet_dev_rv_t
oct_init_cpt (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_crypto_device_t *cd = vnet_dev_get_data (dev);
  vnet_dev_crypto_queue_add_args_t queue_args = {};
  struct roc_cpt *roc_cpt;
  vnet_dev_rv_t rv;
  char group[8];
  u32 n_queues;
  int rrv;

  roc_cpt = oct_plt_init_param.oct_plt_zmalloc (sizeof (struct roc_cpt), CLIB_CACHE_LINE_BYTES);
  roc_cpt->pci_dev = &cd->common.plt_pci_dev;

  cd->hw_ctx_cache = roc_errata_cpt_hang_on_mixed_ctx_val () || roc_model_is_cn10ka_b0 () ||
		     roc_model_is_cn10kb_a0 ();

  if ((rrv = roc_cpt_dev_init (roc_cpt)))
    return cnx_return_roc_err (dev, rrv, "roc_cpt_dev_init");

  snprintf (group, sizeof (group), "v%u", roc_cpt->cpt_revision);
  if ((rv = oct_crypto_queue_group_add (vm, dev, roc_cpt, group)) != VNET_DEV_OK)
    return rv;
  queue_args.group = group;

  /* one LF per queue, threads share queues when there are fewer LFs */
  n_queues = clib_min (vlib_get_n_threads (), roc_cpt->nb_lf_avail);
  if ((rrv = oct_conf_cpt (vm, dev, roc_cpt, n_queues)))
    return rrv;

  cd->roc_cpt = roc_cpt;

  for (u32 i = 0; i < n_queues; i++)
    if ((rv = vnet_dev_crypto_queue_add (vm, dev, &queue_args)) != VNET_DEV_OK)
      return rv;

  return VNET_DEV_OK;
}

static u8 *
oct_crypto_probe (vlib_main_t *vm, vnet_dev_probe_args_t *args)
{
  vnet_dev_bus_pci_device_info_t *di = args->device_info;

  if (di->vendor_id != 0x177d)
    return 0;

  FOREACH_ARRAY_ELT (d, oct_crypto_dev_ids)
    if (d->device_id == di->device_id)
      return format (0, "%s", d->description);

  return 0;
}

static vnet_dev_rv_t
oct_crypto_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_rv_t rv;

  rv = oct_dev_pci_init (vm, dev, /* is_vf */ 1);
  if (rv != VNET_DEV_OK)
    return rv;

  return oct_init_cpt (vm, dev);
}

static void
oct_crypto_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  oct_crypto_device_t *cd = vnet_dev_get_data (dev);

  if (cd->roc_cpt == 0)
    return;

  roc_cpt_dev_fini (cd->roc_cpt);
  oct_plt_init_param.oct_plt_free (cd->roc_cpt);
  cd->roc_cpt = 0;
}

static vnet_dev_rv_t
oct_crypto_driver_init (vlib_main_t *vm, vnet_dev_driver_t *drv)
{
  vnet_dev_rv_t rv;

  if ((rv = oct_roc_init ()) != VNET_DEV_OK)
    return rv;

  if (vnet_crypto_reserve_async_key_data (sizeof (oct_crypto_key_t)))
    return VNET_DEV_ERR_INIT_FAILED;

  return VNET_DEV_OK;
}

VNET_DEV_REGISTER_DRIVER (octeon_cpt) = {
  .name = "octeon-cpt",
  .description = "Marvell Octeon crypto",
  .bus = "pci",
  .device = {
    .data_sz = sizeof (oct_crypto_device_t),
    .ops = {
      .init = oct_crypto_init,
      .deinit = oct_crypto_deinit,
      .probe = oct_crypto_probe,
      .format_info = format_oct_cpt_dev_info,
    },
  },
  .driver = {
    .ops.init = oct_crypto_driver_init,
  },
};
