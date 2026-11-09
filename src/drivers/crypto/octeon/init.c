/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023-2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vlib/pci/pci.h>
#include <octeon_common.h>
#include <crypto.h>

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "crypto-init",
};

typedef struct
{
  oct_dev_common_t common;
} oct_crypto_device_t;

static clib_arg_t oct_crypto_dev_args[] = {
  {
    .name = "n_desc",
    .desc = "number of cpt descriptors",
    .type = CLIB_ARG_TYPE_UINT32,
    .min = OCT_CPT_LF_MIN_NB_DESC,
    .max = OCT_CPT_LF_MAX_NB_DESC,
    .default_val.uint32 = OCT_CPT_LF_DEF_NB_DESC,
  },
  {
    .name = "end",
    .desc = "Argument end",
    .type = CLIB_ARG_END,
  },
};

static int
oct_conf_cpt (vlib_main_t *vm, vnet_dev_t *dev, oct_crypto_dev_t *ocd, int nb_lf)
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
      log_err (dev, "could not configure crypto device %U", format_vlib_pci_addr,
	       roc_cpt->pci_dev->addr);
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
  oct_crypto_device_t *cd = vnet_dev_get_data (dev);
  oct_crypto_dev_t *ocd = NULL;
  int rrv;

  if (ocm->n_cpt == OCT_MAX_N_CPT_DEV || ocm->started)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  ocd = oct_plt_init_param.oct_plt_zmalloc (sizeof (oct_crypto_dev_t), CLIB_CACHE_LINE_BYTES);

  ocd->roc_cpt =
    oct_plt_init_param.oct_plt_zmalloc (sizeof (struct roc_cpt), CLIB_CACHE_LINE_BYTES);
  ocd->roc_cpt->pci_dev = &cd->common.plt_pci_dev;

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

static u8 *
oct_crypto_probe (vlib_main_t *vm, vnet_dev_probe_args_t *args)
{
  return oct_dev_probe (args, 1);
}

static vnet_dev_rv_t
oct_crypto_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_rv_t rv;

  rv = oct_dev_pci_init (vm, dev, 1);
  if (rv != VNET_DEV_OK)
    return rv;

  return oct_init_cpt (vm, dev);
}

static vnet_dev_rv_t
oct_crypto_driver_init (vlib_main_t *vm, vnet_dev_driver_t *drv __clib_unused)
{
  return oct_roc_init ();
}

VNET_DEV_REGISTER_DRIVER (octeon_crypto) = {
  .name = "octeon_crypto",
  .description = "Marvell Octeon crypto",
  .bus = "pci",
  .device = {
    .data_sz = sizeof (oct_crypto_device_t),
    .ops = {
      .init = oct_crypto_init,
      .probe = oct_crypto_probe,
    },
    .args = oct_crypto_dev_args,
  },
  .driver = {
    .ops.init = oct_crypto_driver_init,
  },
};
