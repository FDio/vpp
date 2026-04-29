/*
 * Copyright (c) 2025 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <errno.h>
#include <stdarg.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/ethernet/ethernet.h>
#include <octeon.h>
#include "common.h"

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "pfc",
};

static vnet_dev_rv_t
oct_pfc_roc_err (vnet_dev_t *dev, int rv, char *fmt, ...)
{
  u8 *s = 0;
  va_list va;

  va_start (va, fmt);
  s = va_format (s, fmt, &va);
  va_end (va);

  log_err (dev, "%v - ROC error %s (%d)", s, roc_error_msg_get (rv), rv);

  vec_free (s);
  return VNET_DEV_ERR_INTERNAL;
}

static int
oct_nix_pfc_rq_conf (vnet_dev_port_t *port, uint16_t qid, uint8_t tx_pause,
		     uint8_t tc)
{
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix_pfc_cfg pfc_cfg;
  struct roc_nix *nix = cd->nix;
  struct roc_nix_fc_cfg fc_cfg;
  enum roc_nix_fc_mode mode;
  vnet_dev_rx_queue_t *rxq;
  struct roc_nix_rq *rq;
  struct roc_nix_cq *cq;
  oct_rxq_t *crq;
  int rc;

  if (port->rx_queues == NULL)
    return -EINVAL;

  if (qid >= port->attr.max_rx_queues)
    return -ENOTSUP;

  /* Configure RQ */
  rxq = vnet_dev_get_port_rx_queue_by_id (port, qid);
  if (rxq == 0)
    return -ENODEV;

  crq = vnet_dev_get_rx_queue_data (rxq);
  rq = &crq->rq;
  cq = &crq->cq;

  memset (&fc_cfg, 0, sizeof (struct roc_nix_fc_cfg));
  fc_cfg.type = ROC_NIX_FC_RQ_CFG;
  fc_cfg.rq_cfg.tc = tc;
  fc_cfg.rq_cfg.enable = !!tx_pause;
  fc_cfg.rq_cfg.rq = rq->qid;
  fc_cfg.rq_cfg.pool = rq->aura_handle;
  fc_cfg.rq_cfg.spb_pool = rq->spb_aura_handle;
  fc_cfg.rq_cfg.cq_drop = cq->drop_thresh;
  fc_cfg.rq_cfg.cq_bp = cq->bp_thresh;
  fc_cfg.rq_cfg.pool_drop_pct = ROC_NIX_AURA_THRESH;
  rc = roc_nix_fc_config_set (nix, &fc_cfg);
  if (rc)
    return rc;

  rxq->tc = tc;
  /* Recheck number of RQ's that have PFC enabled */
  cd->tx_pause_en = 0;
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      /* Skip if RQ does not exist */
      if (!q->enabled)
	continue;

      oct_rxq_t *crq2 = vnet_dev_get_rx_queue_data (q);
      rq = &crq2->rq;
      if (rq->tc != ROC_NIX_PFC_CLASS_INVALID)
	cd->tx_pause_en++;
    }

  /* Skip if PFC already enabled in mac */
  if (cd->tx_pause_en > 1)
    return 0;

  /* Configure MAC block */
  cd->class_en = cd->tx_pause_en ? 0xFF : 0x0;

  if (cd->rx_pause_en)
    mode = cd->tx_pause_en ? ROC_NIX_FC_FULL : ROC_NIX_FC_RX;
  else
    mode = cd->tx_pause_en ? ROC_NIX_FC_TX : ROC_NIX_FC_NONE;

  memset (&pfc_cfg, 0, sizeof (struct roc_nix_pfc_cfg));
  pfc_cfg.mode = mode;
  pfc_cfg.tc = cd->class_en;
  return roc_nix_pfc_mode_set (nix, &pfc_cfg);
}

static int
oct_nix_pfc_sq_conf (vnet_dev_port_t *port, uint16_t qid, uint8_t rx_pause,
		     uint8_t tc)
{
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix_pfc_cfg pfc_cfg;
  struct roc_nix *nix = cd->nix;
  struct roc_nix_fc_cfg fc_cfg;
  enum roc_nix_fc_mode mode;
  vnet_dev_tx_queue_t *txq;
  struct roc_nix_sq *sq;
  oct_txq_t *ctq;
  int rc;

  if (port->tx_queues == NULL)
    return -EINVAL;

  if (qid >= port->attr.max_tx_queues)
    return -ENOTSUP;

  /* Check if RX pause frame is enabled or not and
   * confirm user requested for PFC.
   */
  if (!cd->rx_pause_en && rx_pause)
    {
      if ((roc_nix_tm_tree_type_get (nix) == ROC_NIX_TM_DEFAULT) &&
	  port->attr.max_tx_queues > 1)
	{
	  /*
	   * Disabled xmit will be enabled when new topology is available.
	   */
	  rc = roc_nix_tm_hierarchy_disable (nix);
	  if (rc)
	    goto exit;

	  rc = roc_nix_tm_pfc_prepare_tree (nix);
	  if (rc)
	    goto exit;

	  rc = roc_nix_tm_hierarchy_enable (nix, ROC_NIX_TM_PFC, true);
	  if (rc)
	    goto exit;
	}
    }

  txq = vnet_dev_get_port_tx_queue_by_id (port, qid);
  if (txq == 0)
    {
      rc = -ENODEV;
      goto exit;
    }
  ctq = vnet_dev_get_tx_queue_data (txq);
  sq = &ctq->sq;

  memset (&fc_cfg, 0, sizeof (struct roc_nix_fc_cfg));
  fc_cfg.type = ROC_NIX_FC_TM_CFG;
  fc_cfg.tm_cfg.sq = sq->qid;
  fc_cfg.tm_cfg.tc = tc;
  fc_cfg.tm_cfg.enable = !!rx_pause;
  rc = roc_nix_fc_config_set (nix, &fc_cfg);
  if (rc)
    return rc;

  /* Recheck number of SQ's that have PFC enabled */
  cd->rx_pause_en = 0;
  foreach_vnet_dev_port_tx_queue (q, port)
    {
      /* Skip if SQ does not exist */
      if (!q->enabled)
	continue;

      oct_txq_t *ctq2 = vnet_dev_get_tx_queue_data (q);
      sq = &ctq2->sq;
      if (sq->tc != ROC_NIX_PFC_CLASS_INVALID)
	cd->rx_pause_en++;
    }

  if (cd->rx_pause_en > 1)
    goto exit;

  if (cd->tx_pause_en)
    mode = cd->rx_pause_en ? ROC_NIX_FC_FULL : ROC_NIX_FC_TX;
  else
    mode = cd->rx_pause_en ? ROC_NIX_FC_RX : ROC_NIX_FC_NONE;

  memset (&pfc_cfg, 0, sizeof (struct roc_nix_pfc_cfg));
  pfc_cfg.mode = mode;
  pfc_cfg.tc = cd->class_en;
  rc = roc_nix_pfc_mode_set (nix, &pfc_cfg);
exit:
  return rc;
}

static int
oct_pfc_sys_configure (u32 hw_if_idx, pfc_params_t *params)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_dev_port_t *port =
    vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  uint8_t en, tc, mode;
  uint16_t qid;
  int rc = 0;

  if (cd->mode != PFC_ETH_FC_NONE)
    {
      return (int) oct_pfc_roc_err (
	dev, -ENOTSUP,
	"Disable pause frame flow control before configuring PFC");
    }

  if (roc_nix_is_sdp (nix) || roc_nix_is_lbk (nix))
    return (int) oct_pfc_roc_err (dev, -ENOTSUP,
				  "Prio flow ctrl config is not allowed on SDP/LBK");

  /* Disallow flow control changes when device is in started state */
  if (port->started)
    return (int) oct_pfc_roc_err (dev, -EBUSY, "Stop the port=%d for setting PFC",
				  port->port_id);

  mode = params->mode;

  /* Perform Tx pause configuration on RQ */
  qid = params->tx_pause.rxq;
  if (qid < port->attr.max_rx_queues)
    {
      en = (mode == PFC_ETH_FC_FULL) || (mode == PFC_ETH_FC_TX_PAUSE);
      tc = params->tx_pause.tc;
      rc = oct_nix_pfc_rq_conf (port, qid, en, tc);
    }

  /* Perform Rx pause configuration on SQ */
  qid = params->rx_pause.txq;
  if (qid < port->attr.max_tx_queues)
    {
      en = (mode == PFC_ETH_FC_FULL) || (mode == PFC_ETH_FC_RX_PAUSE);
      tc = params->rx_pause.tc;
      rc |= oct_nix_pfc_sq_conf (port, qid, en, tc);
    }

  log_debug (dev, "hw_if_idx %d\n", hw_if_idx);
  log_debug (dev, "mode %x\n", params->mode);
  log_debug (dev, "rx_pause.txq %d\n", params->rx_pause.txq);
  log_debug (dev, "rx_pause.tc %d\n", params->rx_pause.tc);
  log_debug (dev, "tx_pause.pause_time %d\n", params->tx_pause.pause_time);
  log_debug (dev, "tx_pause.rxq %d\n", params->tx_pause.rxq);
  log_debug (dev, "tx_pause.tc %d\n", params->tx_pause.tc);
  return rc;
}

static int
oct_pfc_sys_get_capabilities (u32 hw_if_idx, pfc_capa_params_t *cap)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_dev_port_t *port =
    vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;

  memset (cap, 0, sizeof (*cap));
  cap->tc_max = roc_nix_chan_count_get (nix);
  cap->mode = PFC_ETH_FC_FULL;

  log_debug (dev, "Max TC %d Supported mode %d", cap->tc_max, cap->mode);
  return 0;
}

static int
oct_pfc_sys_disable_pause_frame_flow_ctrl (u32 hw_if_idx, u32 disable)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_dev_port_t *port =
    vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  struct roc_nix_sq *sq;
  struct roc_nix_cq *cq;
  struct roc_nix_rq *rq;
  int rc = 0;

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      struct roc_nix_fc_cfg fc_cfg;

      /* Skip if RQ does not exist */
      if (!q->enabled)
	continue;

      oct_rxq_t *crq = vnet_dev_get_rx_queue_data (q);
      rq = &crq->rq;
      cq = &crq->cq;

      memset (&fc_cfg, 0, sizeof (struct roc_nix_fc_cfg));
      fc_cfg.type = ROC_NIX_FC_RQ_CFG;
      fc_cfg.rq_cfg.rq = rq->qid;
      fc_cfg.rq_cfg.pool = rq->aura_handle;
      fc_cfg.rq_cfg.spb_pool = rq->spb_aura_handle;
      fc_cfg.rq_cfg.cq_drop = cq->drop_thresh;
      fc_cfg.rq_cfg.cq_bp = cq->bp_thresh;
      fc_cfg.rq_cfg.pool_drop_pct = ROC_NIX_AURA_THRESH;

      rc = roc_nix_fc_config_set (nix, &fc_cfg);
      if (rc)
	return (int) oct_pfc_roc_err (
	  dev, rc, "Failed to disable flow control on Rx queue %u", rq->qid);
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      struct roc_nix_fc_cfg fc_cfg;

      /* Skip if SQ does not exist */
      if (!q->enabled)
	continue;

      oct_txq_t *ctq = vnet_dev_get_tx_queue_data (q);
      sq = &ctq->sq;

      memset (&fc_cfg, 0, sizeof (struct roc_nix_fc_cfg));
      fc_cfg.type = ROC_NIX_FC_TM_CFG;
      fc_cfg.tm_cfg.sq = sq->qid;
      rc = roc_nix_fc_config_set (nix, &fc_cfg);
      if (rc && rc != -EEXIST)
	return (int) oct_pfc_roc_err (
	  dev, rc, "Failed to disable flow control on Tx queue %u", sq->qid);
    }

  rc = roc_nix_fc_mode_set (nix, ROC_NIX_FC_NONE);
  if (rc)
    return (int) oct_pfc_roc_err (dev, rc, "Failed to disable flow control on MAC");

  cd->mode = PFC_ETH_FC_NONE;
  (void) disable;
  return rc;
}

static const pfc_system_t oct_pfc_ops_template = {
  .pfc_configure = oct_pfc_sys_configure,
  .pfc_get_capabilities = oct_pfc_sys_get_capabilities,
  .pfc_disable_pause_frame_flow_ctrl =
    oct_pfc_sys_disable_pause_frame_flow_ctrl,
};

int
oct_pfc_sys_init_args (pfc_system_t *pfc)
{
  memset (pfc, 0, sizeof (*pfc));
  memcpy (pfc, &oct_pfc_ops_template, sizeof (*pfc));
  return 0;
}
