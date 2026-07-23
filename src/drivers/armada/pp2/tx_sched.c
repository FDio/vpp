/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vppinfra/clib.h>

#include <pp2/pp2.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "tx-sched",
};

static void
mvpp2_tx_sched_queue_wrr_set (vnet_dev_tx_queue_t *q, u8 weight)
{
  vnet_dev_port_t *port = q->port;
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);
  mvpp22_txp_sched_port_index_reg_t port_index = {
    .index = MVPP2_MAX_TCONT + mp->id,
  };
  u32 reg_val;

  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PORT_INDEX_REG, port_index.as_u32);

  reg_val = mvpp2_dev_reg_rd (dev, MVPP2_TXQ_SCHED_WRR_REG (txq->hw_id));
  reg_val &= ~MVPP2_TXQ_WRR_WEIGHT_ALL_MASK;
  reg_val |= MVPP2_TXQ_WRR_WEIGHT_MASK (weight);
  mvpp2_dev_reg_wr (dev, MVPP2_TXQ_SCHED_WRR_REG (txq->hw_id), reg_val);

  reg_val = mvpp2_dev_reg_rd (dev, MVPP2_TXP_SCHED_FIXED_PRIO_REG);
  reg_val &= ~(1 << q->queue_id);
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_FIXED_PRIO_REG, reg_val);
}

static u8
mvpp2_tx_sched_get_min_weight (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp22_txp_sched_port_index_reg_t port_index = {
    .index = MVPP2_MAX_TCONT + mp->id,
  };
  u32 mtu;

  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PORT_INDEX_REG, port_index.as_u32);

  /* Weight * 256 bytes * 8 bits must be larger then MTU [bits] */
  mtu = mvpp2_dev_reg_rd (dev, MVPP2_TXP_SCHED_MTU_REG);
  mtu /= PP2_AMPLIFY_FACTOR_MTU;
  mtu /= 8; /* move to bytes */
  mtu = ALIGN (mtu, PP2_WRR_WEIGHT_UNIT);
  return mtu / PP2_WRR_WEIGHT_UNIT;
}

static void
mvpp2_tx_sched_mtu_set (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp22_txp_sched_port_index_reg_t port_index = {
    .index = MVPP2_MAX_TCONT + mp->id,
  };
  u32 val, mtu;

  mtu = port->max_rx_frame_size * 8;

  /* WA for wrong Token bucket update: Set MTU value = 3*real MTU value */
  mtu = 3 * mtu;

  if (mtu > MVPP2_TXP_MTU_MAX)
    mtu = MVPP2_TXP_MTU_MAX;

  /* Indirect access to registers */
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PORT_INDEX_REG, port_index.as_u32);

  /* Set MTU */
  val = mvpp2_dev_reg_rd (dev, MVPP2_TXP_SCHED_MTU_REG);
  val &= ~MVPP2_TXP_MTU_MAX;
  val |= mtu;
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_MTU_REG, val);
}

vnet_dev_rv_t
mvpp2_tx_sched_config (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp22_txp_sched_port_index_reg_t port_index = {
    .index = MVPP2_MAX_TCONT + mp->id,
  };
  mvpp22_txp_sched_refill_reg_t refill;
  u8 weight;

  /* Set port MTU (which is used later in the initialization) */
  mvpp2_tx_sched_mtu_set (port);

  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PORT_INDEX_REG, port_index.as_u32);

  refill.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_TXP_SCHED_REFILL_REG);
  refill.tokens = MVPP2_TXP_REFILL_TOKENS_MAX;
  refill.period = MVPP2_TXP_REFILL_PERIOD_MIN;
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_REFILL_REG, refill.as_u32);
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_TOKEN_SIZE_REG, MVPP2_TXP_MAX_CONFIGURABLE_BUCKET_SIZE);

  weight = mvpp2_tx_sched_get_min_weight (port);

  /* Set TXQ scheduler defaults, arbitration mode and WRR weight. */
  foreach_vnet_dev_port_tx_queue (q, port)
    { /* This only works in logical ports post reprioritization */
      mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);
      mvpp22_txq_sched_refill_reg_t refill;

      refill.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_TXQ_SCHED_REFILL_REG (txq->hw_id));
      refill.tokens = MVPP2_TXQ_REFILL_TOKENS_MAX;
      refill.period = MVPP2_TXQ_REFILL_PERIOD_MIN;
      mvpp2_dev_reg_wr (dev, MVPP2_TXQ_SCHED_REFILL_REG (txq->hw_id), refill.as_u32);
      mvpp2_dev_reg_wr (dev, MVPP2_TXQ_SCHED_TOKEN_SIZE_REG (txq->hw_id),
			MVPP2_TXQ_MAX_CONFIGURABLE_BUCKET_SIZE);

      if (vnet_dev_get_port_num_tx_queues (port) > 1)
	mvpp2_tx_sched_queue_wrr_set (q, weight);
    }

  return VNET_DEV_OK;
}
