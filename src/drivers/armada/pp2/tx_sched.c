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

static u8
mvpp2_tx_sched_rational_weight_remap (u32 weight, u32 min, u32 max)
{
  /* The solution for minimum weight of 1 contains square roots, but doesn't for minimum weight of
   * 0, so we offset the parameters by -1 and offset the result back.
   */
  weight -= 1;
  min -= 1;
  max -= 1;
  return ((min * max * max + min - max) * weight + min * max * (max - 1)) /
	   ((min * max + min - max) * weight + max * (max - 1)) +
	 1;
}

static vnet_dev_rv_t
mvpp2_tx_sched_queue_fixed_prio_set (vnet_dev_tx_queue_t *q)
{
  vnet_dev_port_t *port = q->port;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 reg_val;
  int tx_port_num;

  tx_port_num = MVPP2_TX_PORT_NUM (mp->id);
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);

  reg_val = mvpp2_reg_read (mp->hif_base, MVPP2_TXP_SCHED_FIXED_PRIO_REG);
  reg_val |= 1 << q->queue_id;
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_FIXED_PRIO_REG, reg_val);

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
mvpp2_tx_sched_queue_wrr_set (vnet_dev_tx_queue_t *q, u8 weight)
{
  vnet_dev_port_t *port = q->port;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 txq = q->queue_id;
  u32 reg_val;
  int tx_port_num;

  tx_port_num = MVPP2_TX_PORT_NUM (mp->id);
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);

  reg_val = mvpp2_reg_read (mp->hif_base, MVPP2_TXQ_SCHED_WRR_REG (txq));
  reg_val &= ~MVPP2_TXQ_WRR_WEIGHT_ALL_MASK;
  reg_val |= MVPP2_TXQ_WRR_WEIGHT_MASK (weight);
  mvpp2_reg_write (mp->hif_base, MVPP2_TXQ_SCHED_WRR_REG (txq), reg_val);

  reg_val = mvpp2_reg_read (mp->hif_base, MVPP2_TXP_SCHED_FIXED_PRIO_REG);
  reg_val &= ~(1 << txq);
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_FIXED_PRIO_REG, reg_val);

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
mvpp2_tx_sched_queue_arbitration_set (vnet_dev_tx_queue_t *q, enum mvpp2_txq_sched_mode mode,
				      u8 weight)
{
  vnet_dev_port_t *port = q->port;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  if (mode == MVPP2_TXQ_SCHED_WRR)
    return mvpp2_tx_sched_queue_wrr_set (q, weight);

  if (mode == MVPP2_TXQ_SCHED_SP)
    return mvpp2_tx_sched_queue_fixed_prio_set (q);

  log_err (port->dev, "Invalid egress arbitration mode on p%dq%d: %d", mp->id, q->queue_id, mode);
  return VNET_DEV_ERR_INVALID_ARG;
}

static void
mvpp2_tx_sched_remap_weights (vnet_dev_port_t *port, u8 remapped_weights[])
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 hw_min, user_min = 0xff, user_max = 0;
  u32 mtu;
  int tx_port_num;
  int accommodating_dynamic_range; /* Can user requested range be met after MTU restriction */

  tx_port_num = MVPP2_TX_PORT_NUM (mp->id);
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);

  /* Weight * 256 bytes * 8 bits must be larger then MTU [bits] */
  mtu = mvpp2_reg_read (mp->hif_base, MVPP2_TXP_SCHED_MTU_REG);
  mtu /= PP2_AMPLIFY_FACTOR_MTU;
  mtu /= 8; /* move to bytes */
  mtu = ALIGN (mtu, PP2_WRR_WEIGHT_UNIT);
  hw_min = mtu / PP2_WRR_WEIGHT_UNIT;

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      u32 txq = q->queue_id;

      if (mp->txq_config[txq].sched_mode == MVPP2_TXQ_SCHED_WRR)
	{
	  if (mp->txq_config[txq].weight == 0)
	    mp->txq_config[txq].weight = 1;

	  if (mp->txq_config[txq].weight > user_max)
	    user_max = mp->txq_config[txq].weight;

	  if (mp->txq_config[txq].weight < user_min)
	    user_min = mp->txq_config[txq].weight;
	}
    }

  if (user_min > user_max) /* WRR unused */
    return;

  if ((user_max / user_min) < (MVPP2_TXQ_WRR_WEIGHT_MAX / hw_min))
    accommodating_dynamic_range = 1;
  else
    accommodating_dynamic_range = 0;

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      u32 txq = q->queue_id;

      if (mp->txq_config[txq].sched_mode == MVPP2_TXQ_SCHED_WRR)
	{
	  if (accommodating_dynamic_range)
	    remapped_weights[txq] = mp->txq_config[txq].weight * hw_min / user_min;
	  else
	    remapped_weights[txq] = mvpp2_tx_sched_rational_weight_remap (
	      mp->txq_config[txq].weight, hw_min, MVPP2_TXQ_WRR_WEIGHT_MAX);
	}
    }
}

static void
mvpp2_tx_sched_mtu_set (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 val, mtu;
  u32 tx_port_num;

  mtu = port->max_rx_frame_size * 8;

  /* WA for wrong Token bucket update: Set MTU value = 3*real MTU value */
  mtu = 3 * mtu;

  if (mtu > MVPP2_TXP_MTU_MAX)
    mtu = MVPP2_TXP_MTU_MAX;

  /* Indirect access to registers */
  tx_port_num = MVPP2_TX_PORT_NUM (mp->id);
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);

  /* Set MTU */
  val = mvpp2_reg_read (mp->hif_base, MVPP2_TXP_SCHED_MTU_REG);
  val &= ~MVPP2_TXP_MTU_MAX;
  val |= mtu;
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_MTU_REG, val);
}

vnet_dev_rv_t
mvpp2_tx_sched_config (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 n_tx_queues = 0;
  vnet_dev_rv_t rv;
  u32 reg_val;
  u8 remapped_weights[MVPP2_MAX_TXQ];

  /* Set port MTU (which is used later in the initialization) */
  mvpp2_tx_sched_mtu_set (port);

  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, MVPP2_TX_PORT_NUM (mp->id));

  reg_val = mvpp2_reg_read (mp->hif_base, MVPP2_TXP_SCHED_REFILL_REG);
  reg_val &= ~(MVPP2_TXP_REFILL_TOKENS_ALL_MASK | MVPP2_TXP_REFILL_PERIOD_ALL_MASK);
  reg_val |= MVPP2_TXP_REFILL_TOKENS_MASK (MVPP2_TXP_REFILL_TOKENS_MAX);
  reg_val |= MVPP2_TXP_REFILL_PERIOD_MASK (MVPP2_TXP_REFILL_PERIOD_MIN);
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_REFILL_REG, reg_val);
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_TOKEN_SIZE_REG,
		   MVPP2_TXP_MAX_CONFIGURABLE_BUCKET_SIZE);

  mvpp2_tx_sched_remap_weights (port, remapped_weights);

  foreach_vnet_dev_port_tx_queue (q, port)
    n_tx_queues++;

  /* Set TXQ scheduler defaults, arbitration mode and WRR weight. */
  foreach_vnet_dev_port_tx_queue (q, port)
    { /* This only works in logical ports post reprioritization */
      u32 txq = q->queue_id;

      reg_val = mvpp2_reg_read (mp->hif_base, MVPP2_TXQ_SCHED_REFILL_REG (txq));
      reg_val &= ~(MVPP2_TXQ_REFILL_TOKENS_ALL_MASK | MVPP2_TXQ_REFILL_PERIOD_ALL_MASK);
      reg_val |= MVPP2_TXQ_REFILL_TOKENS_MASK (MVPP2_TXQ_REFILL_TOKENS_MAX);
      reg_val |= MVPP2_TXQ_REFILL_PERIOD_MASK (MVPP2_TXQ_REFILL_PERIOD_MIN);
      mvpp2_reg_write (mp->hif_base, MVPP2_TXQ_SCHED_REFILL_REG (txq), reg_val);
      mvpp2_reg_write (mp->hif_base, MVPP2_TXQ_SCHED_TOKEN_SIZE_REG (txq),
		       MVPP2_TXQ_MAX_CONFIGURABLE_BUCKET_SIZE);

      if (n_tx_queues > 1)
	{
	  rv = mvpp2_tx_sched_queue_arbitration_set (q, mp->txq_config[txq].sched_mode,
						     remapped_weights[txq]);
	  if (rv != VNET_DEV_OK)
	    return rv;
	}
    }

  return VNET_DEV_OK;
}
