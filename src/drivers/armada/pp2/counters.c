/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <vppinfra/ring.h>
#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "pp2-counters",
};

#define foreach_mvpp2_port_counter                                                                 \
  _ (RX_PACKETS, RX_PACKETS (0))                                                                   \
  _ (TX_PACKETS, TX_PACKETS (0))                                                                   \
  _ (RX_DROP_FULLQ, VENDOR (0, NA, PACKETS, "drop fullQ"))                                         \
  _ (RX_DROP_EARLY, VENDOR (0, NA, PACKETS, "drop early"))                                         \
  _ (RX_DROP_BM, VENDOR (0, NA, PACKETS, "drop BM"))                                               \
  _ (RX_CLS_LKP_HIT, VENDOR (0, NA, PACKETS, "cls lkp hit"))                                       \
  _ (RX_CLS_FLOW_HIT, VENDOR (0, NA, PACKETS, "cls flow hit"))                                     \
  _ (RX_CLS4_HIT, VENDOR (0, NA, PACKETS, "cls4 hit"))                                             \
  _ (RX_MC_OVF_DROP, VENDOR (0, NA, PACKETS, "drop MC overflow"))                                  \
  _ (TX_DROP_FULLQ, VENDOR (0, NA, PACKETS, "drop fullQ"))                                         \
  _ (TX_DROP_EARLY, VENDOR (0, NA, PACKETS, "drop early"))                                         \
  _ (TX_DROP_BM, VENDOR (0, NA, PACKETS, "drop BM"))                                               \
  _ (TX_DROP_BM_MC, VENDOR (0, NA, PACKETS, "drop BM MC"))

typedef enum
{
#define _(f, c) MVPP2_PORT_CTR_##f,
  foreach_mvpp2_port_counter
#undef _
} mvpp2_port_counter_id_t;

typedef enum
{
  MVPP2_RXQ_CTR_ENQ_DESC,
  MVPP2_RXQ_CTR_DROP_FULLQ,
  MVPP2_RXQ_CTR_DROP_EARLY,
  MVPP2_RXQ_CTR_DROP_BM,
  MVPP2_RXQ_CTR_CLS_LKP_HIT,
  MVPP2_RXQ_CTR_CLS_FLOW_HIT,
  MVPP2_RXQ_CTR_CLS4_HIT,
  MVPP2_RXQ_CTR_MC_OVF_DROP,
} mvpp2_rxq_counter_id_t;

typedef enum
{
  MVPP2_TXQ_CTR_ENQ_DESC,
  MVPP2_TXQ_CTR_ENQ_DEC_TO_DDR,
  MVPP2_TXQ_CTR_ENQ_BUF_TO_DDR,
  MVPP2_TXQ_CTR_DEQ_DESC,
  MVPP2_TXQ_CTR_DROP_FULLQ,
  MVPP2_TXQ_CTR_DROP_EARLY,
  MVPP2_TXQ_CTR_DROP_BM,
  MVPP2_TXQ_CTR_DROP_BM_MC,
} mvpp2_txq_counter_id_t;

static vnet_dev_counter_t mvpp2_port_counters[] = {
#define _(f, c) [MVPP2_PORT_CTR_##f] = VNET_DEV_CTR_##c,
  foreach_mvpp2_port_counter
#undef _
};

static vnet_dev_counter_t mvpp2_rxq_counters[] = {
  [MVPP2_RXQ_CTR_ENQ_DESC] = VNET_DEV_CTR_VENDOR (0, NA, DESCRIPTORS, "enqueued"),
  [MVPP2_RXQ_CTR_DROP_FULLQ] = VNET_DEV_CTR_VENDOR (0, NA, PACKETS, "drop fullQ"),
  [MVPP2_RXQ_CTR_DROP_EARLY] = VNET_DEV_CTR_VENDOR (0, NA, PACKETS, "drop early"),
  [MVPP2_RXQ_CTR_DROP_BM] = VNET_DEV_CTR_VENDOR (0, NA, PACKETS, "drop BM"),
  [MVPP2_RXQ_CTR_CLS_LKP_HIT] = VNET_DEV_CTR_VENDOR (0, NA, PACKETS, "cls lkp hit"),
  [MVPP2_RXQ_CTR_CLS_FLOW_HIT] = VNET_DEV_CTR_VENDOR (0, NA, PACKETS, "cls flow hit"),
  [MVPP2_RXQ_CTR_CLS4_HIT] = VNET_DEV_CTR_VENDOR (0, NA, PACKETS, "cls4 hit"),
  [MVPP2_RXQ_CTR_MC_OVF_DROP] = VNET_DEV_CTR_VENDOR (0, NA, PACKETS, "drop MC overflow"),
};

static vnet_dev_counter_t mvpp2_txq_counters[] = {
  [MVPP2_TXQ_CTR_ENQ_DESC] = VNET_DEV_CTR_VENDOR (0, NA, DESCRIPTORS, "enqueued"),
  [MVPP2_TXQ_CTR_ENQ_DEC_TO_DDR] = VNET_DEV_CTR_VENDOR (0, NA, DESCRIPTORS, "enq to DDR"),
  [MVPP2_TXQ_CTR_ENQ_BUF_TO_DDR] = VNET_DEV_CTR_VENDOR (0, NA, BUFFERS, "enq to DDR"),
  [MVPP2_TXQ_CTR_DEQ_DESC] = VNET_DEV_CTR_VENDOR (0, NA, PACKETS, "dequeued"),
  [MVPP2_TXQ_CTR_DROP_FULLQ] = VNET_DEV_CTR_VENDOR (0, NA, PACKETS, "drop fullQ"),
  [MVPP2_TXQ_CTR_DROP_EARLY] = VNET_DEV_CTR_VENDOR (0, NA, PACKETS, "drop early"),
  [MVPP2_TXQ_CTR_DROP_BM] = VNET_DEV_CTR_VENDOR (0, NA, PACKETS, "drop BM"),
  [MVPP2_TXQ_CTR_DROP_BM_MC] = VNET_DEV_CTR_VENDOR (0, NA, PACKETS, "drop BM MC"),
};

static_always_inline void
mvpp2_port_counter_add (vlib_main_t *vm, vnet_dev_port_t *port, u32 index, u64 v)
{
  vnet_dev_counter_t *c = vnet_dev_port_get_counter_by_index (vm, port, index);

  vnet_dev_counter_value_add (vm, c, v);
}

static void
mvpp2_rxq_update_counters (vlib_main_t *vm, vnet_dev_rx_queue_t *q)
{
  vnet_dev_port_t *port = q->port;
  vnet_dev_t *dev = port->dev;
  mvpp2_rxq_t *mrq = vnet_dev_get_rx_queue_data (q);
  u64 v;
  vnet_dev_counter_t *c;

  mvpp2_dev_reg_wr_relax (dev, MVPP2_CNT_IDX_REG, mrq->hw_id);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_RX_DESC_ENQ_REG);
  c = vnet_dev_rx_queue_get_counter_by_index (vm, q, MVPP2_RXQ_CTR_ENQ_DESC);
  vnet_dev_counter_value_add (vm, c, v);
  mvpp2_port_counter_add (vm, port, MVPP2_PORT_CTR_RX_PACKETS, v);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_RX_PKT_BM_DROP_REG);
  c = vnet_dev_rx_queue_get_counter_by_index (vm, q, MVPP2_RXQ_CTR_DROP_BM);
  vnet_dev_counter_value_add (vm, c, v);
  mvpp2_port_counter_add (vm, port, MVPP2_PORT_CTR_RX_DROP_BM, v);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_RX_PKT_EARLY_DROP_REG);
  c = vnet_dev_rx_queue_get_counter_by_index (vm, q, MVPP2_RXQ_CTR_DROP_EARLY);
  vnet_dev_counter_value_add (vm, c, v);
  mvpp2_port_counter_add (vm, port, MVPP2_PORT_CTR_RX_DROP_EARLY, v);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_RX_PKT_FULLQ_DROP_REG);
  c = vnet_dev_rx_queue_get_counter_by_index (vm, q, MVPP2_RXQ_CTR_DROP_FULLQ);
  vnet_dev_counter_value_add (vm, c, v);
  mvpp2_port_counter_add (vm, port, MVPP2_PORT_CTR_RX_DROP_FULLQ, v);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_CLS_LKP_TBL_HIT_REG);
  c = vnet_dev_rx_queue_get_counter_by_index (vm, q, MVPP2_RXQ_CTR_CLS_LKP_HIT);
  vnet_dev_counter_value_add (vm, c, v);
  mvpp2_port_counter_add (vm, port, MVPP2_PORT_CTR_RX_CLS_LKP_HIT, v);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_CLS_FLOW_TBL_HIT_REG);
  c = vnet_dev_rx_queue_get_counter_by_index (vm, q, MVPP2_RXQ_CTR_CLS_FLOW_HIT);
  vnet_dev_counter_value_add (vm, c, v);
  mvpp2_port_counter_add (vm, port, MVPP2_PORT_CTR_RX_CLS_FLOW_HIT, v);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_CLS4_TBL_HIT_REG);
  c = vnet_dev_rx_queue_get_counter_by_index (vm, q, MVPP2_RXQ_CTR_CLS4_HIT);
  vnet_dev_counter_value_add (vm, c, v);
  mvpp2_port_counter_add (vm, port, MVPP2_PORT_CTR_RX_CLS4_HIT, v);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_MC_OVF_DROP_REG);
  c = vnet_dev_rx_queue_get_counter_by_index (vm, q, MVPP2_RXQ_CTR_MC_OVF_DROP);
  vnet_dev_counter_value_add (vm, c, v);
  mvpp2_port_counter_add (vm, port, MVPP2_PORT_CTR_RX_MC_OVF_DROP, v);
}

static void
mvpp2_txq_update_counters (vlib_main_t *vm, vnet_dev_tx_queue_t *q)
{
  vnet_dev_port_t *port = q->port;
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u64 v;
  vnet_dev_counter_t *c;

  mvpp2_dev_reg_wr_relax (dev, MVPP2_CNT_IDX_REG, MVPP2_CNT_IDX_TX (mp->id, q->queue_id));

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_TX_DESC_ENQ_REG);
  c = vnet_dev_tx_queue_get_counter_by_index (vm, q, MVPP2_TXQ_CTR_ENQ_DESC);
  vnet_dev_counter_value_add (vm, c, v);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_TX_PKT_DQ_REG);
  c = vnet_dev_tx_queue_get_counter_by_index (vm, q, MVPP2_TXQ_CTR_DEQ_DESC);
  vnet_dev_counter_value_add (vm, c, v);
  mvpp2_port_counter_add (vm, port, MVPP2_PORT_CTR_TX_PACKETS, v);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_TX_BUF_ENQ_TO_DRAM_REG);
  c = vnet_dev_tx_queue_get_counter_by_index (vm, q, MVPP2_TXQ_CTR_ENQ_BUF_TO_DDR);
  vnet_dev_counter_value_add (vm, c, v);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_TX_DESC_ENQ_TO_DRAM_REG);
  c = vnet_dev_tx_queue_get_counter_by_index (vm, q, MVPP2_TXQ_CTR_ENQ_DEC_TO_DDR);
  vnet_dev_counter_value_add (vm, c, v);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_TX_PKT_FULLQ_DROP_REG);
  c = vnet_dev_tx_queue_get_counter_by_index (vm, q, MVPP2_TXQ_CTR_DROP_FULLQ);
  vnet_dev_counter_value_add (vm, c, v);
  mvpp2_port_counter_add (vm, port, MVPP2_PORT_CTR_TX_DROP_FULLQ, v);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_TX_PKT_EARLY_DROP_REG);
  c = vnet_dev_tx_queue_get_counter_by_index (vm, q, MVPP2_TXQ_CTR_DROP_EARLY);
  vnet_dev_counter_value_add (vm, c, v);
  mvpp2_port_counter_add (vm, port, MVPP2_PORT_CTR_TX_DROP_EARLY, v);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_TX_PKT_BM_DROP_REG);
  c = vnet_dev_tx_queue_get_counter_by_index (vm, q, MVPP2_TXQ_CTR_DROP_BM);
  vnet_dev_counter_value_add (vm, c, v);
  mvpp2_port_counter_add (vm, port, MVPP2_PORT_CTR_TX_DROP_BM, v);

  v = mvpp2_dev_reg_rd_relax (dev, MVPP2_TX_PKT_BM_MC_DROP_REG);
  c = vnet_dev_tx_queue_get_counter_by_index (vm, q, MVPP2_TXQ_CTR_DROP_BM_MC);
  vnet_dev_counter_value_add (vm, c, v);
  mvpp2_port_counter_add (vm, port, MVPP2_PORT_CTR_TX_DROP_BM_MC, v);
}

void
mvpp2_port_add_counters (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_port_add_counters (vm, port, mvpp2_port_counters,
			      ARRAY_LEN (mvpp2_port_counters));

  foreach_vnet_dev_port_rx_queue (q, port)
    vnet_dev_rx_queue_add_counters (vm, q, mvpp2_rxq_counters,
				    ARRAY_LEN (mvpp2_rxq_counters));

  foreach_vnet_dev_port_tx_queue (q, port)
    vnet_dev_tx_queue_add_counters (vm, q, mvpp2_txq_counters,
				    ARRAY_LEN (mvpp2_txq_counters));
}

void
mvpp2_port_clear_counters (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_get_stats (vm, port);
  if (port->counter_main)
    vnet_dev_counters_clear (vm, port->counter_main);
}

void
mvpp2_rxq_clear_counters (vlib_main_t *vm, vnet_dev_rx_queue_t *q)
{
  mvpp2_rxq_update_counters (vm, q);
  vnet_dev_counters_clear (vm, q->counter_main);
}

void
mvpp2_txq_clear_counters (vlib_main_t *vm, vnet_dev_tx_queue_t *q)
{
  mvpp2_txq_update_counters (vm, q);
  vnet_dev_counters_clear (vm, q->counter_main);
}

vnet_dev_rv_t
mvpp2_port_get_stats (vlib_main_t *vm, vnet_dev_port_t *port)
{
  foreach_vnet_dev_port_rx_queue (q, port)
    mvpp2_rxq_update_counters (vm, q);

  foreach_vnet_dev_port_tx_queue (q, port)
    mvpp2_txq_update_counters (vm, q);

  return VNET_DEV_OK;
}

void
mvpp2_port_counters_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_get_stats (vm, port);
  if (port->counter_main)
    vnet_dev_counters_clear (vm, port->counter_main);

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->counter_main)
      vnet_dev_counters_clear (vm, q->counter_main);

  foreach_vnet_dev_port_tx_queue (q, port)
    if (q->counter_main)
      vnet_dev_counters_clear (vm, q->counter_main);
}
