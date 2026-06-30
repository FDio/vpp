/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <pp2/pp2.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "rss",
};

static void
mvpp2_rss_rxqs_set (vnet_dev_port_t *port, u8 table_id)
{
  vnet_dev_t *dev = port->dev;

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
      mvpp22_rss_idx_reg_t index = {
	.rxq_num = rxq->hw_id,
      };

      mvpp2_dev_reg_wr (dev, MVPP22_RSS_IDX_REG, index.as_u32);
      mvpp2_dev_reg_wr (dev, MVPP22_RSS_RXQ2RSS_TBL_REG, table_id);
      log_debug (dev, "rxq %u uses RSS table %u", rxq->hw_id, table_id);
    }
}

static void
mvpp2_rss_table_set (vnet_dev_port_t *port, u8 table_id)
{
  vnet_dev_t *dev = port->dev;
  u32 n_rx_queues = vnet_dev_get_port_num_rx_queues (port);
  u8 width = max_log2 (n_rx_queues);

  log_debug (dev, "program RSS table %u with %u queues, width %u", table_id, n_rx_queues, width);

  for (u32 line = 0; line < MVPP22_RSS_TBL_LINE_NUM; line++)
    {
      mvpp22_rss_idx_reg_t index = {
	.entry_num = line,
	.table_num = table_id,
      };

      mvpp2_dev_reg_wr (dev, MVPP22_RSS_IDX_REG, index.as_u32);
      mvpp2_dev_reg_wr (dev, MVPP22_RSS_TBL_ENTRY_REG, line % n_rx_queues);
      mvpp2_dev_reg_wr (dev, MVPP22_RSS_WIDTH_REG, width);
    }
}

void
mvpp2_rss_port_init (vnet_dev_port_t *port, enum mvpp2_port_hash_type hash_type)
{
  u32 n_rx_queues = vnet_dev_get_port_num_rx_queues (port);
  u8 table_id = mvpp2_port_id (port);
  u8 enable = hash_type != MVPP2_PORT_HASH_NONE && n_rx_queues > 1;

  ASSERT (table_id < MVPP22_RSS_TBL_NUM);

  if (enable)
    {
      mvpp2_rss_rxqs_set (port, table_id);
      mvpp2_rss_table_set (port, table_id);
    }

  if (mvpp2_cls_rss_enable (port, enable))
    log_err (port->dev, "cannot %s RSS", enable ? "enable" : "disable");
}
