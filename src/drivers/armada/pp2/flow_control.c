/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <pp2/pp2.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "flow-control",
};

static_always_inline u32
mvpp2_port_isr_rx_group_read (vnet_dev_port_t *port, int sub_group)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp22_isr_rxq_group_index_reg_t index = {
    .sub_group = sub_group,
    .group = mp->id,
  };

  mvpp2_dev_reg_wr (dev, MVPP22_ISR_RXQ_GROUP_INDEX_REG, index.as_u32);

  return mvpp2_dev_reg_rd (dev, MVPP22_ISR_RXQ_SUB_GROUP_CONFIG_REG);
}

static_always_inline void
mvpp2_port_isr_rx_group_write (vnet_dev_port_t *port, int sub_group, int start_queue,
			       int num_rx_queues)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp22_isr_rxq_group_index_reg_t index = {
    .sub_group = sub_group,
    .group = mp->id,
  };
  mvpp22_isr_rxq_sub_group_config_reg_t config = {
    .start_queue = start_queue,
    .size = num_rx_queues,
  };

  mvpp2_dev_reg_wr (dev, MVPP22_ISR_RXQ_GROUP_INDEX_REG, index.as_u32);
  mvpp2_dev_reg_wr (dev, MVPP22_ISR_RXQ_SUB_GROUP_CONFIG_REG, config.as_u32);
}

void
mvpp2_port_clear_fc_isr (vnet_dev_port_t *port)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_hif_t *hif;
  u32 thread_index;

  for (thread_index = 0; thread_index < ARRAY_LEN (md->threads); thread_index++)
    {
      mvpp22_isr_rxq_sub_group_config_reg_t saved;

      hif = &md->threads[thread_index].hif;
      if (!hif->descs)
	continue;

      /* Configure Group/Subgroup */
      mp->saved_rx_isr[thread_index] = mvpp2_port_isr_rx_group_read (port, hif->id);
      saved.as_u32 = mp->saved_rx_isr[thread_index];
      mvpp2_port_isr_rx_group_write (port, hif->id, 0, 0);

      /* Configure RX Exceptions Interrupt Mask */
      mvpp2_hif_reg_wr (hif, MVPP2_RX_EX_INT_CAUSE_MASK_REG (mp->id), 0);
      log_debug (port->dev, "port %u HIF %u saved RX interrupt group start %u size %u", mp->id,
		 hif->id, saved.start_queue, saved.size);
    }
}

void
mvpp2_port_interrupts_disable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp22_isr_enable_reg_t interrupts = {};
  u32 mask = 0;

  foreach_vnet_dev_port_rx_queue (q, port)
    mask |= 1 << md->threads[q->rx_thread_index].hif.id;

  interrupts.disable = mask;
  mvpp2_dev_reg_wr (port->dev, MVPP2_ISR_ENABLE_REG (mp->id), interrupts.as_u32);
  log_debug (port->dev, "port %u disabled interrupts for HIF mask 0x%x", mp->id, mask);
}

void
mvpp2_port_restore_fc_isr (vnet_dev_port_t *port)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_hif_t *hif;
  int start_queue, num_rx_queues;
  u32 thread_index;

  for (thread_index = 0; thread_index < ARRAY_LEN (md->threads); thread_index++)
    {
      mvpp22_isr_rxq_sub_group_config_reg_t config = {
	.as_u32 = mp->saved_rx_isr[thread_index],
      };

      hif = &md->threads[thread_index].hif;
      if (!hif->descs)
	continue;

      /* Configure Group/Subgroup */
      start_queue = config.start_queue;
      num_rx_queues = config.size;

      mvpp2_port_isr_rx_group_write (port, hif->id, start_queue, num_rx_queues);
      log_debug (port->dev, "port %u HIF %u restored RX interrupt group start %u size %u", mp->id,
		 hif->id, start_queue, num_rx_queues);
    }
}
