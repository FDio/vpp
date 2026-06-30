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
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int val;

  val = (mp->id << MVPP22_ISR_RXQ_GROUP_INDEX_GROUP_OFFSET) | sub_group;
  mvpp2_reg_write (mp->hif_base, MVPP22_ISR_RXQ_GROUP_INDEX_REG, val);

  return mvpp2_reg_read (mp->hif_base, MVPP22_ISR_RXQ_SUB_GROUP_CONFIG_REG);
}

static_always_inline void
mvpp2_port_isr_rx_group_write (vnet_dev_port_t *port, int sub_group, int start_queue,
			       int num_rx_queues)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int val;

  val = (mp->id << MVPP22_ISR_RXQ_GROUP_INDEX_GROUP_OFFSET) | sub_group;
  mvpp2_reg_write (mp->hif_base, MVPP22_ISR_RXQ_GROUP_INDEX_REG, val);

  val = (num_rx_queues << MVPP22_ISR_RXQ_SUB_GROUP_SIZE_OFFSET) | start_queue;
  mvpp2_reg_write (mp->hif_base, MVPP22_ISR_RXQ_SUB_GROUP_CONFIG_REG, val);
}

void
mvpp2_port_clear_fc_isr (vnet_dev_port_t *port)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int hif_id;
  uintptr_t hif_base;

  for (hif_id = 0; hif_id < PP2_MAX_NUM_USED_INTERRUPTS; hif_id++)
    {
      /* Configure Group/Subgroup */
      mp->saved_rx_isr[hif_id] = mvpp2_port_isr_rx_group_read (port, hif_id);
      mvpp2_port_isr_rx_group_write (port, hif_id, 0, 0);

      hif_base = mvpp2_hif_base (md, hif_id);

      /* Configure RX Exceptions Interrupt Mask */
      mvpp2_reg_write (hif_base, MVPP2_RX_EX_INT_CAUSE_MASK_REG (mp->id), 0);
    }
}

void
mvpp2_port_interrupts_disable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  u32 mask = 0;

  foreach_vnet_dev_port_rx_queue (q, port)
    mask |= 1 << md->threads[q->rx_thread_index].hif_id;

  mvpp2_reg_write (mp->hif_base, MVPP2_ISR_ENABLE_REG (mp->id), MVPP2_ISR_DISABLE_INTERRUPT (mask));
}

void
mvpp2_port_rxqs_fc_state_reset (vnet_dev_port_t *port)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  int cm3_state;
  u32 val;

  /* Remove Flow control enable bit to prevent race between FW and Kernel
   * If Flow control were enabled, it would be re-enabled.
   */
  val = mvpp2_reg_read (md->cm3_base, MSS_CP_FC_COM_REG);
  cm3_state = val & FLOW_CONTROL_ENABLE_BIT;
  val &= ~FLOW_CONTROL_ENABLE_BIT;
  mvpp2_reg_write (md->cm3_base, MSS_CP_FC_COM_REG, val);

  /* Notify Firmware that Flow control config space ready for update */
  val = mvpp2_reg_read (md->cm3_base, MSS_CP_FC_COM_REG);
  val |= FLOW_CONTROL_UPD_COM_BIT;
  val |= cm3_state;
  mvpp2_reg_write (md->cm3_base, MSS_CP_FC_COM_REG, val);
}

void
mvpp2_port_restore_fc_isr (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int hif_id, start_queue, num_rx_queues;

  for (hif_id = 0; hif_id < PP2_MAX_NUM_USED_INTERRUPTS; hif_id++)
    {
      /* Configure Group/Subgroup */
      start_queue = mp->saved_rx_isr[hif_id] & MVPP22_ISR_RXQ_SUB_GROUP_STARTQ_MASK;
      num_rx_queues = (mp->saved_rx_isr[hif_id] & MVPP22_ISR_RXQ_SUB_GROUP_SIZE_MASK) >>
		      MVPP22_ISR_RXQ_SUB_GROUP_SIZE_OFFSET;

      mvpp2_port_isr_rx_group_write (port, hif_id, start_queue, num_rx_queues);
    }
}
