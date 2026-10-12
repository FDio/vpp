/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/format_table.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

#define HPPE_REG_ENQ_OPR(queue)	    (0x85c000 + 0x10 * (queue))
#define HPPE_REG_DEQ_OPR(queue)	    (0x430000 + 0x10 * (queue))
#define HPPE_REG_EG_BRIDGE_CONFIG   0x20044
#define HPPE_QM_GROUP0_BUF_LIMIT    2000
#define HPPE_QM_UCAST_CEIL	    1200
#define HPPE_QM_UCAST_WEIGHT	    7
#define HPPE_QM_UCAST_RESUME_OFFSET 36
#define HPPE_QM_MCAST_CEIL	    250
#define HPPE_QM_MCAST_RESUME_OFFSET 36

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "qm",
};

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, qppe_log.class, "%U" f, format_vnet_dev_log, (dev),              \
	    clib_string_skip_prefix (__func__, "qppe_"), ##__VA_ARGS__)

/* QM (Queue Manager) admission control is independent of BM's per-port
 * admission control. Both operate on the shared PPE buffer pool. */
vnet_dev_rv_t
qppe_qm_init (vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  ppe_reg_ac_grp_cfg_w1_t ac_grp_w1 = { .buf_limit = HPPE_QM_GROUP0_BUF_LIMIT };
  ppe_reg_eg_bridge_config_t eg_bridge_config;
  u32 offset, queue;

  {
    u32 base = HPPE_REG_AC_GRP_CFG_W0 (0);
    u32 words[3];

    for (u32 w = 0; w < ARRAY_LEN (words); w++)
      words[w] = qppe_mmio_read32 (qd, base + 4 * w);
    words[1] = ac_grp_w1.as_u32;
    for (u32 w = 0; w < ARRAY_LEN (words); w++)
      qppe_mmio_write32 (qd, base + 4 * w, words[w]);
    for (u32 w = 0; w < ARRAY_LEN (words); w++)
      if (qppe_mmio_read32 (qd, base + 4 * w) != words[w])
	{
	  log_err (dev, "AC group 0 config readback mismatch at word %u", w);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
  }
  log_debug (dev, "set AC group 0 buffer limit to %u", HPPE_QM_GROUP0_BUF_LIMIT);

  for (queue = 0; queue < HPPE_AC_UNICAST_QUEUE_COUNT; queue++)
    {
      ppe_reg_ac_unicast_queue_cfg_w0_t w0 = {
	.en = 1,
	.dynamic = 1,
	.weight = HPPE_QM_UCAST_WEIGHT,
	.threshold = HPPE_QM_UCAST_CEIL,
      };
      ppe_reg_ac_unicast_queue_cfg_w3_t w3 = { .grn_resume = HPPE_QM_UCAST_RESUME_OFFSET };
      u32 base = HPPE_REG_AC_UNICAST_QUEUE_CFG_W0 (queue);
      u32 words[4];

      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	words[w] = qppe_mmio_read32 (qd, base + 4 * w);
      words[0] = w0.as_u32;
      words[3] = w3.as_u32;
      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	qppe_mmio_write32 (qd, base + 4 * w, words[w]);
      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	if (qppe_mmio_read32 (qd, base + 4 * w) != words[w])
	  {
	    log_err (dev, "AC unicast queue %u config readback mismatch at word %u", queue, w);
	    return VNET_DEV_ERR_INIT_FAILED;
	  }
    }
  log_debug (dev, "configured AC admission control for %u unicast queues",
	     HPPE_AC_UNICAST_QUEUE_COUNT);

  for (queue = HPPE_AC_MULTICAST_QUEUE_BASE;
       queue < HPPE_AC_MULTICAST_QUEUE_BASE + HPPE_AC_MULTICAST_QUEUE_COUNT; queue++)
    {
      ppe_reg_ac_multicast_queue_cfg_w0_t w0 = {
	.en = 1,
	.threshold = HPPE_QM_MCAST_CEIL,
      };
      ppe_reg_ac_multicast_queue_cfg_w2_t w2 = { .resume = HPPE_QM_MCAST_RESUME_OFFSET };
      u32 base = HPPE_REG_AC_MULTICAST_QUEUE_CFG_W0 (queue);
      u32 words[5];

      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	words[w] = qppe_mmio_read32 (qd, base + 4 * w);
      words[0] = w0.as_u32;
      words[2] = w2.as_u32;
      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	qppe_mmio_write32 (qd, base + 4 * w, words[w]);
      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	if (qppe_mmio_read32 (qd, base + 4 * w) != words[w])
	  {
	    log_err (dev, "AC multicast queue %u config readback mismatch at word %u", queue, w);
	    return VNET_DEV_ERR_INIT_FAILED;
	  }
    }
  log_debug (dev, "configured AC admission control for %u multicast queues",
	     HPPE_AC_MULTICAST_QUEUE_COUNT);

  for (queue = 0; queue < HPPE_AC_MULTICAST_QUEUE_BASE + HPPE_AC_MULTICAST_QUEUE_COUNT; queue++)
    {
      ppe_reg_enq_deq_opr_t enq = {};
      ppe_reg_enq_deq_opr_t deq = {};

      offset = HPPE_REG_ENQ_OPR (queue);
      qppe_mmio_write32 (qd, offset, enq.as_u32);
      if (qppe_mmio_read32 (qd, offset) != enq.as_u32)
	{
	  log_err (dev, "enqueue enable for queue %u readback mismatch at offset 0x%x", queue,
		   offset);
	  return VNET_DEV_ERR_INIT_FAILED;
	}

      offset = HPPE_REG_DEQ_OPR (queue);
      qppe_mmio_write32 (qd, offset, deq.as_u32);
      if (qppe_mmio_read32 (qd, offset) != deq.as_u32)
	{
	  log_err (dev, "dequeue enable for queue %u readback mismatch at offset 0x%x", queue,
		   offset);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }
  log_debug (dev, "enabled enqueue/dequeue for %u hardware queues",
	     HPPE_AC_MULTICAST_QUEUE_BASE + HPPE_AC_MULTICAST_QUEUE_COUNT);

  offset = HPPE_REG_EG_BRIDGE_CONFIG;
  eg_bridge_config.as_u32 = qppe_mmio_read32 (qd, offset);
  eg_bridge_config.queue_cnt_en = 1;
  qppe_mmio_write32 (qd, offset, eg_bridge_config.as_u32);
  if (!((ppe_reg_eg_bridge_config_t) { .as_u32 = qppe_mmio_read32 (qd, offset) }).queue_cnt_en)
    {
      log_err (dev, "failed to enable queue counters at offset 0x%x", offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "enabled hardware queue counters");

  return VNET_DEV_OK;
}

u8 *
format_qppe_enq_deq_opr (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "queue", "enq_disable", "deq_disable");
  /* qppe's own init clears both disable bits for every queue, so every
   * row is expected to show 0/0; only show rows that deviate from that
   * (the anomalous/interesting ones), rather than 300 all-identical
   * "enabled" rows. */
  for (u32 queue = 0; queue < 300; queue++)
    {
      ppe_reg_enq_deq_opr_t enq = { .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_ENQ_OPR (queue)) };
      ppe_reg_enq_deq_opr_t deq = { .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_DEQ_OPR (queue)) };

      if (!enq.disable && !deq.disable)
	continue;

      table_format_cell (&table, row, 0, "%u", queue);
      table_format_cell (&table, row, 1, "%u", enq.disable);
      table_format_cell (&table, row, 2, "%u", deq.disable);
      row++;
    }
  u32 indent = format_get_indent (s);
  s = format (s, "PPE ENQ_OPR/DEQ_OPR (queues disabled, if any):");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}
