/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "qm",
};

vnet_dev_rv_t
qppe_qm_init (vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  ppe_reg_ac_grp_cfg_w1_t ac_grp_w1 = { .buf_limit = HPPE_QM_GROUP0_BUF_LIMIT };
  ppe_reg_eg_bridge_config_t eg_bridge_config;
  u32 offset;
  vnet_dev_rv_t rv;

  {
    u32 base = HPPE_REG_AC_GRP_CFG_W0 (0);
    qppe_reg_val_t regs[3] = {};

    for (u32 w = 0; w < ARRAY_LEN (regs); w++)
      regs[w] = (qppe_reg_val_t) {
	.off = base + 4 * w,
	.val = qppe_mmio_read32 (qd, base + 4 * w),
      };
    regs[1].val = ac_grp_w1.as_u32;
    rv = qppe_mmio_write_validate (dev, regs, ARRAY_LEN (regs));
    if (rv != VNET_DEV_OK)
      return rv;
  }
  log_debug (dev, "set AC group 0 buffer limit to %u", HPPE_QM_GROUP0_BUF_LIMIT);

  for (u32 queue = 0; queue < HPPE_AC_UNICAST_QUEUE_COUNT; queue++)
    {
      ppe_reg_ac_unicast_queue_cfg_w0_t w0 = {
	.en = 1,
	.dynamic = 1,
	.weight = HPPE_QM_UCAST_WEIGHT,
	.threshold = HPPE_QM_UCAST_CEIL,
      };
      ppe_reg_ac_unicast_queue_cfg_w3_t w3 = { .grn_resume = HPPE_QM_UCAST_RESUME_OFFSET };
      u32 base = HPPE_REG_AC_UNICAST_QUEUE_CFG_W0 (queue);
      qppe_reg_val_t regs[4] = {};

      for (u32 w = 0; w < ARRAY_LEN (regs); w++)
	regs[w] = (qppe_reg_val_t) {
	  .off = base + 4 * w,
	  .val = qppe_mmio_read32 (qd, base + 4 * w),
	};
      regs[0].val = w0.as_u32;
      regs[3].val = w3.as_u32;
      rv = qppe_mmio_write_validate (dev, regs, ARRAY_LEN (regs));
      if (rv != VNET_DEV_OK)
	return rv;
    }
  log_debug (dev, "configured AC admission control for %u unicast queues",
	     HPPE_AC_UNICAST_QUEUE_COUNT);

  for (u32 queue = HPPE_AC_MULTICAST_QUEUE_BASE;
       queue < HPPE_AC_MULTICAST_QUEUE_BASE + HPPE_AC_MULTICAST_QUEUE_COUNT; queue++)
    {
      ppe_reg_ac_multicast_queue_cfg_w0_t w0 = {
	.en = 1,
	.threshold = HPPE_QM_MCAST_CEIL,
      };
      ppe_reg_ac_multicast_queue_cfg_w2_t w2 = { .resume = HPPE_QM_MCAST_RESUME_OFFSET };
      u32 base = HPPE_REG_AC_MULTICAST_QUEUE_CFG_W0 (queue);
      qppe_reg_val_t regs[5] = {};

      for (u32 w = 0; w < ARRAY_LEN (regs); w++)
	regs[w] = (qppe_reg_val_t) {
	  .off = base + 4 * w,
	  .val = qppe_mmio_read32 (qd, base + 4 * w),
	};
      regs[0].val = w0.as_u32;
      regs[2].val = w2.as_u32;
      rv = qppe_mmio_write_validate (dev, regs, ARRAY_LEN (regs));
      if (rv != VNET_DEV_OK)
	return rv;
    }
  log_debug (dev, "configured AC admission control for %u multicast queues",
	     HPPE_AC_MULTICAST_QUEUE_COUNT);

  for (u32 queue = 0; queue < HPPE_AC_MULTICAST_QUEUE_BASE + HPPE_AC_MULTICAST_QUEUE_COUNT; queue++)
    {
      ppe_reg_enq_deq_opr_t enq = {};

      offset = HPPE_REG_ENQ_OPR (queue);
      qppe_mmio_write32 (qd, offset, enq.as_u32);
      if (qppe_mmio_read32 (qd, offset) != enq.as_u32)
	{
	  log_err (dev, "enqueue enable for queue %u readback mismatch at offset 0x%x", queue,
		   offset);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }
  log_debug (dev, "enabled enqueue for %u hardware queues",
	     HPPE_AC_MULTICAST_QUEUE_BASE + HPPE_AC_MULTICAST_QUEUE_COUNT);

  offset = HPPE_REG_EG_BRIDGE_CONFIG;
  eg_bridge_config.as_u32 = qppe_mmio_read32 (qd, offset);
  eg_bridge_config.queue_cnt_en = 1;
  {
    ppe_reg_eg_bridge_config_t mask = {
      .queue_cnt_en = 1,
    };
    const qppe_reg_val_t reg = {
      .off = offset,
      .val = eg_bridge_config.as_u32,
      .mask = mask.as_u32,
    };

    rv = qppe_mmio_write_validate (dev, &reg, 1);
    if (rv != VNET_DEV_OK)
      return rv;
  }
  log_debug (dev, "enabled hardware queue counters");

  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_qm_ucast_queue_map_set (vnet_dev_t *dev, u32 vp, u32 queue_id, u8 profile)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  ppe_reg_ucast_queue_map_t queue_map = {
    .profile_id = profile,
    .queue_id = queue_id,
  };
  u32 offset = HPPE_REG_UCAST_QUEUE_MAP_TBL (0, vp);

  qppe_mmio_write32 (qd, offset, queue_map.as_u32);
  if (qppe_mmio_read32 (qd, offset) != queue_map.as_u32)
    {
      log_err (dev, "VP %u queue base readback failed at offset 0x%x", vp, offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_qm_port_queue_map_configure (vnet_dev_port_t *port, vnet_dev_rss_config_t *config)
{
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  u16 queues[EDMA_RX_QUEUES_PER_PORT] = {};
  qppe_reg_val_t regs[HPPE_QM_PRIORITIES + HPPE_QM_MAP_KEYS] = {};
  u32 n_queues = 0;

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->enabled)
      {
	ASSERT (n_queues < ARRAY_LEN (queues));
	queues[n_queues++] = q->queue_id;
      }
  ASSERT (n_queues);
  ASSERT (!config->set_lut || config->lut_len);

  /* Priority does not alter the RSS-selected queue. */
  for (u32 i = 0; i < HPPE_QM_PRIORITIES; i++)
    regs[i] = (qppe_reg_val_t) {
      .off = HPPE_REG_UCAST_PRIORITY_MAP_TBL (qp->source_profile, i),
    };

  for (u32 i = 0; i < HPPE_QM_MAP_KEYS; i++)
    regs[HPPE_QM_PRIORITIES + i] = (qppe_reg_val_t) {
      .off = HPPE_REG_UCAST_HASH_MAP_TBL ((qp->source_profile << 8) + i),
      .val = config->set_lut ? config->lut[i % config->lut_len] : queues[i % n_queues],
    };

  return qppe_mmio_write_validate (port->dev, regs, ARRAY_LEN (regs));
}
