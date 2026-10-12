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
  .subclass_name = "sched",
};

vnet_dev_rv_t
qppe_sched_init (vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);

  for (u32 q = 0; q < HPPE_SCHED_QUEUE_COUNT; q++)
    {
      u32 reg = HPPE_REG_SCHED_DEQ_DIS_TBL + 0x10 * q;

      qppe_mmio_write32 (qd, reg, 0);
      if (qppe_mmio_read32 (qd, reg) != 0)
	{
	  log_err (dev, "dequeue enable for queue %u readback mismatch at offset 0x%x", q, reg);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }
  log_debug (dev, "enabled dequeue for %u hardware queues", HPPE_SCHED_QUEUE_COUNT);
  return VNET_DEV_OK;
}
