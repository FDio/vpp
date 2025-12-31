/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <mhi.h>

VLIB_REGISTER_LOG_CLASS (mhi_log, static) = {
  .class_name = "mhi",
  .subclass_name = "event",
};

void
mhi_process_event_ring (vlib_main_t *vm, vnet_dev_t *dev, u16 er_index)
{
  log_debug (dev, "Processing event ring %u", er_index);
}
