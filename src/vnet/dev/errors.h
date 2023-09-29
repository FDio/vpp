/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_ERRORS_H_
#define _VNET_DEV_ERRORS_H_

#define foreach_vnet_dev_rv_type                                              \
  _ (1, TIMEOUT, "timeout")                                                   \
  _ (2, RESOURCE_NOT_AVAILABLE, "resource not available")                     \
  _ (3, BUS, "bus error")                                                     \
  _ (4, DRIVER_NOT_AVAILABLE, "driver not available")                         \
  _ (5, DMA_MEM_ALLOC_FAIL, "DMA memory allocation error")                    \
  _ (6, BUFFER_ALLOC_FAIL, "packet buffer allocation failure")                \
  _ (7, PROCESS_REPLY, "dev process reply error")                             \
  _ (8, ALREADY_IN_USE, "already in use")                                     \
  _ (9, NOT_FOUND, "not found")                                               \
  _ (10, INVALID_DEVICE_ID, "invalid device id")                              \
  _ (11, INVALID_PORT_ID, "invalid port id")                                  \
  _ (12, INVALID_NUM_RX_QUEUES, "invalid number of rx queues")                \
  _ (13, INVALID_NUM_TX_QUEUES, "invalid number of tx queues")                \
  _ (14, INVALID_RX_QUEUE_SIZE, "invalid rx queue size")                      \
  _ (15, INVALID_TX_QUEUE_SIZE, "invalid tx queue size")                      \
  _ (16, NOT_READY, "not ready")                                              \
  _ (17, DEVICE_NO_REPLY, "no reply from device")                             \
  _ (18, UNSUPPORTED_DEV, "unsupported device")                               \
  _ (19, UNSUPPORTED_DEV_VER, "unsupported device version")                   \
  _ (20, INVALID_BUS, "invalid bus")                                          \
  _ (21, BUG, "bug")

#endif /* _VNET_DEV_ERRORS_H_ */
