/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_ERRORS_H_
#define _VNET_DEV_ERRORS_H_

#define foreach_vnet_dev_rv_type                                              \
  _ (TIMEOUT, "timeout")                                                      \
  _ (RESOURCE_NOT_AVAILABLE, "resource not available")                        \
  _ (BUS, "bus error")                                                        \
  _ (DRIVER_NOT_AVAILABLE, "driver not available")                            \
  _ (DMA_MEM_ALLOC_FAIL, "DMA memory allocation error")                       \
  _ (BUFFER_ALLOC_FAIL, "packet buffer allocation failure")                   \
  _ (PROCESS_REPLY, "dev process reply error")                                \
  _ (ALREADY_IN_USE, "already in use")                                        \
  _ (NOT_FOUND, "not found")                                                  \
  _ (INVALID_DEVICE_ID, "invalid device id")                                  \
  _ (INVALID_PORT_ID, "invalid port id")                                      \
  _ (INVALID_NUM_RX_QUEUES, "invalid number of rx queues")                    \
  _ (INVALID_NUM_TX_QUEUES, "invalid number of tx queues")                    \
  _ (INVALID_RX_QUEUE_SIZE, "invalid rx queue size")                          \
  _ (INVALID_TX_QUEUE_SIZE, "invalid tx queue size")                          \
  _ (NOT_READY, "not ready")                                                  \
  _ (DEVICE_NO_REPLY, "no reply from device")                                 \
  _ (UNSUPPORTED_DEV, "unsupported device")                                   \
  _ (UNSUPPORTED_DEV_VER, "unsupported device version")                       \
  _ (INVALID_BUS, "invalid bus")                                              \
  _ (NOT_SUPPORTED, "not supported")                                          \
  _ (UNKNOWN_INTERFACE, "unknown interface")                                  \
  _ (ALREADY_EXISTS, "already exists")                                        \
  _ (INVALID_DATA, "invalid data")                                            \
  _ (NO_CHANGE, "no change")                                                  \
  _ (BUG, "bug")

#endif /* _VNET_DEV_ERRORS_H_ */
