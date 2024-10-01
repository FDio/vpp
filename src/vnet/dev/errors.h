/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_ERRORS_H_
#define _VNET_DEV_ERRORS_H_

#define foreach_vnet_dev_rv_type                                              \
  _ (ALREADY_EXISTS, "already exists")                                        \
  _ (ALREADY_IN_USE, "already in use")                                        \
  _ (BUFFER_ALLOC_FAIL, "packet buffer allocation failure")                   \
  _ (BUG, "bug")                                                              \
  _ (BUS, "bus error")                                                        \
  _ (DEVICE_NO_REPLY, "no reply from device")                                 \
  _ (DMA_MEM_ALLOC_FAIL, "DMA memory allocation error")                       \
  _ (DRIVER_NOT_AVAILABLE, "driver not available")                            \
  _ (INVALID_ARG, "invalid argument")                                         \
  _ (INVALID_BUS, "invalid bus")                                              \
  _ (INVALID_DATA, "invalid data")                                            \
  _ (INVALID_DEVICE_ID, "invalid device id")                                  \
  _ (INVALID_NUM_RX_QUEUES, "invalid number of rx queues")                    \
  _ (INVALID_NUM_TX_QUEUES, "invalid number of tx queues")                    \
  _ (INVALID_PORT_ID, "invalid port id")                                      \
  _ (INVALID_RX_QUEUE_SIZE, "invalid rx queue size")                          \
  _ (INVALID_TX_QUEUE_SIZE, "invalid tx queue size")                          \
  _ (INVALID_VALUE, "invalid value")                                          \
  _ (INTERNAL, "internal error")                                              \
  _ (NOT_FOUND, "not found")                                                  \
  _ (NOT_READY, "not ready")                                                  \
  _ (NOT_SUPPORTED, "not supported")                                          \
  _ (NO_CHANGE, "no change")                                                  \
  _ (NO_AVAIL_QUEUES, "no queues available")                                  \
  _ (NO_SUCH_ENTRY, "no such enty")                                           \
  _ (PORT_STARTED, "port started")                                            \
  _ (PROCESS_REPLY, "dev process reply error")                                \
  _ (RESOURCE_NOT_AVAILABLE, "resource not available")                        \
  _ (TIMEOUT, "timeout")                                                      \
  _ (UNKNOWN_DEVICE, "unknown device")                                        \
  _ (UNKNOWN_INTERFACE, "unknown interface")                                  \
  _ (NOT_PRIMARY_INTERFACE, "not primary interface")                          \
  _ (PRIMARY_INTERFACE_MISSING, "primary interface missing")                  \
  _ (UNSUPPORTED_CONFIG, "unsupported config")                                \
  _ (UNSUPPORTED_DEVICE, "unsupported device")                                \
  _ (UNSUPPORTED_DEVICE_VER, "unsupported device version")                    \
  _ (UNSUPPORTED_INTERFACE, "unsupported interface")                          \
  _ (ALREADY_DONE, "already done")                                            \
  _ (NO_SUCH_INTERFACE, "no such interface")                                  \
  _ (INIT_FAILED, "init failed")

#endif /* _VNET_DEV_ERRORS_H_ */
