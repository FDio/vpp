/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef _QPPE_H_
#define _QPPE_H_

#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/devicetree.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>

/* Compatible string of the PPE base node in the device tree, e.g.
 * "qcom,ipq9574-ppe" for the ethernet@3a000000 node. */
#define QPPE_DT_COMPATIBLE "qcom,ipq9574-ppe"

/* There is a single 'qcom,ipq9574-ppe' hardware variant, and it has no
 * separate version/revision ID register - the compatible string above is
 * the version identifier. */
#define QPPE_MAX_PORTS 8

typedef struct
{
  /* register region managed by the generic platform resource broker */
  void *regs;
  u8 *dt_path;
  vnet_dev_platform_clock_t *clocks;
  vnet_dev_platform_reset_t *resets;
  vnet_dev_platform_interconnect_t *interconnects;
  vnet_dev_platform_phy_t *phys;

  /* device attributes */
  u32 n_ports;
} qppe_device_t;

typedef struct
{
  u32 id;
  const char *label;
  const char *phy_mode;
  const char *managed;
  u8 is_enabled : 1;
} qppe_port_t;

typedef struct
{
} qppe_rxq_t;

typedef struct
{
  u32 *buffers;
} qppe_txq_t;

/* format.c */
format_function_t format_qppe_dev_info;
format_function_t format_qppe_port_status;

/* port.c */
vnet_dev_port_op_t qppe_port_init;
vnet_dev_port_op_no_rv_t qppe_port_deinit;
vnet_dev_port_op_t qppe_port_start;
vnet_dev_port_op_no_rv_t qppe_port_stop;

/* queue.c */
vnet_dev_tx_queue_op_t qppe_txq_alloc;
vnet_dev_tx_queue_op_no_rv_t qppe_txq_free;

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, qppe_log.class, "%U" f, format_vnet_dev_log, (dev),              \
	    clib_string_skip_prefix (__func__, "qppe_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_INFO, qppe_log.class, "%U" f, format_vnet_dev_log, (dev), 0,            \
	    ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, qppe_log.class, "%U" f, format_vnet_dev_log, (dev), 0,          \
	    ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, qppe_log.class, "%U" f, format_vnet_dev_log, (dev), 0,         \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, qppe_log.class, "%U" f, format_vnet_dev_log, (dev), 0,             \
	    ##__VA_ARGS__)

#endif /* _QPPE_H_ */
