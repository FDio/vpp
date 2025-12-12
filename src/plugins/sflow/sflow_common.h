/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 InMon Corp.
 */

#ifndef __included_sflow_common_h__
#define __included_sflow_common_h__

extern vlib_log_class_t sflow_logger;
#define SFLOW_DBG(...)	  vlib_log_debug (sflow_logger, __VA_ARGS__);
#define SFLOW_INFO(...)	  vlib_log_info (sflow_logger, __VA_ARGS__);
#define SFLOW_NOTICE(...) vlib_log_notice (sflow_logger, __VA_ARGS__);
#define SFLOW_WARN(...)	  vlib_log_warn (sflow_logger, __VA_ARGS__);
#define SFLOW_ERR(...)	  vlib_log_err (sflow_logger, __VA_ARGS__);

typedef struct
{
  u32 sw_if_index;
  u32 hw_if_index;
  u32 linux_if_index;
  u32 polled;
  int sflow_enabled;
} sflow_per_interface_data_t;

/* mirror sflow_direction enum in sflow.api */
typedef enum
{
  SFLOW_DIRN_UNDEFINED = 0,
  SFLOW_DIRN_INGRESS,
  SFLOW_DIRN_EGRESS,
  SFLOW_DIRN_BOTH
} sflow_direction_t;

#endif /* __included_sflow_common_h__ */
