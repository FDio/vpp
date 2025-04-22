/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_LOG_H_
#define _VNET_DEV_LOG_H_

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_INFO, dev_log.class, "%U" f, format_vnet_dev_log,  \
	    dev, clib_string_skip_prefix (__func__, "vnet_dev_"),             \
	    ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, dev_log.class, "%U" f,                     \
	    format_vnet_dev_log, dev, 0, ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, dev_log.class, "%U" f,                    \
	    format_vnet_dev_log, dev, 0, ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U" f, format_vnet_dev_log,   \
	    dev, 0, ##__VA_ARGS__)

#endif /* _VNET_DEV_LOG_H_ */
