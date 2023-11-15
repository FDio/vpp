/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_log_h
#define included_onp_drv_inc_log_h

#include <vlib/vlib.h>

extern vlib_log_class_registration_t cnxk_pktio_log;
extern vlib_log_class_registration_t cnxk_pool_log;

#define cnxk_pktio_err(fmt, ...)                                              \
  vlib_log_err (cnxk_pktio_log.class, fmt, ##__VA_ARGS__)

#define cnxk_pktio_warn(fmt, ...)                                             \
  vlib_log_warn (cnxk_pktio_log.class, fmt, ##__VA_ARGS__)

#define cnxk_pktio_notice(fmt, ...)                                           \
  vlib_log_notice (cnxk_pktio_log.class, fmt, ##__VA_ARGS__)

#define cnxk_pktio_debug(fmt, ...)                                            \
  vlib_log_debug (cnxk_pktio_log.class, fmt, ##__VA_ARGS__)

#define cnxk_pool_err(fmt, ...)                                               \
  vlib_log_err (cnxk_pool_log.class, fmt, ##__VA_ARGS__)

#define cnxk_pool_warn(fmt, ...)                                              \
  vlib_log_warn (cnxk_pool_log.class, fmt, ##__VA_ARGS__)

#define cnxk_pool_notice(fmt, ...)                                            \
  vlib_log_notice (cnxk_pool_log.class, fmt, ##__VA_ARGS__)

#define cnxk_pool_debug(fmt, ...)                                             \
  vlib_log_debug (cnxk_pool_log.class, fmt, ##__VA_ARGS__)

#endif /* included_onp_drv_inc_log_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
