/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_pktio_pktio_fp_ops_h
#define included_onp_drv_modules_pktio_pktio_fp_ops_h

#include <onp/drv/inc/pktio.h>

/* clang-format off */

#define foreach_pktio_rx_func                                                 \
 /* trace, out_cksum,  name */                                                \
                                                                              \
 _(     0,         0,  poll_none)                                             \
 _(     0,         1,  poll_ocs)                                              \
 _(     1,         0,  poll_trace_none)                                       \
 _(     1,         1,  poll_trace_ocs)                                        \

#define foreach_pktio_tx_func                                                 \
 /* out_cksum, desc_sz, name */                                               \
                                                                              \
 _(     0,        4,  poll_none)                                              \
 _(     1,        4,  poll_ocs)

/* clang-format on */

#endif /* included_onp_drv_modules_pktio_pktio_fp_ops_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
