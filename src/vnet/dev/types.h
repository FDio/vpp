/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_TYPES_H_
#define _VNET_DEV_TYPES_H_

#include <vppinfra/types.h>
#include <vnet/dev/errors.h>

typedef char vnet_dev_device_id_t[48];
typedef char vnet_dev_if_name_t[32];
typedef char vnet_dev_driver_name_t[16];
typedef char vnet_dev_bus_name_t[16];
typedef u16 vnet_dev_port_id_t;
typedef struct vnet_dev vnet_dev_t;
typedef struct vnet_dev_port vnet_dev_port_t;
typedef struct vnet_dev_rx_queue vnet_dev_rx_queue_t;
typedef struct vnet_dev_tx_queue vnet_dev_tx_queue_t;
typedef struct
{
  u8 key[48];
  u8 length;
} vnet_dev_rss_key_t;

typedef enum
{
  VNET_DEV_MINUS_OK = 0,
#define _(n, d) VNET_DEV_ERR_MINUS_##n,
  foreach_vnet_dev_rv_type
#undef _
} vnet_dev_minus_rv_t;

typedef enum
{
  VNET_DEV_OK = 0,
#define _(n, d) VNET_DEV_ERR_##n = -(VNET_DEV_ERR_MINUS_##n),
  foreach_vnet_dev_rv_type
#undef _
} vnet_dev_rv_t;

/* do not change bit assignments - API dependency */
#define foreach_vnet_dev_flag _ (0, NO_STATS, "don't poll device stats")

typedef union
{
  enum
  {
#define _(b, n, d) VNET_DEV_F_##n = 1ull << (b),
    foreach_vnet_dev_flag
#undef _
  } e;
  u32 n;
} vnet_dev_flags_t;

/* do not change bit assignments - API dependency */
#define foreach_vnet_dev_port_flag                                            \
  _ (0, INTERRUPT_MODE, "enable interrupt mode")                              \
  _ (1, CONSISTENT_QP, "consistent queue pairs")                              \
  _ (2, QUEUE_PER_THREAD, "one rx and one tx queue per thread (inc main)")

typedef union
{
  enum
  {
#define _(b, n, d) VNET_DEV_PORT_F_##n = 1ull << (b),
    foreach_vnet_dev_port_flag
#undef _
  } e;
  u32 n;
} vnet_dev_port_flags_t;

#endif /* _VNET_DEV_TYPES_H_ */
