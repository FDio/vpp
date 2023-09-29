/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_COUNTERS_H_
#define _VNET_DEV_COUNTERS_H_

#include <vnet/dev/dev.h>

typedef enum
{
  VNET_DEV_COUNTER_DIR_NA,
  VNET_DEV_COUNTER_DIR_RX,
  VNET_DEV_COUNTER_DIR_TX,
} __clib_packed vnet_dev_counter_direction_t;

typedef enum
{
  VNET_DEV_COUNTER_TYPE_RX_BYTES,
  VNET_DEV_COUNTER_TYPE_RX_PACKETS,
  VNET_DEV_COUNTER_TYPE_RX_DROPS,
  VNET_DEV_COUNTER_TYPE_TX_BYTES,
  VNET_DEV_COUNTER_TYPE_TX_PACKETS,
  VNET_DEV_COUNTER_TYPE_TX_DROPS,
  VNET_DEV_COUNTER_TYPE_VENDOR,
} __clib_packed vnet_dev_counter_type_t;

typedef enum
{
  VNET_DEV_COUNTER_UNIT_NA,
  VNET_DEV_COUNTER_UNIT_BYTES,
  VNET_DEV_COUNTER_UNIT_PACKETS,
} __clib_packed vnet_dev_counter_unit_t;

typedef struct vnet_dev_counter_t
{
  char name[24];
  uword user_data;
  vnet_dev_counter_type_t type;
  vnet_dev_counter_direction_t dir;
  vnet_dev_counter_unit_t unit;
  u16 index;
} vnet_dev_counter_t;

typedef struct vnet_dev_counter_main_t
{
  u8 *desc;
  u64 *counter_data;
  u16 n_counters;
  vnet_dev_counter_t counters[];
} vnet_dev_counter_main_t;

#define VNET_DEV_COUNTER_RX_BYTES(p, ...)                                     \
  {                                                                           \
    .type = VNET_DEV_COUNTER_TYPE_RX_BYTES, .dir = VNET_DEV_COUNTER_DIR_RX,   \
    .unit = VNET_DEV_COUNTER_UNIT_BYTES, .user_data = (p), __VA_ARGS__        \
  }
#define VNET_DEV_COUNTER_TX_BYTES(p, ...)                                     \
  {                                                                           \
    .type = VNET_DEV_COUNTER_TYPE_TX_BYTES, .dir = VNET_DEV_COUNTER_DIR_TX,   \
    .unit = VNET_DEV_COUNTER_UNIT_BYTES, .user_data = (p), __VA_ARGS__        \
  }
#define VNET_DEV_COUNTER_RX_PACKETS(p, ...)                                   \
  {                                                                           \
    .type = VNET_DEV_COUNTER_TYPE_RX_PACKETS, .dir = VNET_DEV_COUNTER_DIR_RX, \
    .unit = VNET_DEV_COUNTER_UNIT_PACKETS, .user_data = (p), __VA_ARGS__      \
  }
#define VNET_DEV_COUNTER_TX_PACKETS(p, ...)                                   \
  {                                                                           \
    .type = VNET_DEV_COUNTER_TYPE_TX_PACKETS, .dir = VNET_DEV_COUNTER_DIR_TX, \
    .unit = VNET_DEV_COUNTER_UNIT_PACKETS, .user_data = (p), __VA_ARGS__      \
  }
#define VNET_DEV_COUNTER_RX_DROPS(p, ...)                                     \
  {                                                                           \
    .type = VNET_DEV_COUNTER_TYPE_RX_DROPS, .dir = VNET_DEV_COUNTER_DIR_RX,   \
    .unit = VNET_DEV_COUNTER_UNIT_PACKETS, .user_data = (p), __VA_ARGS__      \
  }
#define VNET_DEV_COUNTER_TX_DROPS(p, ...)                                     \
  {                                                                           \
    .type = VNET_DEV_COUNTER_TYPE_TX_DROPS, .dir = VNET_DEV_COUNTER_DIR_TX,   \
    .unit = VNET_DEV_COUNTER_UNIT_PACKETS, .user_data = (p), __VA_ARGS__      \
  }
#define VNET_DEV_COUNTER_VENDOR(p, d, u, n, ...)                              \
  {                                                                           \
    .type = VNET_DEV_COUNTER_TYPE_VENDOR, .user_data = (p), .name = n,        \
    .dir = VNET_DEV_COUNTER_DIR_##d, .unit = VNET_DEV_COUNTER_UNIT_##u,       \
    __VA_ARGS__                                                               \
  }

vnet_dev_counter_main_t *vnet_dev_counters_alloc (vlib_main_t *,
						  vnet_dev_counter_t *, u16,
						  char *, ...);
void vnet_dev_counters_free (vlib_main_t *, vnet_dev_counter_main_t *);

format_function_t format_vnet_dev_counters;
format_function_t format_vnet_dev_counters_all;

static_always_inline void
vnet_dev_counter_value_add (vlib_main_t *vm, vnet_dev_counter_main_t *cm,
			    vnet_dev_counter_t *counter, u64 val)
{
  cm->counter_data[counter->index] += val;
}

static_always_inline void
vnet_dev_counter_value_set (vlib_main_t *vm, vnet_dev_counter_main_t *cm,
			    vnet_dev_counter_t *counter, u64 val)
{
  cm->counter_data[counter->index] = val;
}

#define foreach_vnet_dev_counter(c, cm)                                       \
  if (cm)                                                                     \
    for (typeof (*(cm)->counters) *(c) = (cm)->counters;                      \
	 (c) < (cm)->counters + (cm)->n_counters; (c)++)

#endif /* _VNET_DEV_COUNTERS_H_ */
