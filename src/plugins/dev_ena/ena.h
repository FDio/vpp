/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_H_
#define _ENA_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

typedef struct
{
  void *bar0;
  u8 avail_rxq_bmp;
  u8 avail_txq_bmp;
} ena_device_t;

typedef struct
{
  u32 last_status;
} ena_port_t;

typedef struct
{
  u32 *buffer_indices;
} ena_txq_t;

typedef struct
{
  u32 *buffer_indices;
  u16 head;
  u16 tail;
} ena_rxq_t;

/* format.c */
format_function_t format_ena_reg_write;
format_function_t format_ena_reg_read;
format_function_t format_ena_reg_diff;
format_function_t format_ena_port_status;

#endif /* _ENA_H_ */
