/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _I2XX_H_
#define _I2XX_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#include <dev_i2xx/i2xx_regs.h>

typedef union
{
  struct
  {
    u64 pkt_addr;
    u64 hdr_addr;
  };
  struct
  {
    u64 rss_type : 4;
    u64 packet_type : 13;
    u64 _reserved_17 : 2;
    u64 hdr_len_hi : 2;
    u64 hdr_len_lo : 10;
    u64 sph : 1;
    u64 rss_hash : 32;

    u64 ext_status : 20;
    u64 ext_error : 12;
    u64 pkt_len : 16;
    u64 vlan_tag : 16;
  };
} i2xx_rx_desc_t;

STATIC_ASSERT_SIZEOF (i2xx_rx_desc_t, 16);

typedef struct
{
  void *bar0;
  u8 avail_rxq_bmp;
  u8 avail_txq_bmp;
} i2xx_device_t;

typedef struct
{
  i2xx_reg_status_t last_status;
} i2xx_port_t;

typedef struct
{
  u32 *buffer_indices;
} i2xx_txq_t;

typedef struct
{
  u32 *buffer_indices;
  i2xx_rx_desc_t *descs;
  u16 head;
  u16 tail;
  u32 *reg_rdt;
} i2xx_rxq_t;

/* format.c */
format_function_t format_i2xx_reg_write;
format_function_t format_i2xx_reg_read;
format_function_t format_i2xx_reg_diff;
format_function_t format_i2xx_port_status;

#endif /* _I2XX_H_ */
