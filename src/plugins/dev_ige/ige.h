/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _IGE_H_
#define _IGE_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/types.h>

#include <dev_ige/ige_regs.h>

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
} ige_rx_desc_t;

STATIC_ASSERT_SIZEOF (ige_rx_desc_t, 16);

typedef struct
{
  u8 supports_2_5g : 1;
} ige_dev_flags_t;

typedef struct
{
  void *bar0;
  u8 avail_rxq_bmp;
  u8 avail_txq_bmp;
  ige_dev_flags_t dev_flags;
} ige_device_t;

typedef struct
{
  ige_reg_status_t last_status;
} ige_port_t;

typedef struct
{
  u32 *buffer_indices;
} ige_txq_t;

typedef struct
{
  u32 *buffer_indices;
  ige_rx_desc_t *descs;
  u16 head;
  u16 tail;
  u32 *reg_rdt;
} ige_rxq_t;

/* format.c */
format_function_t format_ige_reg_write;
format_function_t format_ige_reg_read;
format_function_t format_ige_reg_diff;
format_function_t format_ige_port_status;

#endif /* _IGE_H_ */
