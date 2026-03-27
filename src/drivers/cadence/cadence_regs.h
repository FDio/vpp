/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef included_cadence_regs_h
#define included_cadence_regs_h

#define CDN_MOD_ID_7014 0x107
#define CDN_MOD_ID_7021 0x00c

#define foreach_cdn_reg                                                                            \
  _ (0x00fc, MID)                                                                                  \
  _ (0x0000, NCR)                                                                                  \
  _ (0x0004, NCFGR)                                                                                \
  _ (0x0008, NSR)                                                                                  \
  _ (0x000c, USRIO)                                                                                \
  _ (0x0010, DMACFG)                                                                               \
  _ (0x0014, TSR)                                                                                  \
  _ (0x0020, RSR)                                                                                  \
  _ (0x0048, JML)                                                                                  \
  _ (0x0050, HS_MAC_CONFIG)                                                                        \
  _ (0x0054, AXI_PIPELINE)                                                                         \
  _ (0x0024, ISR)                                                                                  \
  _ (0x0028, IER)                                                                                  \
  _ (0x002c, IDR)                                                                                  \
  _ (0x0030, IMR)                                                                                  \
  _ (0x0200, PCSCNTRL)                                                                             \
  _ (0x0204, PCSSTS)                                                                               \
  _ (0x0280, DCFG1)                                                                                \
  _ (0x0284, DCFG2)                                                                                \
  _ (0x0288, DCFG3)                                                                                \
  _ (0x028c, DCFG4)                                                                                \
  _ (0x0290, DCFG5)                                                                                \
  _ (0x0294, DCFG6)                                                                                \
  _ (0x0298, DCFG7)                                                                                \
  _ (0x029c, DCFG8)                                                                                \
  _ (0x02a0, DCFG9)                                                                                \
  _ (0x02a4, DCFG10)                                                                               \
  _ (0x02a8, DCFG11)                                                                               \
  _ (0x02ac, DCFG12)                                                                               \
  _ (0x02b0, DCFG13)                                                                               \
  _ (0x04d8, AHA)                                                                                  \
  _ (0x04ec, WDC)                                                                                  \
  _ (0x04cc, TXBDCTRL)                                                                             \
  _ (0x04d0, RXBDCTRL)

typedef enum
{
#define _(v, n) CDN_##n = v,
  foreach_cdn_reg
#undef _
} cdn_reg_t;

typedef union
{
  struct
  {
    u32 rev : 16;
    u32 idnum : 12;
    u32 reserved : 4;
  };
  u32 as_u32;
} cdn_mid_t;

typedef union
{
  struct
  {
    u32 no_pcs : 1;
    u32 reserved0 : 22;
    u32 irqcor : 1;
    u32 reserved1 : 1;
    u32 dbwdef : 3;
    u32 reserved2 : 4;
  };
  u32 as_u32;
} cdn_dcfg1_t;

typedef union
{
  struct
  {
    u32 reserved0 : 20;
    u32 rx_pkt_buf : 1;
    u32 tx_pkt_buf : 1;
    u32 rx_pbuf_addr : 4;
    u32 reserved1 : 6;
  };
  u32 as_u32;
} cdn_dcfg2_t;

typedef union
{
  struct
  {
    u32 reserved0 : 8;
    u32 tsu : 1;
    u32 reserved1 : 23;
  };
  u32 as_u32;
} cdn_dcfg5_t;

typedef union
{
  struct
  {
    u32 queue_mask : 8;
    u32 reserved0 : 15;
    u32 daw64 : 1;
    u32 reserved1 : 3;
    u32 pbuf_lso : 1;
    u32 reserved2 : 4;
  };
  u32 as_u32;
} cdn_dcfg6_t;

typedef union
{
  struct
  {
    u32 reserved0 : 16;
    u32 axi_pipe_bits : 4;
    u32 reserved1 : 12;
  };
  u32 as_u32;
} cdn_dcfg10_t;

typedef union
{
  struct
  {
    u32 reserved0 : 26;
    u32 high_speed : 1;
    u32 reserved1 : 5;
  };
  u32 as_u32;
} cdn_dcfg12_t;

#endif /* included_cadence_regs_h */
