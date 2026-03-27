/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef included_cadenee_hw_h
#define included_cadenee_hw_h

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
  _ (0x0100, OCTTXL)                                                                               \
  _ (0x0104, OCTTXH)                                                                               \
  _ (0x0108, TXCNT)                                                                                \
  _ (0x010c, TXBCCNT)                                                                              \
  _ (0x0110, TXMCCNT)                                                                              \
  _ (0x0114, TXPAUSECNT)                                                                           \
  _ (0x0118, TX64CNT)                                                                              \
  _ (0x011c, TX65CNT)                                                                              \
  _ (0x0120, TX128CNT)                                                                             \
  _ (0x0124, TX256CNT)                                                                             \
  _ (0x0128, TX512CNT)                                                                             \
  _ (0x012c, TX1024CNT)                                                                            \
  _ (0x0130, TX1519CNT)                                                                            \
  _ (0x0134, TXURUNCNT)                                                                            \
  _ (0x0138, SNGLCOLLCNT)                                                                          \
  _ (0x013c, MULTICOLLCNT)                                                                         \
  _ (0x0140, EXCESSCOLLCNT)                                                                        \
  _ (0x0144, LATECOLLCNT)                                                                          \
  _ (0x0148, TXDEFERCNT)                                                                           \
  _ (0x014c, TXCSENSECNT)                                                                          \
  _ (0x0150, OCTRXL)                                                                               \
  _ (0x0154, OCTRXH)                                                                               \
  _ (0x0158, RXCNT)                                                                                \
  _ (0x015c, RXBROADCNT)                                                                           \
  _ (0x0160, RXMULTICNT)                                                                           \
  _ (0x0164, RXPAUSECNT)                                                                           \
  _ (0x0168, RX64CNT)                                                                              \
  _ (0x016c, RX65CNT)                                                                              \
  _ (0x0170, RX128CNT)                                                                             \
  _ (0x0174, RX256CNT)                                                                             \
  _ (0x0178, RX512CNT)                                                                             \
  _ (0x017c, RX1024CNT)                                                                            \
  _ (0x0180, RX1519CNT)                                                                            \
  _ (0x0184, RXUNDRCNT)                                                                            \
  _ (0x0188, RXOVRCNT)                                                                             \
  _ (0x018c, RXJABCNT)                                                                             \
  _ (0x0190, RXFCSCNT)                                                                             \
  _ (0x0194, RXLENGTHCNT)                                                                          \
  _ (0x0198, RXSYMBCNT)                                                                            \
  _ (0x019c, RXALIGNCNT)                                                                           \
  _ (0x01a0, RXRESERRCNT)                                                                          \
  _ (0x01a4, RXORCNT)                                                                              \
  _ (0x01a8, RXIPCCNT)                                                                             \
  _ (0x01ac, RXTCPCCNT)                                                                            \
  _ (0x01b0, RXUDPCCNT)                                                                            \
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
    u32 reserved0 : 2;
    u32 re : 1;
    u32 te : 1;
    u32 reserved1 : 1;
    u32 clrstat : 1;
    u32 incstat : 1;
    u32 westat : 1;
    u32 reserved2 : 1;
    u32 tstart : 1;
    u32 reserved3 : 22;
  };
  u32 as_u32;
} cdn_ncr_t;

typedef union
{
  struct
  {
    u32 link : 1;
    u32 reserved : 31;
  };
  u32 as_u32;
} cdn_nsr_t;

typedef union
{
  struct
  {
    u32 reserved0 : 3;
    u32 jframe : 1;
    u32 caf : 1;
    u32 reserved1 : 3;
    u32 big : 1;
    u32 reserved2 : 23;
  };
  u32 as_u32;
} cdn_ncfgr_t;

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

typedef struct
{
  union
  {
    struct
    {
      u32 used : 1;
      u32 wrap : 1;
      u32 waddr : 30;
    };
    u32 as_u32;
  } addr;
  union
  {
    struct
    {
      u32 frm_len : 12;
      u32 offset : 2;
      u32 sof : 1;
      u32 eof : 1;
      u32 cfi : 1;
      u32 vlan_pri : 3;
      u32 pri_tag : 1;
      u32 vlan_tag : 1;
      u32 typeid_match : 1;
      u32 sa4_match : 1;
      u32 sa3_match : 1;
      u32 sa2_match : 1;
      u32 sa1_match : 1;
      u32 reserved0 : 1;
      u32 ext_match : 1;
      u32 uhash_match : 1;
      u32 mhash_match : 1;
      u32 broadcast : 1;
    };
    u32 as_u32;
  } ctrl;
  u32 addrh;
  u32 resvd;
} cdn_rx_desc_t;

typedef struct
{
  u32 addr;
  union
  {
    struct
    {
      u32 frm_len : 11;
      u32 reserved0 : 4;
      u32 last : 1;
      u32 nocrc : 1;
      u32 lso : 2;
      u32 tcp_seq_src : 1;
      u32 reserved1 : 7;
      u32 buf_exhausted : 1;
      u32 underrun : 1;
      u32 error : 1;
      u32 wrap : 1;
      u32 used : 1;
    };
    u32 as_u32;
  } ctrl;
  u32 addrh;
  u32 resvd;
} cdn_tx_desc_t;

#endif /* included_cadenee_hw_h */
