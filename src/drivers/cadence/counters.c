/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>

#include <cadence.h>

#define CDN_CTR64(hi, lo) ((u64) (hi) << 32 | (lo))

static vnet_dev_counter_t cdn_port_counters[] = {
  VNET_DEV_CTR_TX_BYTES (CDN_CTR64 (CDN_OCTTXH, CDN_OCTTXL)),
  VNET_DEV_CTR_TX_PACKETS (CDN_TXCNT),
  VNET_DEV_CTR_RX_BYTES (CDN_CTR64 (CDN_OCTRXH, CDN_OCTRXL)),
  VNET_DEV_CTR_RX_PACKETS (CDN_RXCNT),
  VNET_DEV_CTR_VENDOR (CDN_TXBCCNT, TX, PACKETS, "broadcast"),
  VNET_DEV_CTR_VENDOR (CDN_TXMCCNT, TX, PACKETS, "multicast"),
  VNET_DEV_CTR_VENDOR (CDN_TXPAUSECNT, TX, PACKETS, "pause"),
  VNET_DEV_CTR_VENDOR (CDN_TX64CNT, TX, PACKETS, "64 bytes"),
  VNET_DEV_CTR_VENDOR (CDN_TX65CNT, TX, PACKETS, "65-127 bytes"),
  VNET_DEV_CTR_VENDOR (CDN_TX128CNT, TX, PACKETS, "128-255 bytes"),
  VNET_DEV_CTR_VENDOR (CDN_TX256CNT, TX, PACKETS, "256-511 bytes"),
  VNET_DEV_CTR_VENDOR (CDN_TX512CNT, TX, PACKETS, "512-1023 bytes"),
  VNET_DEV_CTR_VENDOR (CDN_TX1024CNT, TX, PACKETS, "1024-1518 bytes"),
  VNET_DEV_CTR_VENDOR (CDN_TX1519CNT, TX, PACKETS, "1519+ bytes"),
  VNET_DEV_CTR_VENDOR (CDN_TXURUNCNT, TX, PACKETS, "underrun"),
  VNET_DEV_CTR_VENDOR (CDN_SNGLCOLLCNT, TX, PACKETS, "single collision"),
  VNET_DEV_CTR_VENDOR (CDN_MULTICOLLCNT, TX, PACKETS, "multiple collision"),
  VNET_DEV_CTR_VENDOR (CDN_EXCESSCOLLCNT, TX, PACKETS, "excessive collision"),
  VNET_DEV_CTR_VENDOR (CDN_LATECOLLCNT, TX, PACKETS, "late collision"),
  VNET_DEV_CTR_VENDOR (CDN_TXDEFERCNT, TX, PACKETS, "deferred"),
  VNET_DEV_CTR_VENDOR (CDN_TXCSENSECNT, TX, PACKETS, "carrier sense errors"),
  VNET_DEV_CTR_VENDOR (CDN_RXBROADCNT, RX, PACKETS, "broadcast"),
  VNET_DEV_CTR_VENDOR (CDN_RXMULTICNT, RX, PACKETS, "multicast"),
  VNET_DEV_CTR_VENDOR (CDN_RXPAUSECNT, RX, PACKETS, "pause"),
  VNET_DEV_CTR_VENDOR (CDN_RX64CNT, RX, PACKETS, "64 bytes"),
  VNET_DEV_CTR_VENDOR (CDN_RX65CNT, RX, PACKETS, "65-127 bytes"),
  VNET_DEV_CTR_VENDOR (CDN_RX128CNT, RX, PACKETS, "128-255 bytes"),
  VNET_DEV_CTR_VENDOR (CDN_RX256CNT, RX, PACKETS, "256-511 bytes"),
  VNET_DEV_CTR_VENDOR (CDN_RX512CNT, RX, PACKETS, "512-1023 bytes"),
  VNET_DEV_CTR_VENDOR (CDN_RX1024CNT, RX, PACKETS, "1024-1518 bytes"),
  VNET_DEV_CTR_VENDOR (CDN_RX1519CNT, RX, PACKETS, "1519+ bytes"),
  VNET_DEV_CTR_VENDOR (CDN_RXUNDRCNT, RX, PACKETS, "undersized"),
  VNET_DEV_CTR_VENDOR (CDN_RXOVRCNT, RX, PACKETS, "oversized"),
  VNET_DEV_CTR_VENDOR (CDN_RXJABCNT, RX, PACKETS, "jabbers"),
  VNET_DEV_CTR_VENDOR (CDN_RXFCSCNT, RX, PACKETS, "fcs errors"),
  VNET_DEV_CTR_VENDOR (CDN_RXLENGTHCNT, RX, PACKETS, "length errors"),
  VNET_DEV_CTR_VENDOR (CDN_RXSYMBCNT, RX, PACKETS, "symbol errors"),
  VNET_DEV_CTR_VENDOR (CDN_RXALIGNCNT, RX, PACKETS, "alignment errors"),
  VNET_DEV_CTR_VENDOR (CDN_RXRESERRCNT, RX, PACKETS, "resource errors"),
  VNET_DEV_CTR_VENDOR (CDN_RXORCNT, RX, PACKETS, "overruns"),
  VNET_DEV_CTR_VENDOR (CDN_RXIPCCNT, RX, PACKETS, "ip checksum errors"),
  VNET_DEV_CTR_VENDOR (CDN_RXTCPCCNT, RX, PACKETS, "tcp checksum errors"),
  VNET_DEV_CTR_VENDOR (CDN_RXUDPCCNT, RX, PACKETS, "udp checksum errors"),
};

vnet_dev_rv_t
cdn_port_counters_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_port_add_counters (vm, port, cdn_port_counters, ARRAY_LEN (cdn_port_counters));

  return VNET_DEV_OK;
}

void
cdn_port_counter_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);

  foreach_vnet_dev_counter (c, port->counter_main)
    {
      u64 reg = c->user_data;
      u32 hi = 0;
      u32 lo;

      lo = cdn_reg_rd_nolog (cd, (u32) reg);
      reg >>= 32;
      if (reg)
	hi = cdn_reg_rd_nolog (cd, (u32) reg);

      vnet_dev_counter_value_add (vm, c, ((u64) hi << 32) | lo);
    }
}
