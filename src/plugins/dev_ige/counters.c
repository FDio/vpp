/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_ige/ige.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#define _(hi, lo) ((u64) hi << 32 | lo)
static vnet_dev_counter_t ige_port_counters[] = {
  VNET_DEV_CTR_RX_BYTES (_ (0x40c4, 0x40c0)),
  VNET_DEV_CTR_TX_BYTES (_ (0x40cc, 0x40c8)),
  VNET_DEV_CTR_RX_PACKETS (0x40d0),
  VNET_DEV_CTR_TX_PACKETS (0x40d4),
  VNET_DEV_CTR_VENDOR (_ (0x408c, 0x4088), RX, BYTES, "good"),
  VNET_DEV_CTR_VENDOR (_ (0x4094, 0x4090), TX, BYTES, "good"),
  VNET_DEV_CTR_VENDOR (_ (0x412c, 0x4128), RX, BYTES, "host good"),
  VNET_DEV_CTR_VENDOR (_ (0x4134, 0x4130), TX, BYTES, "host good"),
  VNET_DEV_CTR_VENDOR (0x4104, RX, PACKETS, "host"),
  VNET_DEV_CTR_VENDOR (0x4000, RX, PACKETS, "CRC error"),
  VNET_DEV_CTR_VENDOR (0x4010, RX, PACKETS, "missed"),
  VNET_DEV_CTR_VENDOR (0x405c, RX, PACKETS, "64 bytes"),
  VNET_DEV_CTR_VENDOR (0x4060, RX, PACKETS, "65-127 byte"),
  VNET_DEV_CTR_VENDOR (0x4064, RX, PACKETS, "128-255 byte"),
  VNET_DEV_CTR_VENDOR (0x4068, RX, PACKETS, "256-511 byte"),
  VNET_DEV_CTR_VENDOR (0x406c, RX, PACKETS, "512-1023 byte"),
  VNET_DEV_CTR_VENDOR (0x4070, RX, PACKETS, ">=1024 byte"),
  VNET_DEV_CTR_VENDOR (0x4074, RX, PACKETS, "good"),
  VNET_DEV_CTR_VENDOR (0x4078, RX, PACKETS, "broadcast"),
  VNET_DEV_CTR_VENDOR (0x407c, RX, PACKETS, "multicast"),
  VNET_DEV_CTR_VENDOR (0x40d8, TX, PACKETS, "64 bytes"),
  VNET_DEV_CTR_VENDOR (0x40dc, TX, PACKETS, "65-127 byte"),
  VNET_DEV_CTR_VENDOR (0x40e0, TX, PACKETS, "128-255 byte"),
  VNET_DEV_CTR_VENDOR (0x40e4, TX, PACKETS, "256-511 byte"),
  VNET_DEV_CTR_VENDOR (0x40e8, TX, PACKETS, "512-1023 byte"),
  VNET_DEV_CTR_VENDOR (0x40ec, TX, PACKETS, ">=1024 byte"),
  VNET_DEV_CTR_VENDOR (0x40f0, TX, PACKETS, "multicast"),
  VNET_DEV_CTR_VENDOR (0x40f4, TX, PACKETS, "broadcast"),
  VNET_DEV_CTR_VENDOR (0x4108, NA, NA, "debug counter 1"),
  VNET_DEV_CTR_VENDOR (0x410c, NA, NA, "debug counter 2"),
  VNET_DEV_CTR_VENDOR (0x4110, NA, NA, "debug counter 3"),
  VNET_DEV_CTR_VENDOR (0x411c, NA, NA, "debug counter 4"),
};

vnet_dev_counter_t ige_rxq_counters[] = {
  VNET_DEV_CTR_RX_PACKETS (_ (0x100, 0x10010)),
  VNET_DEV_CTR_RX_BYTES (_ (0x100, 0x10018)),
  VNET_DEV_CTR_RX_DROPS (_ (0x40, 0xc030)),
  VNET_DEV_CTR_VENDOR (_ (0x100, 0x10038), RX, PACKETS, "multicast"),
};

vnet_dev_counter_t ige_txq_counters[] = {
  VNET_DEV_CTR_TX_PACKETS (_ (0x100, 0x10014)),
  VNET_DEV_CTR_TX_BYTES (_ (0x100, 0x10034)),
  VNET_DEV_CTR_TX_DROPS (_ (0x40, 0xe030)),
};
#undef _

vnet_dev_rv_t
ige_port_counters_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_port_add_counters (vm, port, ige_port_counters,
			      ARRAY_LEN (ige_port_counters));
  foreach_vnet_dev_port_rx_queue (rxq, port)
    vnet_dev_rx_queue_add_counters (vm, rxq, ige_rxq_counters,
				    ARRAY_LEN (ige_rxq_counters));
  foreach_vnet_dev_port_tx_queue (txq, port)
    vnet_dev_tx_queue_add_counters (vm, txq, ige_txq_counters,
				    ARRAY_LEN (ige_txq_counters));
  return 0;
}

static void
ppp (vnet_dev_t *dev, u32 r)
{
  u32 v;
  ige_reg_rd (dev, r, &v);
  if (v)
    fformat (stderr, "%05x: %08x", r, v);
}

void
ige_port_counter_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  u32 val;

  foreach_vnet_dev_counter (c, port->counter_main)
    {
      u64 reg = c->user_data;
      u32 hi = 0, lo;
      ige_reg_rd (dev, (u32) reg, &lo);
      reg >>= 32;
      if (reg)
	ige_reg_rd (dev, (u32) reg, &hi);

      vnet_dev_counter_value_add (vm, c, (u64) hi << 32 | lo);
    }

  foreach_vnet_dev_port_rx_queue (rxq, port)
    if (rxq->started)
      foreach_vnet_dev_counter (c, rxq->counter_main)
	{
	  u32 reg = (u32) c->user_data + (c->user_data >> 32) * rxq->queue_id;
	  ige_reg_rd (dev, reg, &val);
	  vnet_dev_counter_value_update (vm, c, val);
	}

  foreach_vnet_dev_port_tx_queue (txq, port)
    if (txq->started)
      foreach_vnet_dev_counter (c, txq->counter_main)
	{
	  u32 reg = (u32) c->user_data + (c->user_data >> 32) * txq->queue_id;
	  ige_reg_rd (dev, reg, &val);
	  vnet_dev_counter_value_update (vm, c, val);
	}

  for (u32 r = 0x4000; r < 0x413a; r += 4)
    ppp (dev, r);
}
