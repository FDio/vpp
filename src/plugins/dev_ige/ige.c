/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_ige/ige.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (ige_log, static) = {
  .class_name = "dev_ige",
  .subclass_name = "init",
};

#define log_debug(id, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, ige_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_info(id, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_INFO, ige_log.class, "%U: " f,                     \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_notice(id, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, ige_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_warn(id, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_WARNING, ige_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_err(id, f, ...)                                                   \
  vlib_log (VLIB_LOG_LEVEL_ERR, ige_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)

vnet_dev_node_fn_t ige_rx_node_fn = {};
vnet_dev_node_fn_t ige_tx_node_fn = {};

typedef enum
{
  IGE_DEV_TYPE_I211,
  IGE_DEV_TYPE_I225,
  IGE_DEV_TYPE_I226,
} __clib_packed ige_dev_type_t;

static ige_dev_flags_t flags_by_type[] = {
  [IGE_DEV_TYPE_I211] = {},
  [IGE_DEV_TYPE_I225] = { .supports_2_5g = 1 },
  [IGE_DEV_TYPE_I226] = { .supports_2_5g = 1 },
};

static struct
{
  u16 device_id;
  ige_dev_type_t type;
  char *description;
} ige_dev_types[] = {

#define _(id, t, desc)                                                        \
  {                                                                           \
    .device_id = (id), .type = IGE_DEV_TYPE_##t, .description = (desc)        \
  }

  _ (0x1539, I211, "Intel(R) Ethernet Controller I211"),
  _ (0x15f2, I225, "Intel(R) Ethernet Controller I225-LM"),
  _ (0x15f3, I225, "Intel(R) Ethernet Controller I225-V"),
  _ (0x0d9f, I225, "Intel(R) Ethernet Controller I225-IT"),
  _ (0x125b, I226, "Intel(R) Ethernet Controller I226-LM"),
  _ (0x125c, I226, "Intel(R) Ethernet Controller I226-V"),
  _ (0x125d, I226, "Intel(R) Ethernet Controller I226-IT"),
#undef _
};

static u8 *
ige_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;

  if (di->vendor_id != 0x8086)
    return 0;

  FOREACH_ARRAY_ELT (dt, ige_dev_types)
    {
      if (dt->device_id == di->device_id)
	return format (0, "%s", dt->description);
    }

  return 0;
}

#define _(hi, lo) ((u64) hi << 32 | lo)
vnet_dev_counter_t ige_port_counters[] = {
  VNET_DEV_COUNTER_RX_BYTES (_ (0x40c4, 0x40c0)),
  VNET_DEV_COUNTER_TX_BYTES (_ (0x40cc, 0x40c8)),
  VNET_DEV_COUNTER_RX_PACKETS (0x40d0),
  VNET_DEV_COUNTER_TX_PACKETS (0x40d4),
  VNET_DEV_COUNTER_VENDOR (_ (0x408c, 0x4088), RX, BYTES, "good"),
  VNET_DEV_COUNTER_VENDOR (_ (0x4094, 0x4090), TX, BYTES, "good"),
  VNET_DEV_COUNTER_VENDOR (_ (0x412c, 0x4128), RX, BYTES, "host good"),
  VNET_DEV_COUNTER_VENDOR (_ (0x4134, 0x4130), TX, BYTES, "host good"),
  VNET_DEV_COUNTER_VENDOR (0x4104, RX, PACKETS, "host"),
  VNET_DEV_COUNTER_VENDOR (0x4000, RX, PACKETS, "CRC error"),
  VNET_DEV_COUNTER_VENDOR (0x4010, RX, PACKETS, "missed"),
  VNET_DEV_COUNTER_VENDOR (0x405c, RX, PACKETS, "64 bytes"),
  VNET_DEV_COUNTER_VENDOR (0x4060, RX, PACKETS, "65-127 byte"),
  VNET_DEV_COUNTER_VENDOR (0x4064, RX, PACKETS, "128-255 byte"),
  VNET_DEV_COUNTER_VENDOR (0x4068, RX, PACKETS, "256-511 byte"),
  VNET_DEV_COUNTER_VENDOR (0x406c, RX, PACKETS, "512-1023 byte"),
  VNET_DEV_COUNTER_VENDOR (0x4070, RX, PACKETS, ">=1024 byte"),
  VNET_DEV_COUNTER_VENDOR (0x4074, RX, PACKETS, "good"),
  VNET_DEV_COUNTER_VENDOR (0x4078, RX, PACKETS, "broadcast"),
  VNET_DEV_COUNTER_VENDOR (0x407c, RX, PACKETS, "multicast"),
  VNET_DEV_COUNTER_VENDOR (0x40d8, TX, PACKETS, "64 bytes"),
  VNET_DEV_COUNTER_VENDOR (0x40dc, TX, PACKETS, "65-127 byte"),
  VNET_DEV_COUNTER_VENDOR (0x40e0, TX, PACKETS, "128-255 byte"),
  VNET_DEV_COUNTER_VENDOR (0x40e4, TX, PACKETS, "256-511 byte"),
  VNET_DEV_COUNTER_VENDOR (0x40e8, TX, PACKETS, "512-1023 byte"),
  VNET_DEV_COUNTER_VENDOR (0x40ec, TX, PACKETS, ">=1024 byte"),
  VNET_DEV_COUNTER_VENDOR (0x40f0, TX, PACKETS, "multicast"),
  VNET_DEV_COUNTER_VENDOR (0x40f4, TX, PACKETS, "broadcast"),
  VNET_DEV_COUNTER_VENDOR (0x4108, NA, NA, "debug counter 1"),
  VNET_DEV_COUNTER_VENDOR (0x410c, NA, NA, "debug counter 2"),
  VNET_DEV_COUNTER_VENDOR (0x4110, NA, NA, "debug counter 3"),
  VNET_DEV_COUNTER_VENDOR (0x411c, NA, NA, "debug counter 4"),
};

vnet_dev_counter_t ige_rxq_counters[] = {
  VNET_DEV_COUNTER_RX_PACKETS (_ (0x100, 0x10010)),
  VNET_DEV_COUNTER_RX_BYTES (_ (0x100, 0x10018)),
  VNET_DEV_COUNTER_RX_DROPS (_ (0x40, 0xc030)),
  VNET_DEV_COUNTER_VENDOR (_ (0x100, 0x10038), RX, PACKETS, "multicast"),
};

vnet_dev_counter_t ige_txq_counters[] = {
  VNET_DEV_COUNTER_TX_PACKETS (_ (0x100, 0x10014)),
  VNET_DEV_COUNTER_TX_BYTES (_ (0x100, 0x10034)),
  VNET_DEV_COUNTER_TX_DROPS (_ (0x40, 0xe030)),
};
#undef _

static vnet_dev_rv_t
ige_err (ige_device_t *id, vnet_dev_rv_t rv, char *fmt, ...)
{
  va_list va;
  u8 *s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);
  log_err (id, "%v", s);
  vec_free (s);
  return rv;
}

static void
ige_reg_rd (ige_device_t *id, u32 reg, u32 *val)
{
  u32 rv = __atomic_load_n ((u32 *) ((u8 *) id->bar0 + reg), __ATOMIC_ACQUIRE);
  *val = rv;
}

static_always_inline void
ige_reg_wr (ige_device_t *id, u32 reg, u32 val)
{
  __atomic_store_n ((u32 *) ((u8 *) id->bar0 + reg), val, __ATOMIC_RELEASE);
}

static int
ige_reg_poll (vlib_main_t *vm, ige_device_t *id, u32 reg, u32 mask, u32 match,
	      f64 intial_delay, f64 timeout)
{
  f64 t0 = vlib_time_now (vm);
  u32 val;

  for (f64 delay = intial_delay, total_time = delay; total_time < timeout;
       delay *= 2, total_time += delay)
    {
      ige_reg_rd (id, reg, &val);
      if ((val & mask) == match)
	{
	  log_debug (id, "reg_poll: reg %05x (suspend %.6f)", reg,
		     vlib_time_now (vm) - t0);
	  return 1;
	}
      vlib_process_suspend (vm, delay);
    }
  log_debug (id, "reg_poll: reg %05x timeout", reg);
  return 0;
}

static void
ige_reg_sw_fw_sync_release (vlib_main_t *vm, ige_device_t *id)
{
  ige_reg_swsm_t swsm;
  log_debug (id, "reg_sw_fw_sync_release:");
  ige_reg_rd (id, IGE_REG_SWSM, &swsm.as_u32);
  swsm.smbi = 0;
  swsm.swesmbi = 0;
  ige_reg_wr (id, IGE_REG_SWSM, swsm.as_u32);
}

static int
ige_reg_sw_fw_sync_acquire (vlib_main_t *vm, ige_device_t *id)
{
  ige_reg_swsm_t swsm;
  int i, timeout = 10;

  log_debug (id, "reg_sw_fw_sync_acquire:");
  for (i = 0; i < timeout * 2; i++)
    {
      if (i == timeout)
	{
	  log_debug (id,
		     "reg_sw_fw_sync_acquire: timeout, attempt to cleor SWSM");
	  swsm.smbi = 0;
	  swsm.swesmbi = 0;
	  ige_reg_wr (id, IGE_REG_SWSM, swsm.as_u32);
	}
      ige_reg_rd (id, IGE_REG_SWSM, &swsm.as_u32);
      if (swsm.smbi == 0)
	break;
      vlib_process_suspend (vm, 5e-5);
    }

  if (i == timeout)
    {
      log_debug (id, "reg_sw_fw_sync_acquire: timeout acquiring SWSM");
      return 0;
    }

  for (i = 0; i < timeout; i++)
    {
      swsm.swesmbi = 1;
      ige_reg_wr (id, IGE_REG_SWSM, swsm.as_u32);
      ige_reg_rd (id, IGE_REG_SWSM, &swsm.as_u32);
      if (swsm.swesmbi == 1)
	break;
      vlib_process_suspend (vm, 5e-5);
    }

  if (i == timeout)
    {
      swsm.smbi = 0;
      swsm.swesmbi = 0;
      ige_reg_wr (id, IGE_REG_SWSM, swsm.as_u32);
      log_debug (id, "reg_sw_fw_sync_acquire: timeout acquring SWSMBI");
      return 0;
    }

  log_debug (id, "reg_sw_fw_sync_acquire: acquired");
  return 1;
}

static vnet_dev_rv_t
ige_phy_acquire (vlib_main_t *vm, ige_device_t *id)
{
  ige_reg_sw_fw_sync_t sw_fw_sync;
  int n_tries = 5;

  log_debug (id, "phy_acquire:");

  while (n_tries-- > 0)
    {
      if (ige_reg_sw_fw_sync_acquire (vm, id))
	{
	  ige_reg_rd (id, IGE_REG_SW_FW_SYNC, &sw_fw_sync.as_u32);
	  log_debug (id, "phy_acquire: sw_fw_sync 0x%04x");

	  if (sw_fw_sync.fw_phy_sm == 0)
	    {
	      sw_fw_sync.sw_phy_sm = 1;
	      ige_reg_wr (id, IGE_REG_SW_FW_SYNC, sw_fw_sync.as_u32);
	      ige_reg_sw_fw_sync_release (vm, id);
	      return 0;
	    }

	  ige_reg_sw_fw_sync_release (vm, id);
	}
      vlib_process_suspend (vm, 1e-4);
    }
  return ige_err (id, VNET_DEV_ERR_TIMEOUT, "failed to acquire PHY");
}

static vnet_dev_rv_t
ige_phy_release (vlib_main_t *vm, ige_device_t *id)
{
  ige_reg_sw_fw_sync_t sw_fw_sync;

  log_debug (id, "phy_release:");

  /* release phy */
  if (ige_reg_sw_fw_sync_acquire (vm, id) == 0)
    return ige_err (id, VNET_DEV_ERR_TIMEOUT, "sw_fw_sync ownership timeout");

  sw_fw_sync.sw_phy_sm = 0;
  ige_reg_wr (id, IGE_REG_SW_FW_SYNC, sw_fw_sync.as_u32);
  ige_reg_sw_fw_sync_release (vm, id);

  return 0;
}

static vnet_dev_rv_t
ige_phy_read (vlib_main_t *vm, ige_device_t *id, u16 addr, u16 *data)
{
  ige_reg_mdic_t mdic = { .regadd = addr, .opcode = 2 };
  int n_tries = 10;
  f64 t;

  t = vlib_time_now (vm);
  ige_reg_wr (id, IGE_REG_MDIC, mdic.as_u32);
  vlib_process_suspend (vm, 5e-5);
  ige_reg_rd (id, IGE_REG_MDIC, &mdic.as_u32);

  while (mdic.ready == 0 && n_tries-- > 0)
    {
      vlib_process_suspend (vm, 2e-5);
      ige_reg_rd (id, IGE_REG_MDIC, &mdic.as_u32);
    }

  t = vlib_time_now (vm) - t;
  if (t > 1e-4)
    log_warn (id, "phy_read: register read took %.06f sec", t);

  if (mdic.ready == 0)
    return ige_err (id, VNET_DEV_ERR_TIMEOUT, "phy read timeout");

  log_debug (id, "phy_read: addr 0x%02x data 0x%04x", addr, mdic.data);
  *data = mdic.data;
  return 0;
}

static vnet_dev_rv_t
ige_port_status_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ige_device_t *id = vnet_dev_get_data (port->dev);
  ige_port_t *ip = vnet_dev_get_port_data (port);
  ige_reg_status_t status;

  ige_reg_rd (id, IGE_REG_STATUS, &status.as_u32);

  if (ip->last_status.as_u32 != status.as_u32)
    {
      vnet_dev_port_state_changes_t changes = {};

      log_debug (id, "port_status_poll: %U", format_ige_reg_diff,
		 IGE_REG_STATUS, ip->last_status.as_u32, status.as_u32);

      if (ip->last_status.link_up != status.link_up)
	{
	  changes.change.link_state = 1;
	  changes.link_state = status.link_up;
	  log_debug (id, "port_poll: link state changed to %s",
		     status.link_up ? "up" : "down");
	}

      if (ip->last_status.full_duplex != status.full_duplex)
	{
	  changes.change.link_duplex = 1;
	  changes.full_duplex = status.full_duplex;
	  log_debug (id, "port_poll: duplex changed to %s",
		     status.full_duplex ? "full" : "half");
	}

      if (ip->last_status.speed != status.speed ||
	  ip->last_status.speed_2p5 != status.speed_2p5)
	{
	  const u32 link_speeds[8] = {
	    [0b000] = 10000,
	    [0b001] = 100000,
	    [0b010] = 1000000,
	    [0b110] = 2500000,
	  };
	  changes.change.link_speed = 1;
	  changes.link_speed =
	    link_speeds[status.speed_2p5 << 2 | status.speed];
	  if (changes.link_speed)
	    log_debug (id, "port_poll: link speed changed to %u Mbps",
		       changes.link_speed / 1000);
	  else
	    log_warn (id,
		      "port_poll: device reported unknown speed (speed %u "
		      "speed_2p5 %u)",
		      status.speed, status.speed_2p5);
	}
      ip->last_status.as_u32 = status.as_u32;
      if (changes.change.any)
	vnet_dev_port_state_change (vm, port, changes);
    }
  return 0;
}

static void
ppp (ige_device_t *id, u32 r)
{
  u32 v;
  ige_reg_rd (id, r, &v);
  if (v)
    log_debug (id, "%05x: %08x", r, v);
}

static vnet_dev_rv_t
ige_port_counter_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ige_device_t *id = vnet_dev_get_data (port->dev);

  foreach_vnet_dev_counter (c, port->counter_main)
    {
      u64 reg = c->user_data;
      u32 hi = 0, lo;
      ige_reg_rd (id, (u32) reg, &lo);
      reg >>= 32;
      if (reg)
	ige_reg_rd (id, (u32) reg, &hi);

      vnet_dev_counter_value_add (vm, port->counter_main, c,
				  (u64) hi << 32 | lo);
    }

  pool_foreach_pointer (rxq, port->rx_queues)
    if (rxq->started)
      foreach_vnet_dev_counter (c, rxq->counter_main)
	{
	  u32 reg = (u32) c->user_data + (c->user_data >> 32) * rxq->queue_id;
	  u32 val;
	  ige_reg_rd (id, reg, &val);
	  vnet_dev_counter_value_set (vm, rxq->counter_main, c, val);
	}

  pool_foreach_pointer (txq, port->tx_queues)
    if (txq->started)
      foreach_vnet_dev_counter (c, txq->counter_main)
	{
	  u32 reg = (u32) c->user_data + (c->user_data >> 32) * txq->queue_id;
	  u32 val;
	  ige_reg_rd (id, reg, &val);
	  vnet_dev_counter_value_set (vm, txq->counter_main, c, val);
	}

  for (u32 r = 0x4000; r < 0x413a; r += 4)
    ppp (id, r);

  return 0;
}

static vnet_dev_rv_t
ige_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ige_device_t *id = vnet_dev_get_data (port->dev);
  log_debug (id, "port init: port %u", port->port_id);

  vnet_dev_port_add_counters (vm, port, ige_port_counters,
			      ARRAY_LEN (ige_port_counters));
  pool_foreach_pointer (rxq, port->rx_queues)
    vnet_dev_rx_queue_add_counters (vm, rxq, ige_rxq_counters,
				    ARRAY_LEN (ige_rxq_counters));
  pool_foreach_pointer (txq, port->tx_queues)
    vnet_dev_tx_queue_add_counters (vm, txq, ige_txq_counters,
				    ARRAY_LEN (ige_txq_counters));
  vnet_dev_poll_port_add (vm, port, 1, ige_port_status_poll);
  return 0;
}

static vnet_dev_rv_t
ige_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ige_device_t *id = vnet_dev_get_data (port->dev);
  ige_rxq_t *iq;
  ige_reg_rctl_t rctl;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (id, "port start: port %u", port->port_id);

  pool_foreach_pointer (rxq, port->rx_queues)
    {
      iq = vnet_dev_get_rx_queue_data (rxq);
      iq->tail = vlib_buffer_alloc_from_pool (
	vm, iq->buffer_indices, rxq->size, rxq->buffer_pool_index);

      if (iq->tail == 0)
	rv = VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
    }

  if (rv != VNET_DEV_OK)
    {
      pool_foreach_pointer (rxq, port->rx_queues)
	{
	  iq = vnet_dev_get_rx_queue_data (rxq);
	  if (iq->tail)
	    vlib_buffer_free (vm, iq->buffer_indices, iq->tail);
	  iq->tail = 0;
	}
      return rv;
    }

  ige_reg_rd (id, IGE_REG_RCTL, &rctl.as_u32);
  if (rctl.rx_enable)
    {
      log_warn (id, "port_start: port %u rx is unexpectedlly enabled",
		port->port_id);
      rctl.rx_enable = 0;
      ige_reg_wr (id, IGE_REG_RCTL, rctl.as_u32);
    }

  pool_foreach_pointer (rxq, port->rx_queues)
    {
      const ige_reg_srrctl_t srrctl = {
	.drop_en = 1,
	.desc_type = 1,	  /* advanced, no header */
	.bsizepacket = 2, /* 2k */
			  //.bsizeheader = 2, /* 128 B */
      };

      const ige_reg_rxdctl_t rxdctl = {
	.pthresh = 12,
	.hthresh = 10,
	.wthresh = 1,
	.enable = 1,
      };

      u64 dma_addr;
      u16 q = rxq->queue_id;
      ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

      dma_addr = vnet_dev_get_dma_addr (vm, dev, iq->descs);
      ige_reg_wr (id, IGE_REG_RDLEN (q), rxq->size * sizeof (ige_rx_desc_t));
      ige_reg_wr (id, IGE_REG_RDBAH (q), dma_addr >> 32);
      ige_reg_wr (id, IGE_REG_RDBAL (q), dma_addr);
      ige_reg_wr (id, IGE_REG_SRRCTL (q), srrctl.as_u32);
      ige_reg_wr (id, IGE_REG_RXDCTL (q), rxdctl.as_u32);
      iq->head = 0;
      iq->tail = 0;
      iq->reg_rdt = (u32 *) ((u8 *) id->bar0 + IGE_REG_RDT (q));
    }

  rctl.rx_enable = 1;
  rctl.store_bad_packets = 0;
  rctl.strip_eth_crc = 1;
  rctl.long_pkt_reception_ena = 0;
  rctl.vlan_filter_ena = 0;
  rctl.bcast_accept_mode = 1;
  rctl.discard_pause_frames = 1;
  ige_reg_wr (id, IGE_REG_RCTL, rctl.as_u32);

  pool_foreach_pointer (rxq, port->rx_queues)
    {
      u16 q = rxq->queue_id;

      ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      ige_reg_wr (id, IGE_REG_RDH (q), 0);
      ige_reg_wr (id, IGE_REG_RDT (q), iq->tail);
    }

  vnet_dev_poll_port_add (vm, port, 3, ige_port_counter_poll);
  return 0;
}

static void
ige_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ige_device_t *id = vnet_dev_get_data (port->dev);
  log_debug (id, "port stop: port %u", port->port_id);
  ige_reg_rctl_t rctl;
  u32 i;
  vnet_dev_poll_port_remove (vm, port, ige_port_counter_poll);

  ige_reg_rd (id, IGE_REG_RCTL, &rctl.as_u32);
  rctl.rx_enable = 0;
  ige_reg_wr (id, IGE_REG_RCTL, rctl.as_u32);
  pool_foreach_index (i, port->rx_queues)
    {
      vnet_dev_rx_queue_t *rxq = *pool_elt_at_index (port->rx_queues, i);
      ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      vlib_buffer_free_from_ring_no_next (vm, iq->buffer_indices, iq->head,
					  rxq->size, iq->tail - iq->head);
    }
}

static vnet_dev_rv_t
ige_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ige_device_t *id = vnet_dev_get_data (dev);
  ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rv_t rv;

  if (id->avail_rxq_bmp == 0)
    {
      log_err (id, "rx_queue_alloc: no available queues");
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  rxq->queue_id = get_lowest_set_bit_index (id->avail_rxq_bmp);
  id->avail_rxq_bmp ^= 1 << rxq->queue_id;

  iq->buffer_indices = clib_mem_alloc_aligned (
    rxq->size * sizeof (iq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);
  clib_memset_u32 (iq->buffer_indices, 0, rxq->size);

  rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (ige_rx_desc_t) * rxq->size, 0,
			       (void **) &iq->descs);
  if (rv != VNET_DEV_OK)
    return rv;

  log_debug (id, "rx_queue_alloc: queue %u alocated", rxq->queue_id);
  return rv;
}

static void
ige_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ige_device_t *id = vnet_dev_get_data (dev);
  ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

  log_debug (id, "rx_queue_free: queue %u", rxq->queue_id);

  id->avail_rxq_bmp |= 1 << rxq->queue_id;
  vnet_dev_dma_mem_free (vm, dev, iq->descs);
}

static vnet_dev_rv_t
ige_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ige_device_t *id = vnet_dev_get_data (dev);
  if (id->avail_txq_bmp == 0)
    {
      log_err (id, "tx_queue_alloc: no available queues");
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }
  txq->queue_id = get_lowest_set_bit_index (id->avail_txq_bmp);
  id->avail_txq_bmp ^= 1 << txq->queue_id;
  log_debug (id, "tx_queue_alloc: queue %u alocated", txq->queue_id);
  return VNET_DEV_OK;
}

static void
ige_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ige_device_t *id = vnet_dev_get_data (dev);
  log_debug (id, "tx_queue_free: queue %u", txq->queue_id);
  id->avail_txq_bmp |= 1 << txq->queue_id;
}

static vnet_dev_rv_t
ige_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  ige_device_t *id = vnet_dev_get_data (dev);
  vlib_pci_config_hdr_t pci_hdr;
  vnet_dev_rv_t rv;
  u32 match, mask, tmp;

  rv = vnet_dev_pci_read_config_header (vm, dev, &pci_hdr);
  if (rv != VNET_DEV_OK)
    return rv;

  if (pci_hdr.vendor_id != 0x8086)
    return VNET_DEV_ERR_UNSUPPORTED_DEV;

  rv = VNET_DEV_ERR_UNSUPPORTED_DEV;

  FOREACH_ARRAY_ELT (dt, ige_dev_types)
    if (dt->device_id == pci_hdr.device_id)
      {
	id->dev_flags = flags_by_type[dt->type];
	rv = VNET_DEV_OK;
	break;
      }

  if (rv != VNET_DEV_OK)
    return rv;

  /* map BAR0 */
  if (id->bar0 == 0)
    {
      rv = vnet_dev_pci_map_region (vm, dev, 0, &id->bar0);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  /* disable interrupts */
  ige_reg_wr (id, IGE_REG_IMC, 0xffffffff);
  ige_reg_rd (id, IGE_REG_ICR, &tmp);

  rv = vnet_dev_pci_function_level_reset (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = vnet_dev_pci_bus_master_enable (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  mask = (ige_reg_status_t){ .rst_done = 1 }.as_u32;
  match = mask;

  if (ige_reg_poll (vm, id, IGE_REG_STATUS, mask, match, 1e-5, 1e-1) == 0)
    return ige_err (id, VNET_DEV_ERR_TIMEOUT, "reset timeout");

  /* disable interrupts again */
  ige_reg_wr (id, IGE_REG_IMC, 0xffffffff);
  ige_reg_rd (id, IGE_REG_ICR, &tmp);

  /* notify ME that driver is loaded */
  ige_reg_ctrl_ext_t ctrl_ext;
  ige_reg_rd (id, IGE_REG_CTRL_EXT, &ctrl_ext.as_u32);
  ctrl_ext.driver_loaded = 1;
  ige_reg_wr (id, IGE_REG_CTRL_EXT, ctrl_ext.as_u32);

  if (0)
    {
      u16 d[32] = {};
      if ((rv = ige_phy_acquire (vm, id)))
	return rv;
      for (int i = 0; i < 32; i++)
	{
	  if ((rv = ige_phy_read (vm, id, i, d + i)))
	    return rv;
	}
      if ((rv = ige_phy_release (vm, id)))
	return rv;

      fformat (stderr, "PHY dump %U\n", format_hexdump_u16, d, 32);
    }

  vnet_dev_port_add_args_t port = {
    .port = {
      .config = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
        .data_size = sizeof (ige_port_t),
        .max_rx_queues = 4,
        .max_tx_queues = 4,
        .max_frame_size = 9728,
      },
      .ops = {
        .init = ige_port_init,
        .start = ige_port_start,
        .stop = ige_port_stop,
        .format_status = format_ige_port_status,
      },
    },
    .rx_node = {
        .node_fn = &ige_rx_node_fn,
    },
    .tx_node = {
        .node_fn = &ige_tx_node_fn,
    },
    .rx_queue = {
      .config = {
        .data_size = sizeof (ige_rxq_t),
        .default_size = 512,
        .multiplier = 8,
        .min_size = 32,
        .max_size = 32768,
      },
      .ops = {
        .alloc = ige_rx_queue_alloc,
        .free = ige_rx_queue_free,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (ige_txq_t),
        .default_size = 512,
        .multiplier = 8,
        .min_size = 32,
        .max_size = 32768,
      },
      .ops = {
        .alloc = ige_tx_queue_alloc,
        .free = ige_tx_queue_free,
      },
    },
  };

  ige_reg_rd (id, IGE_REG_RAL0, &tmp);
  clib_memcpy (&port.port.config.hw_addr[0], &tmp, 4);
  ige_reg_rd (id, IGE_REG_RAH0, &tmp);
  clib_memcpy (&port.port.config.hw_addr[4], &tmp, 2);
  log_info (id, "MAC address is %U", format_ethernet_address,
	    port.port.config.hw_addr);

  id->avail_rxq_bmp = pow2_mask (4);
  id->avail_txq_bmp = pow2_mask (4);
  vnet_dev_port_add (vm, dev, 0, &port);
  return 0;
}

static void
ige_free (vlib_main_t *vm, vnet_dev_t *dev)
{
}

VNET_DEV_REGISTER_DRIVER (ige) = {
  .name = "ige",
  .bus = "pci",
  .device_data_sz = sizeof (ige_device_t),
  .ops = {
    .device_init = ige_init,
    .device_free = ige_free,
    .probe = ige_probe,
  },
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_ige",
};
