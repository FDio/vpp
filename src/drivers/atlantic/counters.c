/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <atlantic.h>

VLIB_REGISTER_LOG_CLASS (atl_log, static) = {
  .class_name = "atlantic",
  .subclass_name = "counters",
};

typedef enum
{
  ATL_FW_CTR_RX_OCTETS = 0,
  ATL_FW_CTR_RX_PAUSE,
  ATL_FW_CTR_RX_FRAMES,
  ATL_FW_CTR_RX_ERRORS,
  ATL_FW_CTR_RX_UNICAST,
  ATL_FW_CTR_RX_MULTICAST,
  ATL_FW_CTR_RX_BROADCAST,
  ATL_FW_CTR_TX_OCTETS,
  ATL_FW_CTR_TX_PAUSE,
  ATL_FW_CTR_TX_FRAMES,
  ATL_FW_CTR_TX_ERRORS,
  ATL_FW_CTR_TX_UNICAST,
  ATL_FW_CTR_TX_MULTICAST,
  ATL_FW_CTR_TX_BROADCAST,
  ATL_FW_N_CTR,
} atl_fw_ctr_idx_t;

static vnet_dev_counter_t atl_port_counters[] = {
  VNET_DEV_CTR_RX_PACKETS (ATL_FW_CTR_RX_FRAMES),
  VNET_DEV_CTR_TX_PACKETS (ATL_FW_CTR_TX_FRAMES),
  VNET_DEV_CTR_RX_BYTES (ATL_FW_CTR_RX_OCTETS),
  VNET_DEV_CTR_TX_BYTES (ATL_FW_CTR_TX_OCTETS),
  VNET_DEV_CTR_VENDOR (ATL_FW_CTR_RX_ERRORS, RX, PACKETS, "errors"),
  VNET_DEV_CTR_VENDOR (ATL_FW_CTR_TX_ERRORS, TX, PACKETS, "errors"),
  VNET_DEV_CTR_VENDOR (ATL_FW_CTR_RX_UNICAST, RX, PACKETS, "unicast"),
  VNET_DEV_CTR_VENDOR (ATL_FW_CTR_RX_MULTICAST, RX, PACKETS, "multicast"),
  VNET_DEV_CTR_VENDOR (ATL_FW_CTR_RX_BROADCAST, RX, PACKETS, "broadcast"),
  VNET_DEV_CTR_VENDOR (ATL_FW_CTR_TX_UNICAST, TX, PACKETS, "unicast"),
  VNET_DEV_CTR_VENDOR (ATL_FW_CTR_TX_MULTICAST, TX, PACKETS, "multicast"),
  VNET_DEV_CTR_VENDOR (ATL_FW_CTR_TX_BROADCAST, TX, PACKETS, "broadcast"),
  VNET_DEV_CTR_VENDOR (ATL_FW_CTR_RX_PAUSE, RX, PACKETS, "pause"),
  VNET_DEV_CTR_VENDOR (ATL_FW_CTR_TX_PAUSE, TX, PACKETS, "pause"),
};

vnet_dev_rv_t
atl_port_counters_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_port_add_counters (vm, port, atl_port_counters, ARRAY_LEN (atl_port_counters));

  return 0;
}

void
atl_port_counter_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  atl_port_t *ap = vnet_dev_get_port_data (port);
  u64 s[ATL_FW_N_CTR] = {};
  u32 w[ATL_FW_N_CTR * 2];
  vnet_dev_rv_t rv;

  /* Trigger FW to refresh stats snapshot via MPI mailbox */
  atl_reg_wr_u32 (dev, ATL_REG_AQ2_MIF_HOST_FINISHED_STATUS_WRITE, 1);

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_STATS, w, ARRAY_LEN (w));

  if (rv != VNET_DEV_OK)
    {
      if (ap->stats_fetch_fail == 0)
	log_err (dev, "FW stats fetch failed");
      ap->stats_fetch_fail = 1;
      return;
    }

  for (int i = 0; i < ATL_FW_N_CTR; i++)
    s[i] = ((u64) w[i * 2 + 1] << 32) | w[i * 2];

  if (ap->stats_fetch_fail)
    {
      log_notice (dev, "FW stats fetch restored");
      ap->stats_fetch_fail = 0;
    }

  foreach_vnet_dev_counter (c, port->counter_main)
    {
      u64 reg = c->user_data;

      ASSERT (reg < ATL_FW_N_CTR);
      vnet_dev_counter_value_update (vm, c, s[reg]);
    }
}
