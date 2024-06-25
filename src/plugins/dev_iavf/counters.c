/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <dev_iavf/iavf.h>
#include <dev_iavf/virtchnl.h>
#include <dev_iavf/virtchnl_funcs.h>

VLIB_REGISTER_LOG_CLASS (iavf_log, static) = {
  .class_name = "iavf",
  .subclass_name = "counters",
};

typedef enum
{
  IIAVF_PORT_CTR_RX_BYTES,
  IIAVF_PORT_CTR_TX_BYTES,
  IIAVF_PORT_CTR_RX_PACKETS,
  IIAVF_PORT_CTR_TX_PACKETS,
  IIAVF_PORT_CTR_RX_DROPS,
  IIAVF_PORT_CTR_TX_DROPS,
  IIAVF_PORT_CTR_RX_UCAST,
  IIAVF_PORT_CTR_TX_UCAST,
  IIAVF_PORT_CTR_RX_MCAST,
  IIAVF_PORT_CTR_TX_MCAST,
  IIAVF_PORT_CTR_RX_BCAST,
  IIAVF_PORT_CTR_TX_BCAST,
  IIAVF_PORT_CTR_RX_UNKNOWN_PROTOCOL,
  IIAVF_PORT_CTR_TX_ERRORS,
} iavf_port_counter_id_t;

vnet_dev_counter_t iavf_port_counters[] = {
  VNET_DEV_CTR_RX_BYTES (IIAVF_PORT_CTR_RX_BYTES),
  VNET_DEV_CTR_RX_PACKETS (IIAVF_PORT_CTR_RX_PACKETS),
  VNET_DEV_CTR_RX_DROPS (IIAVF_PORT_CTR_RX_DROPS),
  VNET_DEV_CTR_VENDOR (IIAVF_PORT_CTR_RX_UCAST, RX, PACKETS, "unicast"),
  VNET_DEV_CTR_VENDOR (IIAVF_PORT_CTR_RX_MCAST, RX, PACKETS, "multicast"),
  VNET_DEV_CTR_VENDOR (IIAVF_PORT_CTR_RX_BCAST, RX, PACKETS, "broadcast"),
  VNET_DEV_CTR_VENDOR (IIAVF_PORT_CTR_RX_UNKNOWN_PROTOCOL, RX, PACKETS,
		       "unknown protocol"),

  VNET_DEV_CTR_TX_BYTES (IIAVF_PORT_CTR_TX_BYTES),
  VNET_DEV_CTR_TX_PACKETS (IIAVF_PORT_CTR_TX_PACKETS),
  VNET_DEV_CTR_TX_DROPS (IIAVF_PORT_CTR_TX_DROPS),
  VNET_DEV_CTR_VENDOR (IIAVF_PORT_CTR_TX_UCAST, TX, PACKETS, "unicast"),
  VNET_DEV_CTR_VENDOR (IIAVF_PORT_CTR_TX_MCAST, TX, PACKETS, "multicast"),
  VNET_DEV_CTR_VENDOR (IIAVF_PORT_CTR_TX_BCAST, TX, PACKETS, "broadcast"),
  VNET_DEV_CTR_VENDOR (IIAVF_PORT_CTR_TX_ERRORS, TX, PACKETS, "errors"),
};

void
iavf_port_add_counters (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_port_add_counters (vm, port, iavf_port_counters,
			      ARRAY_LEN (iavf_port_counters));
}

void
iavf_port_poll_stats (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv;
  vnet_dev_t *dev = port->dev;
  virtchnl_eth_stats_t stats;
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  virtchnl_queue_select_t qs = { .vsi_id = ap->vsi_id };

  rv = iavf_vc_op_get_stats (vm, dev, &qs, &stats);

  if (rv != VNET_DEV_OK)
    return;

  foreach_vnet_dev_counter (c, port->counter_main)
    {
      switch (c->user_data)
	{
	case IIAVF_PORT_CTR_RX_BYTES:
	  vnet_dev_counter_value_update (vm, c, stats.rx_bytes);
	  break;
	case IIAVF_PORT_CTR_TX_BYTES:
	  vnet_dev_counter_value_update (vm, c, stats.tx_bytes);
	  break;
	case IIAVF_PORT_CTR_RX_PACKETS:
	  vnet_dev_counter_value_update (
	    vm, c, stats.rx_unicast + stats.rx_broadcast + stats.rx_multicast);
	  break;
	case IIAVF_PORT_CTR_TX_PACKETS:
	  vnet_dev_counter_value_update (
	    vm, c, stats.tx_unicast + stats.tx_broadcast + stats.tx_multicast);
	  break;
	case IIAVF_PORT_CTR_RX_DROPS:
	  vnet_dev_counter_value_update (vm, c, stats.rx_discards);
	  break;
	case IIAVF_PORT_CTR_TX_DROPS:
	  vnet_dev_counter_value_update (vm, c, stats.tx_discards);
	  break;
	case IIAVF_PORT_CTR_RX_UCAST:
	  vnet_dev_counter_value_update (vm, c, stats.rx_unicast);
	  break;
	case IIAVF_PORT_CTR_TX_UCAST:
	  vnet_dev_counter_value_update (vm, c, stats.tx_unicast);
	  break;
	case IIAVF_PORT_CTR_RX_MCAST:
	  vnet_dev_counter_value_update (vm, c, stats.rx_multicast);
	  break;
	case IIAVF_PORT_CTR_TX_MCAST:
	  vnet_dev_counter_value_update (vm, c, stats.tx_multicast);
	  break;
	case IIAVF_PORT_CTR_RX_BCAST:
	  vnet_dev_counter_value_update (vm, c, stats.rx_broadcast);
	  break;
	case IIAVF_PORT_CTR_TX_BCAST:
	  vnet_dev_counter_value_update (vm, c, stats.tx_broadcast);
	  break;
	case IIAVF_PORT_CTR_RX_UNKNOWN_PROTOCOL:
	  vnet_dev_counter_value_update (vm, c, stats.rx_unknown_protocol);
	  break;
	case IIAVF_PORT_CTR_TX_ERRORS:
	  vnet_dev_counter_value_update (vm, c, stats.tx_errors);
	  break;
	default:
	  ASSERT (0);
	}
    }
}
