/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <dev_octeon/octeon.h>
#include <dev_octeon/common.h>

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "oct",
  .subclass_name = "counters",
};

typedef enum
{
  OCT_PORT_CTR_RX_BYTES,
  OCT_PORT_CTR_TX_BYTES,
  OCT_PORT_CTR_RX_PACKETS,
  OCT_PORT_CTR_TX_PACKETS,
  OCT_PORT_CTR_RX_DROPS,
  OCT_PORT_CTR_TX_DROPS,
  OCT_PORT_CTR_RX_DROP_BYTES,
  OCT_PORT_CTR_RX_UCAST,
  OCT_PORT_CTR_TX_UCAST,
  OCT_PORT_CTR_RX_MCAST,
  OCT_PORT_CTR_TX_MCAST,
  OCT_PORT_CTR_RX_BCAST,
  OCT_PORT_CTR_TX_BCAST,
  OCT_PORT_CTR_RX_FCS,
  OCT_PORT_CTR_RX_ERR,
  OCT_PORT_CTR_RX_DROP_MCAST,
  OCT_PORT_CTR_RX_DROP_BCAST,
  OCT_PORT_CTR_RX_DROP_L3_MCAST,
  OCT_PORT_CTR_RX_DROP_L3_BCAST,
} oct_port_counter_id_t;

vnet_dev_counter_t oct_port_counters[] = {
  VNET_DEV_CTR_RX_BYTES (OCT_PORT_CTR_RX_BYTES),
  VNET_DEV_CTR_RX_PACKETS (OCT_PORT_CTR_RX_PACKETS),
  VNET_DEV_CTR_RX_DROPS (OCT_PORT_CTR_RX_DROPS),
  VNET_DEV_CTR_VENDOR (OCT_PORT_CTR_RX_DROP_BYTES, RX, BYTES, "drop bytes"),
  VNET_DEV_CTR_VENDOR (OCT_PORT_CTR_RX_UCAST, RX, PACKETS, "unicast"),
  VNET_DEV_CTR_VENDOR (OCT_PORT_CTR_RX_MCAST, RX, PACKETS, "multicast"),
  VNET_DEV_CTR_VENDOR (OCT_PORT_CTR_RX_BCAST, RX, PACKETS, "broadcast"),
  VNET_DEV_CTR_VENDOR (OCT_PORT_CTR_RX_FCS, RX, PACKETS, "fcs"),
  VNET_DEV_CTR_VENDOR (OCT_PORT_CTR_RX_ERR, RX, PACKETS, "error"),
  VNET_DEV_CTR_VENDOR (OCT_PORT_CTR_RX_DROP_MCAST, RX, PACKETS,
		       "drop multicast"),
  VNET_DEV_CTR_VENDOR (OCT_PORT_CTR_RX_DROP_BCAST, RX, PACKETS,
		       "drop broadcast"),
  VNET_DEV_CTR_VENDOR (OCT_PORT_CTR_RX_DROP_L3_MCAST, RX, PACKETS,
		       "drop L3 multicast"),
  VNET_DEV_CTR_VENDOR (OCT_PORT_CTR_RX_DROP_L3_BCAST, RX, PACKETS,
		       "drop L3 broadcast"),

  VNET_DEV_CTR_TX_BYTES (OCT_PORT_CTR_TX_BYTES),
  VNET_DEV_CTR_TX_PACKETS (OCT_PORT_CTR_TX_PACKETS),
  VNET_DEV_CTR_TX_DROPS (OCT_PORT_CTR_TX_DROPS),
  VNET_DEV_CTR_VENDOR (OCT_PORT_CTR_TX_UCAST, TX, PACKETS, "unicast"),
  VNET_DEV_CTR_VENDOR (OCT_PORT_CTR_TX_MCAST, TX, PACKETS, "multicast"),
  VNET_DEV_CTR_VENDOR (OCT_PORT_CTR_TX_BCAST, TX, PACKETS, "broadcast"),
};

typedef enum
{
  OCT_RXQ_CTR_BYTES,
  OCT_RXQ_CTR_PKTS,
  OCT_RXQ_CTR_DROPS,
  OCT_RXQ_CTR_DROP_BYTES,
  OCT_RXQ_CTR_ERR,
} oct_rxq_counter_id_t;

vnet_dev_counter_t oct_rxq_counters[] = {
  VNET_DEV_CTR_RX_BYTES (OCT_RXQ_CTR_BYTES),
  VNET_DEV_CTR_RX_PACKETS (OCT_RXQ_CTR_PKTS),
  VNET_DEV_CTR_RX_DROPS (OCT_RXQ_CTR_DROPS),
  VNET_DEV_CTR_VENDOR (OCT_RXQ_CTR_DROP_BYTES, RX, BYTES, "drop bytes"),
  VNET_DEV_CTR_VENDOR (OCT_RXQ_CTR_ERR, RX, PACKETS, "error"),
};

typedef enum
{
  OCT_TXQ_CTR_BYTES,
  OCT_TXQ_CTR_PKTS,
  OCT_TXQ_CTR_DROPS,
  OCT_TXQ_CTR_DROP_BYTES,
} oct_txq_counter_id_t;

vnet_dev_counter_t oct_txq_counters[] = {
  VNET_DEV_CTR_TX_BYTES (OCT_TXQ_CTR_BYTES),
  VNET_DEV_CTR_TX_PACKETS (OCT_TXQ_CTR_PKTS),
  VNET_DEV_CTR_TX_DROPS (OCT_TXQ_CTR_DROPS),
  VNET_DEV_CTR_VENDOR (OCT_TXQ_CTR_DROP_BYTES, TX, BYTES, "drop bytes"),
};

static vnet_dev_rv_t
oct_roc_err (vnet_dev_t *dev, int rv, char *fmt, ...)
{
  u8 *s = 0;
  va_list va;

  va_start (va, fmt);
  s = va_format (s, fmt, &va);
  va_end (va);

  log_err (dev, "%v - ROC error %s (%d)", s, roc_error_msg_get (rv), rv);

  vec_free (s);
  return VNET_DEV_ERR_INTERNAL;
}

void
oct_port_add_counters (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_port_add_counters (vm, port, oct_port_counters,
			      ARRAY_LEN (oct_port_counters));

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      vnet_dev_rx_queue_add_counters (vm, rxq, oct_rxq_counters,
				      ARRAY_LEN (oct_rxq_counters));
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      vnet_dev_tx_queue_add_counters (vm, txq, oct_txq_counters,
				      ARRAY_LEN (oct_txq_counters));
    }
}

vnet_dev_rv_t
oct_port_get_stats (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rrv;
  struct roc_nix_stats stats;

  if ((rrv = roc_nix_stats_get (nix, &stats)))
    return oct_roc_err (dev, rrv, "roc_nix_stats_get() failed");

  foreach_vnet_dev_counter (c, port->counter_main)
    {
      switch (c->user_data)
	{
	case OCT_PORT_CTR_RX_BYTES:
	  vnet_dev_counter_value_update (vm, c, stats.rx_octs);
	  break;
	case OCT_PORT_CTR_TX_BYTES:
	  vnet_dev_counter_value_update (vm, c, stats.tx_octs);
	  break;
	case OCT_PORT_CTR_RX_PACKETS:
	  vnet_dev_counter_value_update (
	    vm, c, stats.rx_ucast + stats.rx_bcast + stats.rx_mcast);
	  break;
	case OCT_PORT_CTR_TX_PACKETS:
	  vnet_dev_counter_value_update (
	    vm, c, stats.tx_ucast + stats.tx_bcast + stats.tx_mcast);
	  break;
	case OCT_PORT_CTR_RX_DROPS:
	  vnet_dev_counter_value_update (vm, c, stats.rx_drop);
	  break;
	case OCT_PORT_CTR_TX_DROPS:
	  vnet_dev_counter_value_update (vm, c, stats.tx_drop);
	  break;
	case OCT_PORT_CTR_RX_DROP_BYTES:
	  vnet_dev_counter_value_update (vm, c, stats.rx_drop_octs);
	  break;
	case OCT_PORT_CTR_RX_UCAST:
	  vnet_dev_counter_value_update (vm, c, stats.rx_ucast);
	  break;
	case OCT_PORT_CTR_TX_UCAST:
	  vnet_dev_counter_value_update (vm, c, stats.tx_ucast);
	  break;
	case OCT_PORT_CTR_RX_MCAST:
	  vnet_dev_counter_value_update (vm, c, stats.rx_mcast);
	  break;
	case OCT_PORT_CTR_TX_MCAST:
	  vnet_dev_counter_value_update (vm, c, stats.tx_mcast);
	  break;
	case OCT_PORT_CTR_RX_BCAST:
	  vnet_dev_counter_value_update (vm, c, stats.rx_bcast);
	  break;
	case OCT_PORT_CTR_TX_BCAST:
	  vnet_dev_counter_value_update (vm, c, stats.tx_bcast);
	  break;
	case OCT_PORT_CTR_RX_FCS:
	  vnet_dev_counter_value_update (vm, c, stats.rx_fcs);
	  break;
	case OCT_PORT_CTR_RX_ERR:
	  vnet_dev_counter_value_update (vm, c, stats.rx_err);
	  break;
	case OCT_PORT_CTR_RX_DROP_MCAST:
	  vnet_dev_counter_value_update (vm, c, stats.rx_drop_mcast);
	  break;
	case OCT_PORT_CTR_RX_DROP_BCAST:
	  vnet_dev_counter_value_update (vm, c, stats.rx_drop_bcast);
	  break;
	case OCT_PORT_CTR_RX_DROP_L3_MCAST:
	  vnet_dev_counter_value_update (vm, c, stats.rx_drop_l3_mcast);
	  break;
	case OCT_PORT_CTR_RX_DROP_L3_BCAST:
	  vnet_dev_counter_value_update (vm, c, stats.rx_drop_l3_bcast);
	  break;
	default:
	  ASSERT (0);
	}
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
oct_rxq_get_stats (vlib_main_t *vm, vnet_dev_port_t *port,
		   vnet_dev_rx_queue_t *rxq)
{
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  struct roc_nix_stats_queue qstats;
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rrv;

  if ((rrv = roc_nix_stats_queue_get (nix, crq->rq.qid, 1, &qstats)))
    return oct_roc_err (dev, rrv, "roc_nix_stats_queue_get() failed");

  foreach_vnet_dev_counter (c, rxq->counter_main)
    {
      switch (c->user_data)
	{
	case OCT_RXQ_CTR_BYTES:
	  vnet_dev_counter_value_update (vm, c, qstats.rx_octs);
	  break;
	case OCT_RXQ_CTR_PKTS:
	  vnet_dev_counter_value_update (vm, c, qstats.rx_pkts);
	  break;
	case OCT_RXQ_CTR_DROPS:
	  vnet_dev_counter_value_update (vm, c, qstats.rx_drop_pkts);
	  break;
	case OCT_RXQ_CTR_DROP_BYTES:
	  vnet_dev_counter_value_update (vm, c, qstats.rx_drop_octs);
	  break;
	case OCT_RXQ_CTR_ERR:
	  vnet_dev_counter_value_update (vm, c, qstats.rx_error_pkts);
	  break;
	default:
	  ASSERT (0);
	}
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
oct_txq_get_stats (vlib_main_t *vm, vnet_dev_port_t *port,
		   vnet_dev_tx_queue_t *txq)
{
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  struct roc_nix_stats_queue qstats;
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rrv;

  if ((rrv = roc_nix_stats_queue_get (nix, ctq->sq.qid, 0, &qstats)))
    return oct_roc_err (dev, rrv, "roc_nix_stats_queue_get() failed");

  foreach_vnet_dev_counter (c, txq->counter_main)
    {
      switch (c->user_data)
	{
	case OCT_TXQ_CTR_BYTES:
	  vnet_dev_counter_value_update (vm, c, qstats.tx_octs);
	  break;
	case OCT_TXQ_CTR_PKTS:
	  vnet_dev_counter_value_update (vm, c, qstats.tx_pkts);
	  break;
	case OCT_TXQ_CTR_DROPS:
	  vnet_dev_counter_value_update (vm, c, qstats.tx_drop_pkts);
	  break;
	case OCT_TXQ_CTR_DROP_BYTES:
	  vnet_dev_counter_value_update (vm, c, qstats.tx_drop_octs);
	  break;
	default:
	  ASSERT (0);
	}
    }

  return VNET_DEV_OK;
}

void
oct_port_clear_counters (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rrv;

  if ((rrv = roc_nix_stats_reset (nix)))
    oct_roc_err (dev, rrv, "roc_nix_stats_reset() failed");
}

void
oct_rxq_clear_counters (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_t *dev = rxq->port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rrv;

  if ((rrv = roc_nix_stats_queue_reset (nix, crq->rq.qid, 1)))
    oct_roc_err (dev, rrv,
		 "roc_nix_stats_queue_reset() failed for rx queue %u",
		 rxq->queue_id);
}

void
oct_txq_clear_counters (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_t *dev = txq->port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  int rrv;

  if ((rrv = roc_nix_stats_queue_reset (nix, ctq->sq.qid, 0)))
    oct_roc_err (dev, rrv,
		 "roc_nix_stats_queue_reset() failed for tx queue %u",
		 txq->queue_id);
}
