/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <vppinfra/ring.h>
#include <dev_armada/musdk.h>
#include <dev_armada/pp2/pp2.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "pp2-counters",
};

typedef enum
{
  MVPP2_PORT_CTR_RX_BYTES,
  MVPP2_PORT_CTR_RX_PACKETS,
  MVPP2_PORT_CTR_RX_UCAST,
  MVPP2_PORT_CTR_RX_ERRORS,
  MVPP2_PORT_CTR_RX_FULLQ_DROPPED,
  MVPP2_PORT_CTR_RX_BM_DROPPED,
  MVPP2_PORT_CTR_RX_EARLY_DROPPED,
  MVPP2_PORT_CTR_RX_FIFO_DROPPED,
  MVPP2_PORT_CTR_RX_CLS_DROPPED,

  MVPP2_PORT_CTR_TX_BYTES,
  MVPP2_PORT_CTR_TX_PACKETS,
  MVPP2_PORT_CTR_TX_UCAST,
  MVPP2_PORT_CTR_TX_ERRORS,
} mvpp2_port_counter_id_t;

typedef enum
{
  MVPP2_RXQ_CTR_ENQ_DESC,
  MVPP2_RXQ_CTR_DROP_FULLQ,
  MVPP2_RXQ_CTR_DROP_EARLY,
  MVPP2_RXQ_CTR_DROP_BM,
} mvpp2_rxq_counter_id_t;

typedef enum
{
  MVPP2_TXQ_CTR_ENQ_DESC,
  MVPP2_TXQ_CTR_ENQ_DEC_TO_DDR,
  MVPP2_TXQ_CTR_ENQ_BUF_TO_DDR,
  MVPP2_TXQ_CTR_DEQ_DESC,
} mvpp2_txq_counter_id_t;

static vnet_dev_counter_t mvpp2_port_counters[] = {
  VNET_DEV_CTR_RX_BYTES (MVPP2_PORT_CTR_RX_BYTES),
  VNET_DEV_CTR_RX_PACKETS (MVPP2_PORT_CTR_RX_PACKETS),
  VNET_DEV_CTR_RX_DROPS (MVPP2_PORT_CTR_RX_ERRORS),
  VNET_DEV_CTR_VENDOR (MVPP2_PORT_CTR_RX_UCAST, RX, PACKETS, "unicast"),
  VNET_DEV_CTR_VENDOR (MVPP2_PORT_CTR_RX_FULLQ_DROPPED, RX, PACKETS,
		       "fullq dropped"),
  VNET_DEV_CTR_VENDOR (MVPP2_PORT_CTR_RX_BM_DROPPED, RX, PACKETS,
		       "bm dropped"),
  VNET_DEV_CTR_VENDOR (MVPP2_PORT_CTR_RX_EARLY_DROPPED, RX, PACKETS,
		       "early dropped"),
  VNET_DEV_CTR_VENDOR (MVPP2_PORT_CTR_RX_FIFO_DROPPED, RX, PACKETS,
		       "fifo dropped"),
  VNET_DEV_CTR_VENDOR (MVPP2_PORT_CTR_RX_CLS_DROPPED, RX, PACKETS,
		       "cls dropped"),

  VNET_DEV_CTR_TX_BYTES (MVPP2_PORT_CTR_TX_BYTES),
  VNET_DEV_CTR_TX_PACKETS (MVPP2_PORT_CTR_TX_PACKETS),
  VNET_DEV_CTR_TX_DROPS (MVPP2_PORT_CTR_TX_ERRORS),
  VNET_DEV_CTR_VENDOR (MVPP2_PORT_CTR_TX_UCAST, TX, PACKETS, "unicast"),
};

static vnet_dev_counter_t mvpp2_rxq_counters[] = {
  VNET_DEV_CTR_VENDOR (MVPP2_RXQ_CTR_ENQ_DESC, RX, DESCRIPTORS, "enqueued"),
  VNET_DEV_CTR_VENDOR (MVPP2_RXQ_CTR_DROP_FULLQ, RX, PACKETS, "drop fullQ"),
  VNET_DEV_CTR_VENDOR (MVPP2_RXQ_CTR_DROP_EARLY, RX, PACKETS, "drop early"),
  VNET_DEV_CTR_VENDOR (MVPP2_RXQ_CTR_DROP_BM, RX, PACKETS, "drop BM"),
};

static vnet_dev_counter_t mvpp2_txq_counters[] = {
  VNET_DEV_CTR_VENDOR (MVPP2_TXQ_CTR_ENQ_DESC, TX, DESCRIPTORS, "enqueued"),
  VNET_DEV_CTR_VENDOR (MVPP2_TXQ_CTR_DEQ_DESC, TX, PACKETS, "dequeued"),
  VNET_DEV_CTR_VENDOR (MVPP2_TXQ_CTR_ENQ_BUF_TO_DDR, TX, BUFFERS,
		       "enq to DDR"),
  VNET_DEV_CTR_VENDOR (MVPP2_TXQ_CTR_ENQ_DEC_TO_DDR, TX, DESCRIPTORS,
		       "enq to DDR"),
};

void
mvpp2_port_add_counters (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_port_add_counters (vm, port, mvpp2_port_counters,
			      ARRAY_LEN (mvpp2_port_counters));

  foreach_vnet_dev_port_rx_queue (q, port)
    vnet_dev_rx_queue_add_counters (vm, q, mvpp2_rxq_counters,
				    ARRAY_LEN (mvpp2_rxq_counters));

  foreach_vnet_dev_port_tx_queue (q, port)
    vnet_dev_tx_queue_add_counters (vm, q, mvpp2_txq_counters,
				    ARRAY_LEN (mvpp2_txq_counters));
}

void
mvpp2_port_clear_counters (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio_statistics stats;
  pp2_ppio_get_statistics (mp->ppio, &stats, 1);
}

void
mvpp2_rxq_clear_counters (vlib_main_t *vm, vnet_dev_rx_queue_t *q)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (q->port);
  struct pp2_ppio_inq_statistics stats;
  pp2_ppio_inq_get_statistics (mp->ppio, 0, q->queue_id, &stats, 1);
}

void
mvpp2_txq_clear_counters (vlib_main_t *vm, vnet_dev_tx_queue_t *q)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (q->port);
  struct pp2_ppio_inq_statistics stats;
  pp2_ppio_inq_get_statistics (mp->ppio, 0, q->queue_id, &stats, 1);
}

vnet_dev_rv_t
mvpp2_port_get_stats (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio_statistics stats;
  pp2_ppio_get_statistics (mp->ppio, &stats, 0);

  foreach_vnet_dev_counter (c, port->counter_main)
    {
      switch (c->user_data)
	{
	case MVPP2_PORT_CTR_RX_BYTES:
	  vnet_dev_counter_value_update (vm, c, stats.rx_bytes);
	  break;
	case MVPP2_PORT_CTR_RX_PACKETS:
	  vnet_dev_counter_value_update (vm, c, stats.rx_packets);
	  break;
	case MVPP2_PORT_CTR_RX_UCAST:
	  vnet_dev_counter_value_update (vm, c, stats.rx_unicast_packets);
	  break;
	case MVPP2_PORT_CTR_RX_ERRORS:
	  vnet_dev_counter_value_update (vm, c, stats.rx_errors);
	  break;
	case MVPP2_PORT_CTR_TX_BYTES:
	  vnet_dev_counter_value_update (vm, c, stats.tx_bytes);
	  break;
	case MVPP2_PORT_CTR_TX_PACKETS:
	  vnet_dev_counter_value_update (vm, c, stats.tx_packets);
	  break;
	case MVPP2_PORT_CTR_TX_UCAST:
	  vnet_dev_counter_value_update (vm, c, stats.tx_unicast_packets);
	  break;
	case MVPP2_PORT_CTR_TX_ERRORS:
	  vnet_dev_counter_value_update (vm, c, stats.tx_errors);
	  break;
	case MVPP2_PORT_CTR_RX_FULLQ_DROPPED:
	  vnet_dev_counter_value_update (vm, c, stats.rx_fullq_dropped);
	  break;
	case MVPP2_PORT_CTR_RX_BM_DROPPED:
	  vnet_dev_counter_value_update (vm, c, stats.rx_bm_dropped);
	  break;
	case MVPP2_PORT_CTR_RX_EARLY_DROPPED:
	  vnet_dev_counter_value_update (vm, c, stats.rx_early_dropped);
	  break;
	case MVPP2_PORT_CTR_RX_FIFO_DROPPED:
	  vnet_dev_counter_value_update (vm, c, stats.rx_fifo_dropped);
	  break;
	case MVPP2_PORT_CTR_RX_CLS_DROPPED:
	  vnet_dev_counter_value_update (vm, c, stats.rx_cls_dropped);
	  break;

	default:
	  ASSERT (0);
	}
    }

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      struct pp2_ppio_inq_statistics stats;
      pp2_ppio_inq_get_statistics (mp->ppio, 0, q->queue_id, &stats, 0);

      foreach_vnet_dev_counter (c, q->counter_main)
	{
	  switch (c->user_data)
	    {
	    case MVPP2_RXQ_CTR_ENQ_DESC:
	      vnet_dev_counter_value_update (vm, c, stats.enq_desc);
	      break;
	    case MVPP2_RXQ_CTR_DROP_BM:
	      vnet_dev_counter_value_update (vm, c, stats.drop_bm);
	      break;
	    case MVPP2_RXQ_CTR_DROP_EARLY:
	      vnet_dev_counter_value_update (vm, c, stats.drop_early);
	      break;
	    case MVPP2_RXQ_CTR_DROP_FULLQ:
	      vnet_dev_counter_value_update (vm, c, stats.drop_fullq);
	      break;
	    default:
	      ASSERT (0);
	    }
	}
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      struct pp2_ppio_outq_statistics stats;
      pp2_ppio_outq_get_statistics (mp->ppio, q->queue_id, &stats, 0);

      foreach_vnet_dev_counter (c, q->counter_main)
	{
	  switch (c->user_data)
	    {
	    case MVPP2_TXQ_CTR_ENQ_DESC:
	      vnet_dev_counter_value_update (vm, c, stats.enq_desc);
	      break;
	    case MVPP2_TXQ_CTR_DEQ_DESC:
	      vnet_dev_counter_value_update (vm, c, stats.deq_desc);
	      break;
	    case MVPP2_TXQ_CTR_ENQ_BUF_TO_DDR:
	      vnet_dev_counter_value_update (vm, c, stats.enq_buf_to_ddr);
	      break;
	    case MVPP2_TXQ_CTR_ENQ_DEC_TO_DDR:
	      vnet_dev_counter_value_update (vm, c, stats.enq_dec_to_ddr);
	      break;
	    default:
	      ASSERT (0);
	    }
	}
    }

  return VNET_DEV_OK;
}
