/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <vppinfra/ring.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <limits.h>
#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

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

static int
mvpp2_port_statistics_init (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u8 sset_info_data[sizeof (struct ethtool_sset_info) + sizeof (u32)] = {};
  struct ethtool_sset_info *sset_info = (void *) sset_info_data;
  struct ifreq ifr = {};
  u32 len;

  if (mp->stats_name)
    return 0;

  mvpp2_port_ifname (port, ifr.ifr_name);
  sset_info->cmd = ETHTOOL_GSSET_INFO;
  sset_info->sset_mask = 1ULL << ETH_SS_STATS;
  ifr.ifr_data = (char *) sset_info;
  if (mvpp2_netdev_ioctl (port->dev, SIOCETHTOOL, &ifr))
    return -EIO;

  len = sset_info->data[0];
  if (len == 0)
    return -ENOENT;

  mp->stats_name = clib_mem_alloc (sizeof (*mp->stats_name) + len * ETH_GSTRING_LEN);
  clib_memset (mp->stats_name, 0, sizeof (*mp->stats_name) + len * ETH_GSTRING_LEN);
  mp->stats_name->cmd = ETHTOOL_GSTRINGS;
  mp->stats_name->string_set = ETH_SS_STATS;
  mp->stats_name->len = len;
  ifr.ifr_data = (char *) mp->stats_name;
  if (mvpp2_netdev_ioctl (port->dev, SIOCETHTOOL, &ifr))
    {
      clib_mem_free (mp->stats_name);
      mp->stats_name = 0;
      return -EIO;
    }

  return 0;
}

static int
mvpp2_read_port_statistics (vnet_dev_port_t *port,
			    mvpp2_port_statistics_t *stats)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct ethtool_stats *values;
  struct ifreq ifr = {};
  uword size;

  clib_memset (stats, 0, sizeof (*stats));
  if (mvpp2_port_statistics_init (port))
    return -EIO;

  size = sizeof (*values) + mp->stats_name->len * sizeof (u64);
  values = clib_mem_alloc (size);
  clib_memset (values, 0, size);

  mvpp2_port_ifname (port, ifr.ifr_name);
  values->cmd = ETHTOOL_GSTATS;
  values->n_stats = mp->stats_name->len;
  ifr.ifr_data = (char *) values;
  if (mvpp2_netdev_ioctl (port->dev, SIOCETHTOOL, &ifr))
    {
      clib_mem_free (values);
      return -EIO;
    }

  for (u32 i = 0; i < mp->stats_name->len; i++)
    {
      char *name = (char *) &mp->stats_name->data[i * ETH_GSTRING_LEN];
      u64 value = values->data[i];

      if (!strcmp (name, "good_octets_received") || !strcmp (name, "rx_bytes"))
	stats->rx_bytes = value;
      else if (!strcmp (name, "unicast_frames_received") || !strcmp (name, "rx_unicast"))
	stats->rx_unicast_packets = value;
      else if (!strcmp (name, "rx_frames"))
	stats->rx_packets = value;
      else if (!strcmp (name, "broadcast_frames_received") ||
	       !strcmp (name, "multicast_frames_received"))
	stats->rx_packets += value;
      else if (!strcmp (name, "rx_fifo_overrun") || !strcmp (name, "undersize_received") ||
	       !strcmp (name, "fragments_err_received") || !strcmp (name, "oversize_received") ||
	       !strcmp (name, "jabber_received") || !strcmp (name, "mac_receive_error") ||
	       !strcmp (name, "bad_crc_event") || !strcmp (name, "rx_total_err"))
	stats->rx_errors += value;
      else if (!strcmp (name, "rx_ppv2_overrun"))
	stats->rx_fifo_dropped = value;
      else if (!strcmp (name, "rx_cls_drop"))
	stats->rx_cls_dropped = value;
      else if (!strcmp (name, "good_octets_sent") || !strcmp (name, "tx_bytes"))
	stats->tx_bytes = value;
      else if (!strcmp (name, "unicast_frames_sent") || !strcmp (name, "tx_unicast"))
	stats->tx_unicast_packets = value;
      else if (!strcmp (name, "tx_frames"))
	stats->tx_packets = value;
      else if (!strcmp (name, "multicast_frames_sent") || !strcmp (name, "broadcast_frames_sent"))
	stats->tx_packets += value;
      else if (!strcmp (name, "collision") || !strcmp (name, "late_collision") ||
	       !strcmp (name, "crc_errors_sent") || !strcmp (name, "tx_crc_sent"))
	stats->tx_errors += value;
    }

  clib_mem_free (values);
  return 0;
}

static_always_inline u32
mvpp2_counter_read (uintptr_t hif_base, u32 reg)
{
  u32 value;

  asm volatile ("ldr %w0, [%1]" : "=r"(value) : "r"(hif_base + reg));
  return le32toh (value);
}

static_always_inline void
mvpp2_counter_write (uintptr_t hif_base, u32 reg, u32 value)
{
  value = htole32 (value);
  asm volatile ("str %w0, [%1]" : : "r"(value), "r"(hif_base + reg));
}

static int
mvpp2_read_rxq_statistics (vnet_dev_port_t *port, u8 tc, u8 qid,
			   mvpp2_rxq_statistics_t *stats, int reset)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_rx_queue_t *q = vnet_dev_get_port_rx_queue_by_id (port, qid);
  mvpp2_rxq_t *mrq = vnet_dev_get_rx_queue_data (q);
  u32 value;

  ASSERT (tc == 0);
  mvpp2_counter_write (mp->hif_base, MVPP2_CNT_IDX_REG, mrq->hw_id);
  mrq->stats.enq_desc += mvpp2_counter_read (mp->hif_base, MVPP2_RX_DESC_ENQ_REG);
  value = mvpp2_counter_read (mp->hif_base, MVPP2_RX_PKT_FULLQ_DROP_REG);
  mrq->stats.drop_fullq =
    (u64) mrq->stats.drop_fullq + value > UINT_MAX ? UINT_MAX : mrq->stats.drop_fullq + value;
  value = mvpp2_counter_read (mp->hif_base, MVPP2_RX_PKT_EARLY_DROP_REG);
  mrq->stats.drop_early =
    (u32) mrq->stats.drop_early + value > USHRT_MAX ? USHRT_MAX : mrq->stats.drop_early + value;
  value = mvpp2_counter_read (mp->hif_base, MVPP2_RX_PKT_BM_DROP_REG);
  mrq->stats.drop_bm =
    (u32) mrq->stats.drop_bm + value > USHRT_MAX ? USHRT_MAX : mrq->stats.drop_bm + value;

  if (stats)
    clib_memcpy (stats, &mrq->stats, sizeof (*stats));
  if (reset)
    clib_memset (&mrq->stats, 0, sizeof (mrq->stats));

  return 0;
}

static int
mvpp2_read_txq_statistics (vnet_dev_port_t *port, u8 qid,
			   mvpp2_txq_statistics_t *stats,
			   int reset)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_tx_queue_t *q = vnet_dev_get_port_tx_queue_by_id (port, qid);
  mvpp2_txq_t *mtq = vnet_dev_get_tx_queue_data (q);

  mvpp2_counter_write (mp->hif_base, MVPP2_CNT_IDX_REG, MVPP2_CNT_IDX_TX (mp->id, q->queue_id));
  mtq->stats.enq_desc += mvpp2_counter_read (mp->hif_base, MVPP2_TX_DESC_ENQ_REG);
  mtq->stats.enq_dec_to_ddr += mvpp2_counter_read (mp->hif_base, MVPP2_TX_DESC_ENQ_TO_DRAM_REG);
  mtq->stats.enq_buf_to_ddr += mvpp2_counter_read (mp->hif_base, MVPP2_TX_BUF_ENQ_TO_DRAM_REG);
  mtq->stats.deq_desc += mvpp2_counter_read (mp->hif_base, MVPP2_TX_PKT_DQ_REG);

  if (stats)
    clib_memcpy (stats, &mtq->stats, sizeof (*stats));
  if (reset)
    clib_memset (&mtq->stats, 0, sizeof (mtq->stats));

  return 0;
}

static int
mvpp2_rxq_get_statistics (vnet_dev_port_t *port, u8 tc, u8 qid,
			  mvpp2_rxq_statistics_t *stats, int reset)
{
  return mvpp2_read_rxq_statistics (port, tc, qid, stats, reset);
}

static int
mvpp2_txq_get_statistics (vnet_dev_port_t *port, u8 qid,
			  mvpp2_txq_statistics_t *stats, int reset)
{
  return mvpp2_read_txq_statistics (port, qid, stats, reset);
}

static int
mvpp2_port_get_statistics (vnet_dev_port_t *port,
			   mvpp2_port_statistics_t *stats, int reset)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_port_statistics_t cur_stats = {};

  mvpp2_read_port_statistics (port, &cur_stats);
  cur_stats.rx_packets = 0;
  cur_stats.tx_packets = 0;

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_statistics_t rx_stats;

      mvpp2_rxq_get_statistics (port, 0, q->queue_id, &rx_stats, reset);
      cur_stats.rx_packets += rx_stats.enq_desc;
      cur_stats.rx_fullq_dropped += rx_stats.drop_fullq;
      cur_stats.rx_bm_dropped += rx_stats.drop_bm;
      cur_stats.rx_early_dropped += rx_stats.drop_early;
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      mvpp2_txq_statistics_t tx_stats;

      mvpp2_txq_get_statistics (port, q->queue_id, &tx_stats, reset);
      cur_stats.tx_packets += tx_stats.deq_desc;
    }

  if (stats)
    {
      stats->rx_packets = cur_stats.rx_packets;
      stats->rx_fullq_dropped = cur_stats.rx_fullq_dropped;
      stats->rx_bm_dropped = cur_stats.rx_bm_dropped;
      stats->rx_early_dropped = cur_stats.rx_early_dropped;
      stats->tx_packets = cur_stats.tx_packets;
      stats->rx_bytes = cur_stats.rx_bytes - mp->stats.rx_bytes;
      stats->rx_unicast_packets = cur_stats.rx_unicast_packets - mp->stats.rx_unicast_packets;
      stats->rx_errors = cur_stats.rx_errors - mp->stats.rx_errors;
      stats->rx_fifo_dropped = cur_stats.rx_fifo_dropped - mp->stats.rx_fifo_dropped;
      stats->rx_cls_dropped = cur_stats.rx_cls_dropped - mp->stats.rx_cls_dropped;
      stats->tx_bytes = cur_stats.tx_bytes - mp->stats.tx_bytes;
      stats->tx_unicast_packets = cur_stats.tx_unicast_packets - mp->stats.tx_unicast_packets;
      stats->tx_errors = cur_stats.tx_errors - mp->stats.tx_errors;
    }

  if (reset)
    clib_memcpy (&mp->stats, &cur_stats, sizeof (mp->stats));

  return 0;
}

void
mvpp2_port_counters_init (vnet_dev_port_t *port)
{
  mvpp2_port_get_statistics (port, 0, 1);
}

void
mvpp2_port_counters_deinit (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  if (mp->stats_name)
    {
      clib_mem_free (mp->stats_name);
      mp->stats_name = 0;
    }
}

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
  mvpp2_port_statistics_t stats;
  mvpp2_port_get_statistics (port, &stats, 1);
}

void
mvpp2_rxq_clear_counters (vlib_main_t *vm, vnet_dev_rx_queue_t *q)
{
  mvpp2_rxq_statistics_t stats;
  mvpp2_rxq_get_statistics (q->port, 0, q->queue_id, &stats, 1);
}

void
mvpp2_txq_clear_counters (vlib_main_t *vm, vnet_dev_tx_queue_t *q)
{
  mvpp2_txq_statistics_t stats;
  mvpp2_txq_get_statistics (q->port, q->queue_id, &stats, 1);
}

vnet_dev_rv_t
mvpp2_port_get_stats (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_statistics_t stats;
  mvpp2_port_get_statistics (port, &stats, 0);

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
      mvpp2_rxq_statistics_t stats;
      mvpp2_rxq_get_statistics (port, 0, q->queue_id, &stats, 0);

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
      mvpp2_txq_statistics_t stats;
      mvpp2_txq_get_statistics (port, q->queue_id, &stats, 0);

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
