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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "pp2-port",
};

static_always_inline u32
mvpp2_port_reg_read (uintptr_t base, u32 offset)
{
  volatile u32 *addr = (void *) (base + offset);
  u32 value;

  value = __atomic_load_n (addr, __ATOMIC_RELAXED);
  asm volatile ("dsb ld" : : : "memory");
  return value;
}

static vnet_dev_rv_t
mvpp2_port_set_loopback (vnet_dev_port_t *port, int en)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int mac_num = mp->gop_index;
  uintptr_t base;
  u32 pp2_version;
  u32 val;

  /* Configure GMAC loopback. */
  base = md->gop_hw_gmac.base + mac_num * md->gop_hw_gmac.obj_size;
  val = mvpp2_port_reg_read (base, PP2_GMAC_PORT_CTRL1_REG);
  if (en)
    val |= PP2_GMAC_PORT_CTRL1_GMII_LOOPBACK_MASK;
  else
    val &= ~PP2_GMAC_PORT_CTRL1_GMII_LOOPBACK_MASK;
  mvpp2_reg_write (base, PP2_GMAC_PORT_CTRL1_REG, val);

  /* GOP#0 and GOP#2 (In PP23/CP115) can support both XLG and GMAC;
   * We cannot know that on the fly so always configure both of them;
   * All the rest support only GMAC
   */
  pp2_version = mvpp2_port_reg_read (mp->hif_base, MVPP2_VER_ID_REG);
  if (mac_num == 0 || (mac_num == 2 && pp2_version == MVPP2_VER_PP23))
    {
      /* Configure XLG loopback when available. */
      base = md->gop_hw_xlg_mac.base + mac_num * md->gop_hw_xlg_mac.obj_size;
      val = mvpp2_port_reg_read (base, PP2_XLG_PORT_MAC_CTRL1_REG);
      if (en)
	val |= PP2_XLG_MAC_CTRL1_MACLOOPBACKEN_MASK | PP2_XLG_MAC_CTRL1_XGMIILOOPBACKEN_MASK;
      else
	val &= ~(PP2_XLG_MAC_CTRL1_MACLOOPBACKEN_MASK | PP2_XLG_MAC_CTRL1_XGMIILOOPBACKEN_MASK);
      mvpp2_reg_write (base, PP2_XLG_PORT_MAC_CTRL1_REG, val);
    }

  return VNET_DEV_OK;
}

static void
mvpp2_port_egress_disable_qmask (vnet_dev_port_t *port, u32 q_mask)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  volatile u32 tmo;
  u32 val = 0;
  u32 tx_port_num = MVPP2_MAX_TCONT + mp->id;

  /* Issue stop command for active channels only */
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  if (q_mask)
    mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_Q_CMD_REG,
		     q_mask << MVPP2_TXP_SCHED_DISQ_OFFSET);

  /* TXQs disable. Wait for all Tx activity to terminate. */
  tmo = 0;
  do
    {
      if (tmo >= MVPP2_TX_DISABLE_TIMEOUT_MSEC)
	{
	  log_warn (dev, "Port: Egress disable timeout = 0x%08X\n", val);
	  break;
	}
      /* Sleep for 1 millisecond */
      usleep (1000);
      tmo++;
      val = mvpp2_reg_read (mp->hif_base, MVPP2_TXP_SCHED_Q_CMD_REG);
    }
  while (val & q_mask);
}

static void
mvpp2_port_egress_disable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 q_mask;

  q_mask = mvpp2_reg_read (mp->hif_base, MVPP2_TXP_SCHED_Q_CMD_REG) & MVPP2_TXP_SCHED_ENQ_MASK;
  mvpp2_port_egress_disable_qmask (port, q_mask);
}

static void
mvpp2_port_egress_enable (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 q_mask = 0;
  u32 tx_port_num = MVPP2_MAX_TCONT + mp->id;

  foreach_vnet_dev_port_tx_queue (q, port)
    q_mask |= 1 << q->queue_id;

  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_Q_CMD_REG, q_mask);
  log_debug (dev, "Port: Egress enable tx_port_num=%u q_mask=0x%X\n", tx_port_num, q_mask);
}

static void
mvpp2_port_ingress_disable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 val;

  /* RXQs disable */
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);

      val = mvpp2_reg_read (mp->hif_base, MVPP2_RXQ_CONFIG_REG (rxq->hw_id));
      val |= MVPP2_RXQ_DISABLE_MASK;
      mvpp2_reg_write (mp->hif_base, MVPP2_RXQ_CONFIG_REG (rxq->hw_id), val);
    }
}

static void
mvpp2_port_ingress_enable (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 val;

  /* RXQs enable */
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);

      val = mvpp2_reg_read (mp->hif_base, MVPP2_RXQ_CONFIG_REG (rxq->hw_id));
      val &= ~MVPP2_RXQ_DISABLE_MASK;
      mvpp2_reg_write (mp->hif_base, MVPP2_RXQ_CONFIG_REG (rxq->hw_id), val);
    }
}

static void
mvpp2_port_defaults_set (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 tx_port_num, val, queue, ptxq;

  /* Disable Legacy WRR, Disable EJP, Release from reset */
  tx_port_num = MVPP2_MAX_TCONT + mp->id;
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_PORT_INDEX_REG, tx_port_num);
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_CMD_1_REG, 0x0);

  /* Close bandwidth for all queues */
  for (queue = 0; queue < MVPP2_MAX_TXQ; queue++)
    {
      ptxq = (MVPP2_MAX_TCONT + mp->id) * MVPP2_MAX_TXQ + queue;
      mvpp2_reg_write (mp->hif_base, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (ptxq), 0x0);
    }

  /* Set refill period to 1 usec, refill tokens
   * and bucket size to maximum
   */
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_PERIOD_REG,
		   PP2_TCLK_FREQ / 1000000); /* USEC_PER_SEC */
  val = mvpp2_reg_read (mp->hif_base, MVPP2_TXP_SCHED_REFILL_REG);
  val &= ~MVPP2_TXP_REFILL_PERIOD_ALL_MASK;
  val |= MVPP2_TXP_REFILL_PERIOD_MASK (1);
  val |= MVPP2_TXP_REFILL_TOKENS_ALL_MASK;
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_REFILL_REG, val);
  mvpp2_reg_write (mp->hif_base, MVPP2_TXP_SCHED_TOKEN_SIZE_REG, MVPP2_TXP_TOKEN_SIZE_MAX);

  /* Set MaximumLowLatencyPacketSize value to 256 */
  /* Set GemPortIdSrcSel from classifier */
  mvpp2_reg_write (mp->hif_base, MVPP2_RX_CTRL_REG (mp->id),
		   MVPP2_RX_USE_PSEUDO_FOR_CSUM_MASK | MVPP2_RX_LOW_LATENCY_PKT_SIZE (256) |
		     MVPP2_RX_GEM_PORT_ID_SRC_SEL (2));

  /* Disable Rx cache snoop */
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);

      val = mvpp2_reg_read (mp->hif_base, MVPP2_RXQ_CONFIG_REG (rxq->hw_id));
      /* Coherent */
      val |= MVPP2_SNOOP_PKT_SIZE_MASK;
      val |= MVPP2_SNOOP_BUF_HDR_MASK;
      mvpp2_reg_write (mp->hif_base, MVPP2_RXQ_CONFIG_REG (rxq->hw_id), val);
    }

  /* As default, mask all interrupts to all present cpus */
  mvpp2_port_interrupts_disable (port);
}

vnet_dev_rv_t
mvpp2_port_set_rx_pause (vnet_dev_port_t *port, int en)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct ethtool_pauseparam param = {
    .cmd = ETHTOOL_SPAUSEPARAM,
    .rx_pause = en,
    .tx_pause = mp->tx_pause_en,
    .autoneg = 1,
  };
  struct ifreq ifr = {};
  int fd;

  if (mp->rx_pause_en == en)
    return VNET_DEV_OK;

  mvpp2_port_ifname (port, ifr.ifr_name);
  ifr.ifr_data = (char *) &param;

  fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd == -1)
    {
      log_err (dev, "can't open socket: errno %d", errno);
      return VNET_DEV_ERR_INTERNAL;
    }

  if (ioctl (fd, SIOCETHTOOL, &ifr) == -1)
    {
      log_err (dev, "unable to %s rx pause: errno %d", en ? "enable" : "disable", errno);
      close (fd);
      return VNET_DEV_ERR_INTERNAL;
    }

  close (fd);
  mp->rx_pause_en = en;
  log_debug (dev, "rx pause is %s", en ? "enabled" : "disabled");
  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  struct mvpp2_port_link_info li;
  enum mvpp2_port_hash_type hash_type = MVPP2_PORT_HASH_5_TUPLE;
  enum mvpp2_port_eth_start_hdr eth_start_hdr;
  char ifname[IFNAMSIZ];
  vnet_dev_rv_t mrv;
  u32 first_rxq;
  u16 n_rxq = 0;
  u8 index;

  log_debug (port->dev, "");

  foreach_vnet_dev_port_rx_queue (q, port)
    n_rxq++;

  if (n_rxq > 1)
    hash_type = clib_args_get_enum_val_by_name (port->args, "rss_hash");

  switch (clib_args_get_enum_val_by_name (port->args, "dsa_enable"))
    {
    case MVPP2_PORT_DSA_ENABLED_ON:
      mp->is_dsa = 1;
      break;
    case MVPP2_PORT_DSA_ENABLED_OFF:
      mp->is_dsa = 0;
      break;
    case MVPP2_PORT_DSA_ENABLED_AUTO:
      break;
    default:
      ASSERT (0);
      break;
    }

  index = get_lowest_set_bit_index (md->free_bpools);
  md->free_bpools ^= 1 << index;

  mrv = mvpp2_bpool_init (
    &(mvpp2_bpool_params_t) {
      .vm = vm,
      .dev = dev,
      .id = index,
      .buff_len = vlib_buffer_get_default_data_size (vm),
    },
    &mp->bpool);
  if (mrv < 0)
    {
      log_err (dev, "mvpp2_bpool_init failed for bpool %u, err %d", index, mrv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }
  log_debug (dev, "bpool %u initialized as pool %u:%u", index, md->pp_id, mp->bpool.id);

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *prq = vnet_dev_get_rx_queue_data (q);

      prq->bpool_desc_template = (mvpp2_tx_desc_t) {
	.cmds = {
	  [0] = (TXD_IP_CHK_DISABLE << 15) | (TXD_L4_CHK_DISABLE << 13) |
		(TXD_FIRST_LAST << 28) | (mp->bpool.id << 16 & TXD_POOL_ID_MASK) |
		(1 << 7 & TXD_BUFMODE_MASK),
	  [1] = MVPP2_BPOOL_DUMMY_PKT_EFEC_OFFS |
		  (MVPP2_LOOPBACK_TXQ_ID << 8 & TXD_DEST_QID_MASK),
	  [3] = TXD_ERR_SUM_MASK,
	},
      };
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      mp->txq_config[q->queue_id] = (struct pp2_txq_config) {
	.size = q->size,
	.weight = 1,
      };
    }

  mvpp2_port_ifname (port, ifname);
  log_debug (dev, "port init: pp2_id(%u), port_id(%u), ifname(%s)", md->pp_id, mp->id, ifname);

  first_rxq = mp->id * PP2_HW_PORT_NUM_RXQS;
  mp->first_rxq = first_rxq;
  mp->num_tcs = 1;
  mp->tc.tc_config = (struct mvpp2_tc_config) {
    .pkt_offset = L1_CACHE_LINE_BYTES,
    .num_in_qs = n_rxq,
    .first_rxq = first_rxq,
    .pools[0][0] = &mp->bpool,
    .pools[0][1] = &md->dummy_short_bpool,
  };
  mp->hash_type = n_rxq > 1 ? hash_type : MVPP2_PORT_HASH_NONE;
  mp->hif_base = md->pp_base;

  mrv = mvpp2_netdev_set_priv_flags (port, MVPP22_F_IF_MUSDK_PRIV);
  if (mrv)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      log_err (dev, "port %u (%u:%u) init failed, rv %d", port->port_id, md->pp_id, port->port_id,
	       mrv);
      goto done;
    }

  mvpp2_port_egress_disable (port);
  foreach_vnet_dev_port_tx_queue (q, port)
    {
      mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);
      u32 qid = q->queue_id;

      txq->hw_id = (MVPP2_MAX_TCONT + mp->id) * MVPP2_MAX_TXQ + qid;
      txq->disabled = 0;
      for (u32 i = 0; i < ARRAY_LEN (txq->desc_rsrvd); i++)
	txq->desc_rsrvd[i] = 0;
    }

  mvpp2_rxqs_create (port);
  mvpp2_port_ingress_disable (port);
  mvpp2_port_defaults_set (port);
  mp->stats = (mvpp2_port_statistics_t) {};
  mvpp2_rss_port_init (port);
  mvpp2_cls_mng_config_default_cos_queue (port);

  mvpp2_port_clear_prs_vlans (port);
  mvpp2_port_flush_mac_addrs (port, 1, 1);
  mp->tx_pause_en = 0;
  mp->rx_pause_en = 1;
  mvpp2_port_set_rx_pause (port, 0);

  eth_start_hdr = mp->is_dsa ? MVPP2_PORT_HDR_ETH_DSA : MVPP2_PORT_HDR_ETH;

  mvpp2x_cls_oversize_rxq_set (port);
  foreach_vnet_dev_port_rx_queue (q, port)
    mvpp2_rxq_init (q);
  mvpp2_port_rxqs_fc_state_reset (port);
  mvpp2_port_clear_fc_isr (port);

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      mvpp2_txq_init (q);
      mvpp2_port_set_txq_state (q, 1);
    }

  if (mvpp2_parser_eth_start_header_set (port, eth_start_hdr))
    {
      log_err (dev, "port %u failed to initialize ethernet start header", port->port_id);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  if (mvpp2_cls_mng_modify_default_flows (port, 0))
    {
      log_err (dev, "port %u failed to modify default flows", port->port_id);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  mvpp2_port_set_loopback (port, 0);
  mvpp2_port_set_promisc (port, 0);
  mp->is_open = 1;

  log_debug (dev, "port %u (%u:%u) init ok", port->port_id, md->pp_id, port->port_id);
  mvpp2_port_counters_init (port);

  mrv = mvpp2_gop_get_link_info (port, &li);
  if (mrv)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      log_err (dev, "failed to get link info for port %u, rv %d",
	       port->port_id, mrv);
      goto done;
    }

  log_debug (dev, "port %u %U", port->port_id, format_mvpp2_port_link_info, &li, mp);

  mvpp2_port_add_counters (vm, port);

done:
  if (rv != VNET_DEV_OK)
    mvpp2_port_stop (vm, port);
  return rv;
}

void
mvpp2_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  volatile u32 *flush_reg;
  uintptr_t hif_base;
  u32 val;

  log_debug (port->dev, "");

  if (mp->is_open)
    {
      mvpp2_port_counters_deinit (port);
      mvpp2_port_set_loopback (port, 0);
      mvpp2_port_set_promisc (port, 0);

      mvpp2_port_flush_mac_addrs (port, 1, 1);
      vec_free (mp->added_uc_addrs);

      mvpp2_port_restore_fc_isr (port);
      mvpp2_port_rxqs_fc_state_reset (port);
      foreach_vnet_dev_port_rx_queue (q, port)
	mvpp2_rxq_deinit (q);

      hif_base = mp->hif_base;
      flush_reg = (void *) (hif_base + MVPP2_TX_PORT_FLUSH_REG);
      val = __atomic_load_n (flush_reg, __ATOMIC_RELAXED);
      asm volatile ("dsb ld" : : : "memory");
      val |= MVPP2_TX_PORT_FLUSH_MASK (mp->id);
      mvpp2_reg_write (hif_base, MVPP2_TX_PORT_FLUSH_REG, val);

      foreach_vnet_dev_port_tx_queue (q, port)
	mvpp2_port_txq_deinit (q);

      val &= ~MVPP2_TX_PORT_FLUSH_MASK (mp->id);
      mvpp2_reg_write (hif_base, MVPP2_TX_PORT_FLUSH_REG, val);

      foreach_vnet_dev_port_tx_queue (q, port)
	{
	  mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);

	  vnet_dev_dma_mem_free (vm, port->dev, txq->desc_virt_arr);
	  txq->desc_virt_arr = 0;
	}

      foreach_vnet_dev_port_rx_queue (q, port)
	{
	  mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);

	  vnet_dev_dma_mem_free (vm, port->dev, rxq->hw_descs);
	  rxq->hw_descs = 0;
	}

      mvpp2_netdev_set_priv_flags (port, 0);
      mp->is_open = 0;
    }

  if (mp->bpool.is_initialized)
    {
      mvpp2_bpool_deinit (vm, port->dev, &mp->bpool);
    }
}

void
mvpp2_port_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  vnet_dev_t *dev = port->dev;
  vnet_dev_port_state_changes_t changes = {};
  struct mvpp2_port_link_info li;
  vnet_dev_rv_t mrv;

  mrv = mvpp2_gop_get_link_info (port, &li);

  if (mrv)
    {
      log_debug (dev, "failed to get link info, rv %d", mrv);
      return;
    }

  if (mp->last_link_info.up != li.up)
    {
      changes.change.link_state = 1;
      changes.link_state = li.up != 0;
      log_debug (dev, "link state changed to %u", changes.link_state);
    }

  if (mp->last_link_info.full_duplex != li.full_duplex)
    {
      changes.change.link_duplex = 1;
      changes.full_duplex = li.full_duplex;
      log_debug (dev, "link full duplex changed to %u", changes.full_duplex);
    }

  if (mp->last_link_info.speed != li.speed)
    {
      changes.change.link_speed = 1;
      changes.link_speed = li.speed;
      log_debug (dev, "link speed changed to %u", changes.link_speed);
    }

  if (changes.change.any)
    {
      mp->last_link_info = li;
      vnet_dev_port_state_change (vm, port, changes);
    }

  mvpp2_port_get_stats (vm, port);
}

vnet_dev_rv_t
mvpp2_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  log_debug (port->dev, "");

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *prq = vnet_dev_get_rx_queue_data (q);
      prq->n_bpool_refill = q->size;
      mrvl_pp2_bpool_put_no_inline (vm, q);
      if (prq->n_bpool_refill)
	log_warn (port->dev, "mrvl_pp2_bpool_put failed to fill %u buffers",
		  prq->n_bpool_refill);
    }

  log_debug (port->dev, "enabling port %u", mp->id);
  mvpp2_netdev_set_enable (port, 1);
  vlib_process_suspend (vm, 0.5);
  mvpp2_gop_max_rx_size_set (port);
  mvpp2_tx_sched_config (port);
  log_debug (port->dev, "start_dev: tx_port_num %d", MVPP2_MAX_TCONT + mp->id);
  mvpp2_port_egress_enable (port);
  mvpp2_port_ingress_enable (port);

  mp->is_enabled = 1;

  vnet_dev_poll_port_add (vm, port, 0.5, mvpp2_port_poll);

  return VNET_DEV_OK;
}

void
mvpp2_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_buff_info_t bi;

  log_debug (port->dev, "");

  if (mp->is_enabled)
    {
      vnet_dev_poll_port_remove (vm, port, mvpp2_port_poll);

      log_debug (port->dev, "stopping port %u", port->port_id);
      mvpp2_port_ingress_disable (port);
      vlib_process_suspend (vm, 0.01);
      mvpp2_port_interrupts_disable (port);
      mvpp2_port_egress_disable (port);
      mvpp2_netdev_set_enable (port, 0);

      vnet_dev_port_state_change (vm, port,
				  (vnet_dev_port_state_changes_t){
				    .change.link_state = 1,
				    .change.link_speed = 1,
				    .link_speed = 0,
				    .link_state = 0,
				  });
      mp->is_enabled = 0;
    }

  while (mvpp2_bpool_get_buff (vm, port->dev, &mp->bpool, &bi) == 0)
    vlib_buffer_free (vm, &(u32){ bi.cookie }, 1);
}

vnet_dev_rv_t
mvpp2_port_add_sec_if (vlib_main_t *vm, vnet_dev_port_t *port, void *p)
{
  vnet_dev_port_interface_t *sif = p;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 port_id = CLIB_U32_MAX, switch_id = 0, index;

  if (mp->is_dsa == 0)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  port_id = clib_args_get_uint32_val_by_name (sif->args, "dsa_port");
  switch_id = clib_args_get_uint32_val_by_name (sif->args, "dsa_switch");

  if (port_id == CLIB_U32_MAX)
    {
      log_err (port->dev, "missing dsa_port argument");
      return VNET_DEV_ERR_INVALID_ARG;
    }

  log_debug (port->dev, "switch %u port %u", switch_id, port_id);

  mv_dsa_tag_t tag = {
    .tag_type = MV_DSA_TAG_TYPE_FROM_CPU,
    .src_port_or_lag = port_id,
    .src_dev = switch_id,
  };

  index = switch_id << 5 | port_id;

  sif->user_data = tag.as_u32;
  uword_bitmap_set_bits_at_index (mp->valid_dsa_src_bitmap, index, 1);
  mp->dsa_to_sec_if[index] = sif->index;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_port_del_sec_if (vlib_main_t *vm, vnet_dev_port_t *port, void *p)
{
  vnet_dev_port_interface_t *sif = p;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mv_dsa_tag_t tag = { .as_u32 = sif->user_data };
  u32 index = tag.src_dev << 5 | tag.src_port_or_lag;

  log_debug (port->dev, "switch %u port %u", tag.src_dev, tag.src_port_or_lag);

  uword_bitmap_clear_bits_at_index (mp->valid_dsa_src_bitmap, index, 1);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
				vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_PROMISC_MODE:
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      break;

    default:
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}

vnet_dev_rv_t
mvpp2_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
		       vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  eth_addr_t addr;
  vnet_dev_rv_t mrv;

  switch (req->type)
    {

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      mrv = mvpp2_port_set_promisc (port, req->promisc);
      if (mrv)
	{
	  log_err (port->dev, "mvpp2_port_set_promisc: failed, rv %d", mrv);
	  rv = VNET_DEV_ERR_INTERNAL;
	}
      else
	log_debug (port->dev, "promisc %u", req->promisc);
      break;

    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      clib_memcpy (&addr, req->addr.eth_mac, sizeof (addr));
      mrv = mvpp2_port_set_mac_addr (port, addr);
      if (mrv)
	{
	  log_err (port->dev, "mvpp2_port_set_mac_addr: failed, rv %d", mrv);
	  rv = VNET_DEV_ERR_INTERNAL;
	}
      else
	log_debug (port->dev, "primary MAC %U set", format_ethernet_address, &addr);
      break;

    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      clib_memcpy (&addr, req->addr.eth_mac, sizeof (addr));
      mrv = mvpp2_port_add_mac_addr (port, addr);
      if (mrv)
	{
	  log_err (port->dev, "mvpp2_port_add_mac_addr: failed, rv %d", mrv);
	  rv = VNET_DEV_ERR_INTERNAL;
	}
      else
	log_debug (port->dev, "secondary MAC %U added", format_ethernet_address, &addr);
      break;

    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      clib_memcpy (&addr, req->addr.eth_mac, sizeof (addr));
      mrv = mvpp2_port_remove_mac_addr (port, addr);
      if (mrv)
	{
	  log_err (port->dev, "mvpp2_port_remove_mac_addr: failed, rv %d", mrv);
	  rv = VNET_DEV_ERR_INTERNAL;
	}
      else
	log_debug (port->dev, "secondary MAC %U removed", format_ethernet_address, &addr);
      break;

    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}
