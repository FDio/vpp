/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
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

static vnet_dev_rv_t
mvpp2_port_set_loopback (vnet_dev_port_t *port, int en)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int mac_num = mp->gop_index;
  u32 val;

  /* Configure GMAC loopback. */
  val = mvpp2_gop_gmac_reg_rd (port->dev, mac_num, PP2_GMAC_PORT_CTRL1_REG);
  if (en)
    val |= PP2_GMAC_PORT_CTRL1_GMII_LOOPBACK_MASK;
  else
    val &= ~PP2_GMAC_PORT_CTRL1_GMII_LOOPBACK_MASK;
  mvpp2_gop_gmac_reg_wr (port->dev, mac_num, PP2_GMAC_PORT_CTRL1_REG, val);

  /* GOP#0 and GOP#2 (in PP23/CP115) can support both XLG and GMAC.
   * Configure both MAC blocks when the port has XLG capability.
   */
  if (mp->has_xlg)
    {
      mvpp22_xlg_mac_ctrl1_reg_t control;

      /* Configure XLG loopback when available. */
      control.as_u32 = mvpp2_gop_xlg_reg_rd (port->dev, mac_num, PP2_XLG_PORT_MAC_CTRL1_REG);
      control.mac_loopback = en;
      control.xgmii_loopback = en;
      mvpp2_gop_xlg_reg_wr (port->dev, mac_num, PP2_XLG_PORT_MAC_CTRL1_REG, control.as_u32);
    }

  return VNET_DEV_OK;
}

static void
mvpp2_port_egress_disable_qmask (vnet_dev_port_t *port, u32 q_mask)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp22_txp_sched_port_index_reg_t port_index = {
    .index = MVPP2_MAX_TCONT + mp->id,
  };
  mvpp22_txp_sched_q_cmd_reg_t command = {};
  volatile u32 tmo;

  /* Issue stop command for active channels only */
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PORT_INDEX_REG, port_index.as_u32);
  if (q_mask)
    {
      command.disable = q_mask;
      mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_Q_CMD_REG, command.as_u32);
    }

  /* TXQs disable. Wait for all Tx activity to terminate. */
  tmo = 0;
  do
    {
      if (tmo >= MVPP2_TX_DISABLE_TIMEOUT_MSEC)
	{
	  log_warn (dev, "Port: Egress disable timeout = 0x%08X\n", command.as_u32);
	  break;
	}
      /* Sleep for 1 millisecond */
      usleep (1000);
      tmo++;
      command.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_TXP_SCHED_Q_CMD_REG);
    }
  while (command.enable & q_mask);
}

static void
mvpp2_port_egress_disable (vnet_dev_port_t *port)
{
  mvpp22_txp_sched_q_cmd_reg_t command;

  command.as_u32 = mvpp2_dev_reg_rd (port->dev, MVPP2_TXP_SCHED_Q_CMD_REG);
  mvpp2_port_egress_disable_qmask (port, command.enable);
}

static void
mvpp2_port_egress_enable (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp22_txp_sched_port_index_reg_t port_index = {
    .index = MVPP2_MAX_TCONT + mp->id,
  };
  mvpp22_txp_sched_q_cmd_reg_t command = {};
  u32 q_mask = 0;

  foreach_vnet_dev_port_tx_queue (q, port)
    q_mask |= 1 << q->queue_id;

  command.enable = q_mask;
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PORT_INDEX_REG, port_index.as_u32);
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_Q_CMD_REG, command.as_u32);
  log_debug (dev, "Port: Egress enable tx_port_num=%u q_mask=0x%X\n", port_index.index, q_mask);
}

static void
mvpp2_port_ingress_disable (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  /* RXQs disable */
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
      mvpp22_rxq_config_reg_t config;

      config.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_RXQ_CONFIG_REG (rxq->hw_id));
      config.disable = 1;
      mvpp2_dev_reg_wr (dev, MVPP2_RXQ_CONFIG_REG (rxq->hw_id), config.as_u32);
    }
}

static void
mvpp2_port_ingress_enable (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  /* RXQs enable */
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
      mvpp22_rxq_config_reg_t config;

      config.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_RXQ_CONFIG_REG (rxq->hw_id));
      config.disable = 0;
      mvpp2_dev_reg_wr (dev, MVPP2_RXQ_CONFIG_REG (rxq->hw_id), config.as_u32);
    }
}

static void
mvpp2_port_defaults_set (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp22_txp_sched_port_index_reg_t port_index = {
    .index = MVPP2_MAX_TCONT + mp->id,
  };
  mvpp22_txp_sched_refill_reg_t refill;
  mvpp22_rx_ctrl_reg_t rx_ctrl = {
    .gem_port_id_src = 2,
    .low_latency_pkt_size = 256,
    .use_pseudo_for_csum = 1,
  };
  u32 queue, ptxq;

  /* Disable Legacy WRR, Disable EJP, Release from reset */
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PORT_INDEX_REG, port_index.as_u32);
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_CMD_1_REG, 0x0);

  /* Close bandwidth for all queues */
  for (queue = 0; queue < MVPP2_MAX_TXQ; queue++)
    {
      ptxq = (MVPP2_MAX_TCONT + mp->id) * MVPP2_MAX_TXQ + queue;
      mvpp2_dev_reg_wr (dev, MVPP2_TXQ_SCHED_TOKEN_CNTR_REG (ptxq), 0x0);
    }

  /* Set refill period to 1 usec, refill tokens
   * and bucket size to maximum
   */
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_PERIOD_REG, PP2_TCLK_FREQ / 1000000); /* USEC_PER_SEC */
  refill.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_TXP_SCHED_REFILL_REG);
  refill.period = 1;
  refill.tokens = MVPP2_TXP_REFILL_TOKENS_MAX;
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_REFILL_REG, refill.as_u32);
  mvpp2_dev_reg_wr (dev, MVPP2_TXP_SCHED_TOKEN_SIZE_REG, MVPP2_TXP_TOKEN_SIZE_MAX);

  /* Set MaximumLowLatencyPacketSize value to 256 */
  /* Set GemPortIdSrcSel from classifier */
  mvpp2_dev_reg_wr (dev, MVPP2_RX_CTRL_REG (mp->id), rx_ctrl.as_u32);

  /* Disable Rx cache snoop */
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
      mvpp22_rxq_config_reg_t config;

      config.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_RXQ_CONFIG_REG (rxq->hw_id));
      /* Coherent */
      config.snoop_pkt_size = 0x1ff;
      config.snoop_buf_hdr = 1;
      mvpp2_dev_reg_wr (dev, MVPP2_RXQ_CONFIG_REG (rxq->hw_id), config.as_u32);
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
  mvpp2_port_link_info_t li;
  enum mvpp2_port_hash_type hash_type = MVPP2_PORT_HASH_5_TUPLE;
  char ifname[IFNAMSIZ];
  vnet_dev_rv_t mrv;
  u16 n_rxq = vnet_dev_get_port_num_rx_queues (port);
  u8 index;

  log_debug (port->dev, "");

  if (n_rxq > 1)
    hash_type = clib_args_get_enum_val_by_name (port->args, "rss_hash");

  index = get_lowest_set_bit_index (md->free_bpools);
  md->free_bpools ^= 1 << index;

  mrv = mvpp2_bpool_init (vm, dev, index, vlib_buffer_get_default_data_size (vm), &mp->bpool);
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
      vnet_dev_rx_queue_if_rt_data_t *if_rt_data = vnet_dev_get_rx_queue_if_rt_data (q);

      prq->bpool_desc_template = (mvpp2_tx_desc_t) {
	.cmd = {
	  .buf_mode = 1,
	  .l4_chk_disable = 2,
	  .ip_chk_disable = 1,
	  .pool_id = mp->bpool.id,
	  .last = 1,
	  .first = 1,
	},
	.pkt_offset = MVPP2_BPOOL_DUMMY_PKT_EFEC_OFFS,
	.dest_qid = MVPP2_LOOPBACK_TXQ_ID,
	.err_sum = 1,
      };
      if_rt_data->buffer_template.current_data = MV_MH_SIZE;
    }

  mvpp2_port_ifname (port, ifname);
  log_debug (dev, "port init: pp2_id(%u), port_id(%u), ifname(%s)", md->pp_id, mp->id, ifname);

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
      txq->desc_template = (mvpp2_tx_desc_t) {
	.cmd = {
	  .l4_chk_disable = 2,
	  .ip_chk_disable = 1,
	  .last = 1,
	  .first = 1,
	},
	.dest_qid = txq->hw_id,
      };
    }

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);

      rxq->hw_id = mvpp2_port_get_rxq_hw_id (port, q->queue_id);
      log_debug (dev, "port[%u:%u] rxq%u", md->pp_id, mp->id, rxq->hw_id);
    }
  mvpp2_port_ingress_disable (port);
  mvpp2_port_defaults_set (port);
  mvpp2_rss_port_init (port, n_rxq > 1 ? hash_type : MVPP2_PORT_HASH_NONE);
  mvpp2_cls_mng_config_default_cos_queue (port);

  rv = mvpp2_port_clear_prs_vlans (port);
  if (rv != VNET_DEV_OK)
    goto done;
  mvpp2_port_flush_mac_addrs (port, 1, 1);
  mp->rx_pause_en = 1;
  mvpp2_port_set_rx_pause (port, 0);

  mvpp2x_cls_oversize_rxq_set (port);
  foreach_vnet_dev_port_rx_queue (q, port)
    if ((rv = mvpp2_rxq_init (vm, q)) != VNET_DEV_OK)
      goto done;
  mvpp2_port_clear_fc_isr (port);

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      if ((rv = mvpp2_txq_init (vm, q)) != VNET_DEV_OK)
	goto done;
      mvpp2_port_set_txq_state (q, 1);
    }

  if (mvpp2_parser_eth_start_header_set (port, MVPP2_PORT_HDR_ETH))
    {
      log_err (dev, "port %u failed to initialize ethernet start header", port->port_id);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  if (mvpp2_cls_mng_modify_default_flows (port))
    {
      log_err (dev, "port %u failed to modify default flows", port->port_id);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  mvpp2_port_set_loopback (port, 0);
  mvpp2_port_set_promisc (port, 0);
  mp->is_open = 1;

  log_debug (dev, "port %u (%u:%u) init ok", port->port_id, md->pp_id, port->port_id);
  mvpp2_gop_get_link_info (port, &li);
  log_debug (dev, "port %u %U", port->port_id, format_mvpp2_port_link_info, &li, mp);

  mvpp2_port_add_counters (vm, port);
  mvpp2_port_counters_init (vm, port);

done:
  if (rv != VNET_DEV_OK)
    {
      mvpp2_port_stop (vm, port);
      foreach_vnet_dev_port_tx_queue (q, port)
	{
	  mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);

	  if (txq->desc_virt_arr)
	    {
	      mvpp2_port_txq_deinit (q);
	      vnet_dev_dma_mem_free (vm, dev, txq->desc_virt_arr);
	      txq->desc_virt_arr = 0;
	    }
	}
      foreach_vnet_dev_port_rx_queue (q, port)
	{
	  mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);

	  if (rxq->hw_descs)
	    {
	      mvpp2_rxq_deinit (q);
	      vnet_dev_dma_mem_free (vm, dev, rxq->hw_descs);
	      rxq->hw_descs = 0;
	    }
	}
    }
  return rv;
}

void
mvpp2_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 val;

  log_debug (dev, "");

  if (mp->is_open)
    {
      mvpp2_port_set_loopback (port, 0);
      mvpp2_port_set_promisc (port, 0);

      mvpp2_port_flush_mac_addrs (port, 1, 1);
      vec_free (mp->added_uc_addrs);

      mvpp2_port_restore_fc_isr (port);
      foreach_vnet_dev_port_rx_queue (q, port)
	mvpp2_rxq_deinit (q);

      val = mvpp2_dev_reg_rd (dev, MVPP2_TX_PORT_FLUSH_REG);
      val |= MVPP2_TX_PORT_FLUSH_MASK (mp->id);
      mvpp2_dev_reg_wr (dev, MVPP2_TX_PORT_FLUSH_REG, val);

      foreach_vnet_dev_port_tx_queue (q, port)
	mvpp2_port_txq_deinit (q);

      val &= ~MVPP2_TX_PORT_FLUSH_MASK (mp->id);
      mvpp2_dev_reg_wr (dev, MVPP2_TX_PORT_FLUSH_REG, val);

      foreach_vnet_dev_port_tx_queue (q, port)
	{
	  mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);

	  vnet_dev_dma_mem_free (vm, dev, txq->desc_virt_arr);
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
  mvpp2_port_link_info_t li;

  mvpp2_gop_get_link_info (port, &li);
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
  mvpp2_gop_max_rx_size_set (port, port->max_rx_frame_size);
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
mvpp2_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
				vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
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

    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      mvpp2_gop_max_rx_size_set (port, req->max_rx_frame_size);
      log_debug (port->dev, "max rx frame size %u", req->max_rx_frame_size);
      break;

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
