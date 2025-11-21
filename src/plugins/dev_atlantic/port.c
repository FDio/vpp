/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_atlantic/atlantic.h>

VLIB_REGISTER_LOG_CLASS (atl_log, static) = {
  .class_name = "atlantic",
  .subclass_name = "port",
};

void
atl_port_status_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  atl_port_t *ap = vnet_dev_get_port_data (port);
  static const u32 rate_lut[] = {
    0, 10000, 100000, 1000000, 2500000, 5000000, 10000000,
  };
  vnet_dev_rv_t rv;
  atl_reg_aq2_fw_interface_out_link_status_t st;
  vnet_dev_port_state_changes_t changes = {};

  rv = atl_aq2_interface_buffer_read (
    dev, ATL_REG_AQ2_FW_INTERFACE_OUT_LINK_STATUS, &st.as_u32, 1);

  if (rv != VNET_DEV_OK)
    {
      if (ap->link_status_fail == 0)
	log_err (dev, "link status read failed");
      ap->link_status_fail = 1;
      return;
    }
  else if (ap->link_status_fail)
    {
      log_notice (dev, "link status read restored");
      ap->link_status_fail = 0;
    }

  if (st.as_u32 == ap->last_link_status.as_u32)
    return;

  if (st.link_rate != ap->last_link_status.link_rate)
    {
      changes.change.link_speed = 1;
      changes.link_speed =
	(st.link_rate < ARRAY_LEN (rate_lut)) ? rate_lut[st.link_rate] : 0;

      log_debug (dev, "link speed changed to %u kbps", changes.link_speed);
    }

  if (st.link_state != ap->last_link_status.link_state)
    {
      changes.change.link_state = 1;
      changes.link_state = st.link_state;

      log_debug (dev, "link state changed to %s",
		 changes.link_state ? "up" : "down");
    }

  if (st.duplex != ap->last_link_status.duplex)
    {
      changes.change.link_duplex = 1;
      changes.full_duplex = st.duplex;

      log_debug (dev, "link duplex changed to %s",
		 st.duplex ? "full" : "half");
    }

  ap->last_link_status = st;

  if (changes.change.any)
    vnet_dev_port_state_change (vm, port, changes);
}

static vnet_dev_rv_t
aq2_filter_art_set (vnet_dev_t *dev, u32 idx,
		    atl_reg_aq2_rpf_act_art_req_tag_t tag,
		    atl_reg_aq2_rpf_act_art_req_tag_t mask,
		    atl_reg_aq2_rpf_act_art_req_action_t action)
{
  atl_device_t *ad = vnet_dev_get_data (dev);
  vlib_main_t *vm = vlib_get_main ();
  f64 t0 = vlib_time_now (vm);

  while (1)
    {
      if (atl_reg_rd_u32 (dev, ATL_REG_AQ2_ART_SEM) == 1)
	break;
      if (vlib_time_now (vm) - t0 > 10e-3)
	return VNET_DEV_ERR_TIMEOUT;
    }

  idx += ad->resolver_base;
  atl_reg_wr (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_TAG (idx),
	      (atl_reg_t){ .aq2_rpf_act_art_req_tag = tag });
  atl_reg_wr (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_MASK (idx),
	      (atl_reg_t){ .aq2_rpf_act_art_req_tag = mask });
  atl_reg_wr (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_ACTION (idx),
	      (atl_reg_t){ .aq2_rpf_act_art_req_action = action });

  atl_reg_wr_u32 (dev, ATL_REG_AQ2_ART_SEM, 1);

  return VNET_DEV_OK;
}

static void
atl_aq2_launchtime_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  u32 fpgaver, speed;

  fpgaver = atl_reg_rd (dev, ATL_REG_AQ2_HW_FPGA_VERSION).as_u32;
  if (fpgaver < 0x01000000)
    speed = 1; /* AQ2_LAUNCHTIME_CTRL_RATIO_SPEED_FULL */
  else if (fpgaver >= 0x01008502)
    speed = 2; /* AQ2_LAUNCHTIME_CTRL_RATIO_SPEED_HALF */
  else
    speed = 4; /* AQ2_LAUNCHTIME_CTRL_RATIO_SPEED_QUARTER */

  atl_reg_wr (dev, ATL_REG_AQ2_LAUNCHTIME_CTRL,
	      (atl_reg_t){
		.aq2_launchtime_ctrl = {
		  .ratio = speed,
		},
	      });
  log_debug (dev, "launchtime init done (speed %u)", speed);
}

static void
atl_tx_path_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  atl_reg_t r;

  r = atl_reg_rd (dev, ATL_REG_TPB_TX_BUF);
  r.tpb_tx_buf.en = 1;
  r.tpb_tx_buf.tc_mode_en = 1;
  r.tpb_tx_buf.scp_ins_en = 1;
  r.tpb_tx_buf.clk_gate_en = 0;
  r.tpb_tx_buf.tc_q_rand_map_en = 1;
  atl_reg_wr (dev, ATL_REG_TPB_TX_BUF, r);

  atl_reg_wr (dev, ATL_REG_THM_LSO_TCP_FLAG1,
	      (atl_reg_t){
		.thm_lso_tcp_flag = {
		  .val = 0x0ff6,
		},
	      });
  atl_reg_wr (dev, ATL_REG_THM_LSO_TCP_FLAG1 + 4,
	      (atl_reg_t){
		.thm_lso_tcp_flag = {
		  .val = 0x0ff6,
		},
	      }); /* MID */
  atl_reg_wr (dev, ATL_REG_THM_LSO_TCP_FLAG2,
	      (atl_reg_t){
		.thm_lso_tcp_flag = {
		  .val = 0x0f7f,
		},
	      });

  atl_reg_wr (dev, ATL_REG_TX_TPO2,
	      (atl_reg_t){
		.tx_tpo2 = {
		  .en = 1,
		},
	      });

  atl_reg_wr (dev, ATL_REG_TDM_DCA, (atl_reg_t){});
  log_debug (dev, "tx path init done");
}

static void
atl_rss_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  u32 rss_key[10] = { 0x8771ad1e, 0x7d26fc65, 0x7467450d, 0x181a06cd,
		      0xc7f0c1b6, 0xf8be18bb, 0xa94b1319, 0x70fe3ed0,
		      0x50ab0325, 0x0c828b6a };
  u32 n_rxq = pool_elts (port->rx_queues);
  int i;

  for (i = 0; i < 10; i++)
    {
      atl_reg_wr_u32 (dev, ATL_REG_RPF_RSS_KEY_WR_DATA,
		      clib_host_to_net_u32 (rss_key[9 - i]));
      atl_reg_wr_u32 (dev, ATL_REG_RPF_RSS_KEY_ADDR, i | 0x20);
      while (atl_reg_rd_u32 (dev, ATL_REG_RPF_RSS_KEY_ADDR) & 0x20)
	;
    }

  for (i = 0; i < 64; i++)
    {
      u32 q = i % n_rxq;

      atl_reg_wr_u32 (dev, ATL_REG_AQ2_RPF_RSS_REDIR (i), q);
    }
}

static void
atl_rx_path_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  atl_reg_rpb_rpf_rx_t rpb_rx;
  atl_reg_t r = {};

  rpb_rx = atl_reg_rd (dev, ATL_REG_RPB_RPF_RX).rpb_rpf_rx;
  rpb_rx.buf_en = 1;

  if (pool_elts (port->rx_queues) > 1)
    {

      atl_rss_init (port);
      r.rx_flr_rss_control1.en = 1;
      r.rx_flr_rss_control1.queues = 0x33333333;

      rpb_rx.tc_mode = 1;
    }
  else
    rpb_rx.tc_mode = 0;

  atl_reg_wr (dev, ATL_REG_AQ2_RPF_REDIR2,
	      (atl_reg_t){
		.aq2_rpf_redir2.hashtype = 0x1FF,
	      });

  atl_reg_wr (dev, ATL_REG_RPB_RPF_RX,
	      (atl_reg_t){
		.rpb_rpf_rx = rpb_rx,
	      });

  atl_reg_wr (dev, ATL_REG_RX_FLR_RSS_CONTROL1, r);
  atl_reg_wr (dev, ATL_REG_RX_DMA_DCA, (atl_reg_t){});
  log_debug (dev, "rx path init done");
}

static void
atl_filters_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  atl_reg_rpf_l2uc_msw_t l2uc_msw;
  int i;

  for (i = 0; i < AQ_HW_MAC_NUM; i++)
    {
      l2uc_msw = atl_reg_rd (dev, ATL_REG_RPF_L2UC_MSW (i)).rpf_l2uc_msw;
      l2uc_msw.en = 0;
      l2uc_msw.action = 1; /* RPF_ACTION_HOST */
      atl_reg_wr (dev, ATL_REG_RPF_L2UC_MSW (i),
		  (atl_reg_t){ .rpf_l2uc_msw = l2uc_msw });
    }

  atl_reg_wr_u32 (dev, ATL_REG_RPF_MCAST_FILTER_MASK, 0);
  atl_reg_wr_u32 (dev, ATL_REG_RPF_MCAST_FILTER (0), 0x00010fff);

  atl_reg_wr (dev, ATL_REG_RPF_VLAN_TPID,
	      (atl_reg_t){
		.rpf_vlan_tpid = {
		  .outer = 0,
		  .inner = 0,
		},
	      });

  atl_reg_wr (dev, ATL_REG_RPF_VLAN_MODE,
	      (atl_reg_t){
		.rpf_vlan_mode = {
		  .promisc = 1,
		  .accept_untagged = 1,
		  .untagged_action = 1, /* RPF_ACTION_HOST */
		},
	      });
  log_debug (dev, "filters init done");
}

static vnet_dev_rv_t
atl_aq2_filters_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  atl_reg_rpf_l2uc_msw_t l2uc_msw0;
  vnet_dev_rv_t rv;
  int i;

  atl_reg_wr (dev, ATL_REG_AQ2_RPF_REC_TAB_ENABLE,
	      (atl_reg_t){
		.aq2_rpf_rec_tab_enable = {
		  .mask = 0xffff,
		},
	      });

  l2uc_msw0 = atl_reg_rd (dev, ATL_REG_RPF_L2UC_MSW (0)).rpf_l2uc_msw;
  l2uc_msw0.tag = 1;
  atl_reg_wr (dev, ATL_REG_RPF_L2UC_MSW (0),
	      (atl_reg_t){ .rpf_l2uc_msw = l2uc_msw0 });

  atl_reg_wr (dev, ATL_REG_AQ2_RPF_L2BC_TAG,
	      (atl_reg_t){
		.aq2_rpf_l2bc_tag = {
		  .mask = 1,
		},
	      });

  rv = aq2_filter_art_set (dev, AQ2_RPF_INDEX_L2_PROMISC_OFF,
			   (atl_reg_aq2_rpf_act_art_req_tag_t){},
			   (atl_reg_aq2_rpf_act_art_req_tag_t){
			     .uc = 0x2f,
			     .allmc = 1,
			   },
			   (atl_reg_aq2_rpf_act_art_req_action_t){
			     .enable = 1,
			   });

  if (rv != VNET_DEV_OK)
    return rv;

  rv = aq2_filter_art_set (dev, AQ2_RPF_INDEX_VLAN_PROMISC_OFF,
			   (atl_reg_aq2_rpf_act_art_req_tag_t){},
			   (atl_reg_aq2_rpf_act_art_req_tag_t){
			     .vlan = 0xf,
			     .untag = 1,
			   },
			   (atl_reg_aq2_rpf_act_art_req_action_t){});

  if (rv != VNET_DEV_OK)
    return rv;

  for (i = 0; i < 8; i++)
    {
      rv = aq2_filter_art_set (
	dev, AQ2_RPF_INDEX_PCP_TO_TC + i,
	(atl_reg_aq2_rpf_act_art_req_tag_t){ .pcp = i },
	(atl_reg_aq2_rpf_act_art_req_tag_t){ .pcp = 0x7 },
	(atl_reg_aq2_rpf_act_art_req_action_t){
	  .action = 1, .rss = 1, .index = i % 1, .enable = 1 }); /* TC 0 */
      if (rv != VNET_DEV_OK)
	return rv;
    }

  atl_reg_wr (dev, ATL_REG_RPF_L2BC,
	      (atl_reg_t){
		.rpf_l2bc = {
		  .en = 1,
		  .action = 1,
		  .threshold = 0xffff,
		},
	      });

  atl_reg_wr (dev, ATL_REG_AQ2_RPF_NEW_CTRL,
	      (atl_reg_t){
		.aq2_rpf_new_ctrl = {
		  .enable = 1,
		},
	      });
  log_debug (dev, "AQ2 filters init done");

  return VNET_DEV_OK;
}

static void
atl_mac_addr_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  atl_device_t *ad = vnet_dev_get_data (dev);
  u32 h, l;

  h = (ad->mac[0] << 8) | (ad->mac[1]);
  l = ((u32) ad->mac[2] << 24) | (ad->mac[3] << 16) | (ad->mac[4] << 8) |
      (ad->mac[5]);

  atl_reg_wr (dev, ATL_REG_RPF_L2UC_MSW (0),
	      (atl_reg_t){
		.rpf_l2uc_msw = {
		  .en = 0,
		},
	      });
  atl_reg_wr_u32 (dev, ATL_REG_RPF_L2UC_LSW (0), l);
  atl_reg_wr (dev, ATL_REG_RPF_L2UC_MSW (0),
	      (atl_reg_t){
		.rpf_l2uc_msw = {
		  .macaddr_hi = h,
		  .action = 1, /* RPF_ACTION_HOST */
		  .tag = 1,
		  .en = 1,
		},
	      });
  log_debug (dev, "MAC address init done");
}

static void
atl_buffers_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  u32 buff_size = 192; /* AQ2_HW_RXBUF_MAX */
  int i;

  buff_size = 128; /* AQ2_HW_TXBUF_MAX */
  atl_reg_wr (dev, ATL_REG_TPB_TXB_BUFSIZE (0),
	      (atl_reg_t){
		.tpb_txb_bufsize = {
		  .bufsize = buff_size,
		},
	      });

  atl_reg_wr (dev, ATL_REG_TPB_TXB_THRESH (0),
	      (atl_reg_t){
		.tpb_txb_thresh = {
		  .hi = (buff_size * (1024 / 32) * 66) / 100,
		  .lo = (buff_size * (1024 / 32) * 50) / 100,
		},
	      });

  atl_reg_wr (dev, ATL_REG_RPB_RXB_BUFSIZE (0),
	      (atl_reg_t){
		.rpb_rxb_bufsize = {
		  .bufsize = buff_size,
		},
	      });

  atl_reg_wr (dev, ATL_REG_RPB_RXB_XOFF (0),
	      (atl_reg_t){
		.rpb_rxb_xoff = {
		  .hi = (buff_size * (1024 / 32) * 66) / 100,
		  .lo = (buff_size * (1024 / 32) * 50) / 100,
		  .en = 0,
		},
	      });

  for (i = 0; i < 8; i++)
    atl_reg_wr_u32 (dev, ATL_REG_RPF_RPB_RX_TC_UPT, 0);

  /* Map all queues to TC 0 */
  foreach_vnet_dev_port_tx_queue (txq, port)
    atl_reg_wr_u32 (dev, ATL_REG_AQ2_TX_Q_TC_MAP (txq->queue_id), 0);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    atl_reg_wr_u32 (dev, ATL_REG_AQ2_RX_Q_TC_MAP (rxq->queue_id), 0);

  log_debug (dev, "buffers init done");
}

static void
atl_interrupts_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  atl_reg_wr (dev, ATL_REG_INTR_CTRL,
	      (atl_reg_t){
		.aq_intr_ctrl = {
		  .reset_dis = 1,
		  .irqmode = 0,
		},
	      });

  atl_reg_wr_u32 (dev, ATL_REG_INTR_AUTOMASK, 0xffffffff);

  /* Map all interrupts to vector 0 (though disabled) */
  atl_reg_wr_u32 (dev, ATL_REG_AQ_GEN_INTR_MAP (0), 0);
  log_debug (dev, "interrupts init done");
}

vnet_dev_rv_t
atl_port_init (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv;

  atl_aq2_launchtime_init (port);
  atl_tx_path_init (port);
  atl_rx_path_init (port);
  atl_filters_init (port);

  rv = atl_aq2_filters_init (port);
  if (rv != VNET_DEV_OK)
    return rv;

  atl_mac_addr_init (port);
  atl_buffers_init (port);
  atl_interrupts_init (port);
  atl_port_counters_init (vlib_get_main (), port);
  vnet_dev_poll_port_add (vlib_get_main (), port, 1, atl_port_counter_poll);
  vnet_dev_poll_port_add (vlib_get_main (), port, 1, atl_port_status_poll);

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
atl_aq2_fw_wait_shared_ack (vnet_dev_t *dev)
{
  vlib_main_t *vm = vlib_get_main ();
  f64 t0 = vlib_time_now (vm);

  atl_reg_wr_u32 (dev, ATL_REG_AQ2_MIF_HOST_FINISHED_STATUS_WRITE, 1);

  while (1)
    {
      if ((atl_reg_rd_u32 (dev, ATL_REG_AQ2_MIF_HOST_FINISHED_STATUS_READ) &
	   1) == 0)
	return VNET_DEV_OK;

      if (vlib_time_now (vm) - t0 > 1.0)
	return VNET_DEV_ERR_TIMEOUT;
    }
}

vnet_dev_rv_t
atl_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  atl_device_t *ad = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = VNET_DEV_OK;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    if (rxq->enabled)
      {
	atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
	u16 mask = rxq->size - 1;
	u64 dma_addr = vnet_dev_get_dma_addr (vm, dev, aq->descs);
	u32 data_size = vnet_dev_get_rx_queue_buffer_data_size (vm, rxq);
	u32 buf_sz, desc_cfg, n_alloc, base, v, qid = rxq->queue_id;
	u8 bpi;
	f64 t0;

	mask = rxq->size - 1;

	buf_sz = (data_size + 1023) / 1024;
	if (buf_sz == 0)
	  buf_sz = 1;
	if (buf_sz > 31)
	  buf_sz = 31;

	desc_cfg = (rxq->size / 8) << 3;

	atl_reg_wr_u32 (dev, ATL_REG_RX_DMA_DESC_LEN (qid), desc_cfg);
	atl_reg_wr_u32 (dev, ATL_REG_RX_DMA_DESC_HEAD_PTR (qid), 0);
	atl_reg_wr_u32 (dev, ATL_REG_RX_DMA_DESC_BASE_ADDRLSW (qid), dma_addr);
	atl_reg_wr_u32 (dev, ATL_REG_RX_DMA_DESC_BASE_ADDRMSW (qid),
			dma_addr >> 32);
	aq->tail_reg =
	  (u32 *) ((u8 *) ad->bar0 + ATL_REG_RX_DMA_DESC_TAIL_PTR (qid));

	base = ATL_REG_RX_DMA_DESC_BASE_ADDRLSW (qid) - 0x0;
	atl_reg_wr_u32 (dev, base + 0x0c, 0);
	atl_reg_wr_u32 (dev, base + 0x18, buf_sz);

	bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
	n_alloc = vlib_buffer_alloc_from_pool (vm, aq->buffer_indices,
					       rxq->size - 1, bpi);

	if (n_alloc != rxq->size - 1)
	  {
	    if (n_alloc)
	      vlib_buffer_free (vm, aq->buffer_indices, n_alloc);
	    rv = VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
	    goto done;
	  }

	for (u16 i = 0; i < n_alloc; i++)
	  {
	    vlib_buffer_t *b = vlib_get_buffer (vm, aq->buffer_indices[i]);

	    aq->descs[i] = (atl_rx_desc_t){
	      .buf_addr = vnet_dev_get_dma_addr (vm, dev, b->data),
	    };
	  }

	aq->head = 0;
	aq->tail = n_alloc;

	__atomic_store_n (aq->tail_reg, aq->tail & mask, __ATOMIC_RELEASE);

	aq->next_index = 0;

	atl_reg_wr_u32 (dev, ATL_REG_RX_DMA_DESC_LEN (qid),
			desc_cfg | (1U << 31));
	v = atl_reg_rd_u32 (dev, 0x5a00);
	atl_reg_wr_u32 (dev, 0x5a00, v ^ 1);

	t0 = vlib_time_now (vm);
	while (atl_reg_rd_u32 (dev, 0x5a10) == 0)
	  if (vlib_time_now (vm) - t0 > 10e-3)
	    break;
      }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      atl_txq_t *aq = vnet_dev_get_tx_queue_data (txq);
      u64 dma_addr;
      u32 qid = txq->queue_id;

      dma_addr = vnet_dev_get_dma_addr (vm, dev, aq->descs);

      atl_reg_wr (dev, ATL_REG_TX_DMA_DESC_LEN (qid),
		  (atl_reg_t){ .tx_dma_desc_len = { .len = txq->size / 8, }, });

      atl_reg_wr_u32 (dev, ATL_REG_TX_DMA_DESC_BASE_ADDRLSW (qid), dma_addr);
      atl_reg_wr_u32 (dev, ATL_REG_TX_DMA_DESC_BASE_ADDRMSW (qid),
		      dma_addr >> 32);

      aq->tail_reg =
	(u32 *) ((u8 *) ad->bar0 + ATL_REG_TX_DMA_DESC_TAIL_PTR (qid));

      aq->head_index = 0;
      aq->tail_index = 0;

      __atomic_store_n (aq->tail_reg, 0, __ATOMIC_RELEASE);

      atl_reg_wr (dev, ATL_REG_TX_DMA_DESC_LEN (qid),
		  (atl_reg_t){
		    .tx_dma_desc_len = {
		      .len = txq->size / 8,
		      .en = 1,
		    },
		  });
    }

  /* Enable link */
  atl_reg_wr (dev, ATL_REG_AQ2_FW_INTERFACE_IN_LINK_CONTROL,
	      (atl_reg_t){
		.aq2_fw_interface_in_link_control = {
		  .mode = 1, /* MODE_ACTIVE */
		},
	      });

  atl_reg_wr (dev, ATL_REG_AQ2_FW_INTERFACE_IN_LINK_OPTIONS,
	      (atl_reg_t){
		.aq2_fw_interface_in_link_options = {
		  .link_up = 1,
		  .link_renegotiate = 1,
		  .rate = 0xFF,
		  .rate_hd = 0x7,
		  .pause_rx = 1,
		  .pause_tx = 1,
		  .downshift = 1,
		},
	      });

  atl_reg_wr_u32 (dev, ATL_REG_AQ2_FW_INTERFACE_IN_MTU,
		  port->max_rx_frame_size);
  log_debug (dev, "max rx frame seize set to %u", port->max_rx_frame_size);

  atl_reg_wr (dev, ATL_REG_AQ2_FW_INTERFACE_IN_REQUEST_POLICY,
	      (atl_reg_t){
		.aq2_fw_interface_in_request_policy = {
		  .mcast_accept = 1,
		  .bcast_accept = 1,
		},
	      });

  rv = atl_aq2_fw_wait_shared_ack (dev);

done:
  if (rv != VNET_DEV_OK)
    {
      foreach_vnet_dev_port_rx_queue (rxq, port)
	{
	  atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
	  u16 mask = rxq->size - 1;
	  u32 n_free = aq->tail - aq->head;
	  u16 start = aq->head & mask;

	  if (n_free)
	    vlib_buffer_free_from_ring_no_next (vm, aq->buffer_indices, start,
						rxq->size, n_free);

	  aq->head = aq->tail = 0;
	  aq->next_index = 0;
	  if (aq->tail_reg)
	    __atomic_store_n (aq->tail_reg, 0, __ATOMIC_RELAXED);

	  atl_reg_wr (dev, ATL_REG_RX_DMA_DESC_LEN (rxq->queue_id),
		      (atl_reg_t){
			.rx_dma_desc_len = {
			  .len = rxq->size / 8,
			},
		      });
	}
      foreach_vnet_dev_port_tx_queue (txq, port)
	{
	  atl_txq_t *aq = vnet_dev_get_tx_queue_data (txq);

	  atl_reg_wr (dev, ATL_REG_TX_DMA_DESC_LEN (txq->queue_id),
		      (atl_reg_t){
			.tx_dma_desc_len = {
			  .len = txq->size / 8,
			},
		      });

	  aq->tail_reg =
	    (u32 *) ((u8 *) ad->bar0 +
		     ATL_REG_TX_DMA_DESC_TAIL_PTR (txq->queue_id));
	  aq->head_index = 0;
	  aq->tail_index = 0;

	  if (aq->tail_reg)
	    __atomic_store_n (aq->tail_reg, 0, __ATOMIC_RELAXED);
	}
    }

  return rv;
}

void
atl_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  atl_device_t *ad = vnet_dev_get_data (dev);
  atl_reg_t r;

  atl_reg_wr (dev, ATL_REG_AQ2_FW_INTERFACE_IN_LINK_CONTROL,
	      (atl_reg_t){
		.aq2_fw_interface_in_link_control = {
		  .mode = 4, /* MODE_SHUTDOWN */
		},
	      });

  r = atl_reg_rd (dev, ATL_REG_AQ2_FW_INTERFACE_IN_LINK_OPTIONS);
  r.aq2_fw_interface_in_link_options.link_up = 0;
  atl_reg_wr (dev, ATL_REG_AQ2_FW_INTERFACE_IN_LINK_OPTIONS, r);

  atl_aq2_fw_wait_shared_ack (dev);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
      u16 mask = rxq->size - 1;
      u32 n_free = aq->tail - aq->head;
      u16 start = aq->head & mask;

      if (n_free)
	vlib_buffer_free_from_ring_no_next (vm, aq->buffer_indices, start,
					    rxq->size, n_free);

      aq->head = aq->tail = 0;
      aq->next_index = 0;
      if (aq->tail_reg)
	__atomic_store_n (aq->tail_reg, 0, __ATOMIC_RELAXED);

      atl_reg_wr (dev, ATL_REG_RX_DMA_DESC_LEN (rxq->queue_id),
		  (atl_reg_t){
		    .rx_dma_desc_len = {
		      .len = rxq->size / 8,
		    },
		  });
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      atl_txq_t *aq = vnet_dev_get_tx_queue_data (txq);

      atl_reg_wr (dev, ATL_REG_TX_DMA_DESC_LEN (txq->queue_id),
		  (atl_reg_t){
		    .tx_dma_desc_len = {
		      .len = txq->size / 8,
		    },
		  });

      aq->tail_reg = (u32 *) ((u8 *) ad->bar0 +
			      ATL_REG_TX_DMA_DESC_TAIL_PTR (txq->queue_id));
      aq->head_index = 0;
      aq->tail_index = 0;

      if (aq->tail_reg)
	__atomic_store_n (aq->tail_reg, 0, __ATOMIC_RELAXED);
    }

  vnet_dev_poll_port_remove (vm, port, atl_port_status_poll);
  vnet_dev_poll_port_remove (vm, port, atl_port_counter_poll);
}

u8 *
atl_port_format_status (u8 *s, va_list *args __clib_unused)
{
  return s;
}

vnet_dev_rv_t
atl_port_cfg_change_validate (
  vlib_main_t *vm __clib_unused, vnet_dev_port_t *port,
  vnet_dev_port_cfg_change_req_t *req __clib_unused)
{
  return VNET_DEV_OK;
}

vnet_dev_rv_t
atl_port_cfg_change (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port,
		     vnet_dev_port_cfg_change_req_t *req __clib_unused)
{
  return VNET_DEV_OK;
}
