/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <atlantic.h>

VLIB_REGISTER_LOG_CLASS (atl_log, static) = {
  .class_name = "atlantic",
  .subclass_name = "port",
};

#define ATL_RPF_RSS_KEY_ADDR_MASK 0x1f
#define ATL_RPF_RSS_KEY_WR_EN	  (1 << 5)

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

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_LINK_STATUS, &st.as_u32, 1);

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
      changes.link_speed = (st.link_rate < ARRAY_LEN (rate_lut)) ? rate_lut[st.link_rate] : 0;

      log_debug (dev, "link speed changed to %u kbps", changes.link_speed);
    }

  if (st.link_state != ap->last_link_status.link_state)
    {
      changes.change.link_state = 1;
      changes.link_state = st.link_state;

      log_debug (dev, "link state changed to %s", changes.link_state ? "up" : "down");
    }

  if (st.duplex != ap->last_link_status.duplex)
    {
      changes.change.link_duplex = 1;
      changes.full_duplex = st.duplex;

      log_debug (dev, "link duplex changed to %s", st.duplex ? "full" : "half");
    }

  ap->last_link_status = st;

  if (changes.change.any)
    vnet_dev_port_state_change (vm, port, changes);
}

static vnet_dev_rv_t
atl_aq2_fw_wait_shared_ack (vnet_dev_t *dev)
{
  vlib_main_t *vm = vlib_get_main ();
  f64 t0 = vlib_time_now (vm);

  atl_reg_wr_u32 (dev, ATL_REG_AQ2_MIF_HOST_FINISHED_STATUS_WRITE, 1);

  while (1)
    {
      if ((atl_reg_rd_u32 (dev, ATL_REG_AQ2_MIF_HOST_FINISHED_STATUS_READ) & 1) == 0)
	return VNET_DEV_OK;

      if (vlib_time_now (vm) - t0 > 1.0)
	return VNET_DEV_ERR_TIMEOUT;
    }
}

static vnet_dev_rv_t
aq2_filter_art_set (vnet_dev_t *dev, u32 idx, atl_aq2_art_tag_t tag, atl_aq2_art_tag_t mask,
		    atl_aq2_art_action_t action)
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

  idx += (8 * ad->caps.resolver_base_index);
  atl_reg_wr_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_TAG (idx), tag.as_u32);
  atl_reg_wr_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_MASK (idx), mask.as_u32);
  atl_reg_wr_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_ACTION (idx), action.as_u32);

  atl_reg_wr_u32 (dev, ATL_REG_AQ2_ART_SEM, 1);

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
atl_rss_validate (vnet_dev_port_t *port, const vnet_dev_rss_config_t *config)
{
  if ((config->set_key && config->key_len != ATL_RSS_KEY_SIZE) ||
      (config->set_lut && config->lut_len != ATL_RSS_LUT_SIZE))
    return VNET_DEV_ERR_INVALID_DATA;

  if (config->set_lut)
    for (u32 i = 0; i < ATL_RSS_LUT_SIZE; i++)
      {
	vnet_dev_rx_queue_t *rxq = vnet_dev_get_port_rx_queue_by_id (port, config->lut[i]);

	if (!rxq || !rxq->enabled)
	  return VNET_DEV_ERR_INVALID_VALUE;
      }

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
atl_rss_apply (vnet_dev_port_t *port, const vnet_dev_rss_config_t *config)
{
  vnet_dev_t *dev = port->dev;
  vlib_main_t *vm = vlib_get_main ();

  if (config->set_key)
    for (u32 i = 0; i < ATL_RSS_KEY_SIZE / 4; i++)
      {
	u32 w = ((u32) config->key[i * 4 + 0] << 24) | ((u32) config->key[i * 4 + 1] << 16) |
		((u32) config->key[i * 4 + 2] << 8) | ((u32) config->key[i * 4 + 3] << 0);
	f64 t0 = vlib_time_now (vm);

	atl_reg_wr_u32 (dev, ATL_REG_RPF_RSS_KEY_WR_DATA, w);
	atl_reg_wr_u32 (dev, ATL_REG_RPF_RSS_KEY_ADDR,
			((9 - i) & ATL_RPF_RSS_KEY_ADDR_MASK) | ATL_RPF_RSS_KEY_WR_EN);

	while (atl_reg_rd_u32 (dev, ATL_REG_RPF_RSS_KEY_ADDR) & ATL_RPF_RSS_KEY_WR_EN)
	  if (vlib_time_now (vm) - t0 > 10e-3)
	    return VNET_DEV_ERR_TIMEOUT;
      }

  if (config->set_lut)
    for (u32 i = 0; i < ATL_RSS_LUT_SIZE; i++)
      {
	u32 v = 0;

	for (u32 tc = 0; tc < 4; tc++)
	  v |= ((tc * 8 + config->lut[i]) & 0x1f) << (5 * tc);

	atl_reg_wr_u32 (dev, ATL_REG_AQ2_RPF_RSS_REDIR (i), v);
      }

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
atl_rss_init (vnet_dev_port_t *port)
{
  vnet_dev_rss_config_t config = port->rss_config;
  u16 queue_ids[ATL_RSS_LUT_SIZE];
  u32 n_queues = 0;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    if (rxq->enabled && n_queues < ARRAY_LEN (queue_ids))
      queue_ids[n_queues++] = rxq->queue_id;

  if (n_queues == 0)
    return VNET_DEV_OK;

  if (config.set_lut && atl_rss_validate (port, &config) != VNET_DEV_OK)
    config.set_lut = 0;

  if (!config.set_lut)
    {
      for (u32 i = 0; i < ATL_RSS_LUT_SIZE; i++)
	config.lut[i] = queue_ids[i % n_queues];

      config.set_lut = 1;
      config.lut_len = ATL_RSS_LUT_SIZE;
    }

  return atl_rss_apply (port, &config);
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

  atl_reg_wr (dev, ATL_REG_TDM_LSO_EN,
	      (atl_reg_t){
		.tdm_lso_en = {
		  .queue_mask = 0xffffffff,
		},
	      });
  atl_reg_wr (dev, ATL_REG_THM_LSO_TCP_FLAG1,
	      (atl_reg_t){
		.thm_lso_tcp_flag1 = {
		  .first = 0x0ff6,
		  .middle = 0x0ff6,
		},
	      });
  atl_reg_wr (dev, ATL_REG_THM_LSO_TCP_FLAG2,
	      (atl_reg_t){
		.thm_lso_tcp_flag2 = {
		  .last = 0x0f7f,
		},
	      });

  atl_reg_wr (dev, ATL_REG_TX_DMA_INT_DESC_WRWB_EN,
	      (atl_reg_t){
		.tx_dma_int_desc_wrwb_en = {
		  .wrwb_en = 1,
		  .moderate_en = 0,
		},
	      });

  /* Enable TX block */
  r = atl_reg_rd (dev, ATL_REG_TX_DMA_CTRL);
  r.tx_dma_ctrl.en = 1;
  atl_reg_wr (dev, ATL_REG_TX_DMA_CTRL, r);

  atl_reg_wr (dev, ATL_REG_TDM_DCA, (atl_reg_t){});

  r = atl_reg_rd (dev, ATL_REG_TPO_OFFLOAD_CTRL);
  r.tpo_offload_ctrl.tcp_udp_crc_en = 1;
  r.tpo_offload_ctrl.ipv4_hdr_crc_en = 1;
  atl_reg_wr (dev, ATL_REG_TPO_OFFLOAD_CTRL, r);

  log_debug (dev, "tx path init done");
}

static_always_inline u16
atl_mac_addr_high (const vnet_dev_hw_addr_t *hw_addr)
{
  return (hw_addr->eth_mac[0] << 8) | hw_addr->eth_mac[1];
}

static_always_inline u32
atl_mac_addr_low (const vnet_dev_hw_addr_t *hw_addr)
{
  return (hw_addr->eth_mac[2] << 24) | (hw_addr->eth_mac[3] << 16) | (hw_addr->eth_mac[4] << 8) |
	 (hw_addr->eth_mac[5]);
}

static vnet_dev_rv_t
atl_change_primary_hw_addr (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *hw_addr)
{
  vnet_dev_t *dev = port->dev;
  atl_device_t *ad = vnet_dev_get_data (dev);
  atl_reg_rpf_l2uc_msw_t l2uc_msw;
  u32 l2_idx = ad->caps.l2_base_index;

  /* disable L2 unicast filter before updating address */
  atl_reg_wr (dev, ATL_REG_RPF_L2UC_MSW (l2_idx),
	      (atl_reg_t){
		.rpf_l2uc_msw.en = 0,
	      });
  atl_reg_wr_u32 (dev, ATL_REG_RPF_L2UC_LSW (l2_idx), atl_mac_addr_low (hw_addr));

  /* set primary MAC address and enable L2 unicast filter */
  l2uc_msw = (atl_reg_rpf_l2uc_msw_t){
    .macaddr_hi = atl_mac_addr_high (hw_addr),
    .action = 1, /* RPF_ACTION_HOST */
    .tag = 1,
    .en = 1,
  };
  atl_reg_wr (dev, ATL_REG_RPF_L2UC_MSW (l2_idx),
	      (atl_reg_t){
		.rpf_l2uc_msw = l2uc_msw,
	      });
  log_debug (dev, "l2uc[%u] %U", l2_idx, format_atl_l2uc, &l2uc_msw, atl_mac_addr_low (hw_addr));

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
atl_rss_hash_set (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  atl_reg_wr (dev, ATL_REG_AQ2_RPF_REDIR2,
	      (atl_reg_t){
		.aq2_rpf_redir2 = {
                  .hashtype_ip = 1,
                  .hashtype_tcp4 = 1,
                  .hashtype_udp4 = 1,
                  .hashtype_ip6 = 1,
                  .hashtype_tcp6 = 1,
                  .hashtype_udp6 = 1,
                  .hashtype_ip6ex = 1,
                  .hashtype_tcp6ex = 1,
                  .hashtype_udp6ex = 1,
                },
	      });

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
atl_rx_path_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv;
  atl_reg_t r;
  atl_aq2_art_tag_t tag;
  atl_aq2_art_tag_t mask;
  atl_aq2_art_action_t action;
  int i;

  rv = atl_rss_hash_set (port);
  if (rv != VNET_DEV_OK)
    return rv;

  atl_reg_wr_u32 (dev, ATL_REG_RX_FLR_RSS_CONTROL1, ATL_RSS_ENABLED_4TCS_3INDEX_BITS);

  for (i = 0; i < 34; i++)
    {
      r = atl_reg_rd (dev, ATL_REG_RPF_L2UC_MSW (i));
      r.rpf_l2uc_msw.en = 0;
      r.rpf_l2uc_msw.action = 1; /* RPF_ACTION_HOST */
      atl_reg_wr (dev, ATL_REG_RPF_L2UC_MSW (i), r);
    }

  atl_reg_wr (dev, ATL_REG_RPF_MCAST_FILTER_MASK,
	      (atl_reg_t){
		.rpf_mcast_filter_mask = {
		  .mask = 0x00004000,
		},
	      });
  atl_reg_wr_u32 (dev, ATL_REG_RPF_MCAST_FILTER0, 0x00010fff);

  atl_reg_wr (dev, ATL_REG_RPF_VLAN_TPID,
	      (atl_reg_t){
		.rpf_vlan_tpid = {
		  .outer = 0x88a8,
		  .inner = 0x8100,
		},
	      });

  atl_reg_wr (dev, ATL_REG_RPF_VLAN_MODE,
	      (atl_reg_t){
		.rpf_vlan_mode = {
		  .accept_untagged = 1,
		  .untagged_action = 1, /* RPF_ACTION_HOST */
		},
	      });

  /* enable all receive classification table entries */
  r = atl_reg_rd (dev, ATL_REG_AQ2_RPF_REC_TAB_ENABLE);
  r.aq2_rpf_rec_tab_enable.mask = 0xffff;
  atl_reg_wr (dev, ATL_REG_AQ2_RPF_REC_TAB_ENABLE, r);

  rv = atl_change_primary_hw_addr (port, &port->primary_hw_addr);
  if (rv != VNET_DEV_OK)
    return rv;

  /* set tag for L2 broadcast */
  r = atl_reg_rd (dev, ATL_REG_AQ2_RPF_L2BC_TAG);
  r.aq2_rpf_l2bc_tag.tag = 1;
  atl_reg_wr (dev, ATL_REG_AQ2_RPF_L2BC_TAG, r);

  /* disable L2 promiscuous filtering in ART */
  tag = (atl_aq2_art_tag_t){};
  mask = (atl_aq2_art_tag_t) { .uc = 0x3f, .allmc = 1 };
  action = (atl_aq2_art_action_t){ .enable = 1, .action = ATL_AQ2_ART_ACTION_DISCARD };
  rv = aq2_filter_art_set (dev, AQ2_RPF_INDEX_L2_PROMISC_OFF, tag, mask, action);

  if (rv != VNET_DEV_OK)
    return rv;

  /* disable VLAN promiscuous filtering in ART */
  mask = (atl_aq2_art_tag_t){ .vlan = 0xf, .untag = 1 };
  rv =
    aq2_filter_art_set (dev, AQ2_RPF_INDEX_VLAN_PROMISC_OFF, tag, mask, (atl_aq2_art_action_t){});

  if (rv != VNET_DEV_OK)
    return rv;

  /* map PCP priorities to TC 0 */
  action = (atl_aq2_art_action_t){ .enable = 1, .action = ATL_AQ2_ART_ACTION_HOST_AND_MGMT };
  mask = (atl_aq2_art_tag_t){ .pcp = 0x7 };
  for (u32 i = 0; i < 8; i++)
    {
      tag.pcp = i;
      rv = aq2_filter_art_set (dev, AQ2_RPF_INDEX_PCP_TO_TC + i, tag, mask, action);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  /* enable L2 broadcast filtering */
  atl_reg_wr (dev, ATL_REG_RPF_L2BC, (atl_reg_t){
		.rpf_l2bc = {
		  .en = 1,
		  .action = 1,
		  .threshold = 0xffff,
		},
	      });

  r = atl_reg_rd (dev, ATL_REG_RX_DMA_DCA);
  r.rx_dma_dca.en = 0;
  r.rx_dma_dca.mode = 0;
  atl_reg_wr (dev, ATL_REG_RX_DMA_DCA, r);

  atl_reg_wr (dev, ATL_REG_RPF_L3_V6_V4_SELECT,
	      (atl_reg_t){
		.rpf_l3_v6_v4_select = {
		  .v6_v4_select = 1,
		},
	      });
  atl_reg_wr (dev, ATL_REG_RX_DMA_INT_DESC_WRWB_EN,
	      (atl_reg_t){
		.rx_dma_int_desc_wrwb_en = {
		  .wrwb_en = 1,
		  .moderate_en = 0,
		},
	      });

  log_debug (dev, "rx path init done");

  return rv;
}

static vnet_dev_rv_t
atl_add_secondary_hw_addr (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *hw_addr)
{
  vnet_dev_t *dev = port->dev;
  atl_device_t *ad = vnet_dev_get_data (dev);
  atl_reg_rpf_l2uc_msw_t l2uc_msw;
  u16 h = atl_mac_addr_high (hw_addr);
  u32 l = atl_mac_addr_low (hw_addr);
  u32 l2_count = ad->caps.l2_count;
  u32 l2_base_index = ad->caps.l2_base_index;
  u32 empty_slot = 0;
  u32 l2_idx, l2uc_lsw, i;

  if (l2_count == 0)
    l2_count = AQ_HW_MAC_NUM;

  for (i = 1; i < l2_count; i++)
    {
      l2_idx = l2_base_index + i;
      l2uc_msw = atl_reg_rd (dev, ATL_REG_RPF_L2UC_MSW (l2_idx)).rpf_l2uc_msw;
      if (l2uc_msw.en)
	{
	  l2uc_lsw = atl_reg_rd_u32 (dev, ATL_REG_RPF_L2UC_LSW (l2_idx));
	  if (l2uc_msw.macaddr_hi == h && l2uc_lsw == l)
	    return VNET_DEV_ERR_ALREADY_EXISTS;
	}
      else if (empty_slot == 0)
	empty_slot = l2_idx;
    }

  if (empty_slot == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;

  l2uc_msw = (atl_reg_rpf_l2uc_msw_t){
    .macaddr_hi = h,
    .action = 1, /* RPF_ACTION_HOST */
    .tag = 1,
    .en = 1,
  };
  atl_reg_wr (dev, ATL_REG_RPF_L2UC_MSW (empty_slot),
	      (atl_reg_t){
		.rpf_l2uc_msw.en = 0,
	      });
  atl_reg_wr_u32 (dev, ATL_REG_RPF_L2UC_LSW (empty_slot), l);
  atl_reg_wr (dev, ATL_REG_RPF_L2UC_MSW (empty_slot),
	      (atl_reg_t){
		.rpf_l2uc_msw = l2uc_msw,
	      });
  log_debug (dev, "l2uc[%u] %U", empty_slot, format_atl_l2uc, &l2uc_msw, l);

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
atl_remove_secondary_hw_addr (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *hw_addr)
{
  vnet_dev_t *dev = port->dev;
  atl_device_t *ad = vnet_dev_get_data (dev);
  atl_reg_rpf_l2uc_msw_t l2uc_msw;
  u16 h = atl_mac_addr_high (hw_addr);
  u32 l = atl_mac_addr_low (hw_addr);
  u32 l2_count = ad->caps.l2_count;
  u32 l2_base_index = ad->caps.l2_base_index;
  u32 l2_idx, l2uc_lsw, i;

  if (l2_count == 0)
    l2_count = AQ_HW_MAC_NUM;

  for (i = 1; i < l2_count; i++)
    {
      l2_idx = l2_base_index + i;
      l2uc_msw = atl_reg_rd (dev, ATL_REG_RPF_L2UC_MSW (l2_idx)).rpf_l2uc_msw;
      if (!l2uc_msw.en)
	continue;
      l2uc_lsw = atl_reg_rd_u32 (dev, ATL_REG_RPF_L2UC_LSW (l2_idx));
      if (l2uc_msw.macaddr_hi == h && l2uc_lsw == l)
	{
	  log_debug (dev, "l2uc[%u] %U", l2_idx, format_atl_l2uc, &l2uc_msw, l2uc_lsw);
	  atl_reg_wr (dev, ATL_REG_RPF_L2UC_MSW (l2_idx),
		      (atl_reg_t){
			.rpf_l2uc_msw.en = 0,
		      });
	  return VNET_DEV_OK;
	}
    }

  return VNET_DEV_ERR_NOT_FOUND;
}

static void
atl_buffers_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  u32 rx_buff_size = 192; /* AQ2_HW_RXBUF_MAX */
  u32 tx_buff_size = 128; /* AQ2_HW_TXBUF_MAX */

  /* configure TX buffer size for TC 0 */
  atl_reg_wr (dev, ATL_REG_TPB_TXB_BUFSIZE (0),
	      (atl_reg_t){
		.tpb_txb_bufsize = {
		  .bufsize = 128,
		},
	      });

  /* configure TX flow control thresholds for TC 0 */
  atl_reg_wr (dev, ATL_REG_TPB_TXB_THRESH (0),
	      (atl_reg_t){
		.tpb_txb_thresh = {
		  .hi = (tx_buff_size * (1024 / 32) * 66) / 100,
		  .lo = (tx_buff_size * (1024 / 32) * 50) / 100,
		},
	      });

  /* configure RX buffer size for TC 0 */
  atl_reg_wr (dev, ATL_REG_RPB_RXB_BUFSIZE (0),
	      (atl_reg_t){
		.rpb_rxb_bufsize = {
		  .bufsize = 320,
		},
	      });

  /* configure RX flow control thresholds for TC 0 */
  atl_reg_wr (dev, ATL_REG_RPB_RXB_XOFF (0),
	      (atl_reg_t){
		.rpb_rxb_xoff = {
		  .hi = (rx_buff_size * (1024 / 32) * 66) / 100,
		  .lo = (rx_buff_size * (1024 / 32) * 50) / 100,
		  .en = 0,
		},
	      });

  /* map all user priorities to TC 0 */
  atl_reg_wr_u32 (dev, ATL_REG_RPF_RPB_RX_TC_UPT, 0);

  /* Map all queues to TC 0 */
  foreach_vnet_dev_port_tx_queue (txq, port)
    atl_reg_wr_u32 (dev, ATL_REG_AQ2_TX_Q_TC_MAP (txq->queue_id), 0);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    atl_reg_wr_u32 (dev, ATL_REG_AQ2_RX_Q_TC_MAP (rxq->queue_id), 0);

  log_debug (dev, "buffers init done");
}

#define ATL_IRQ_MAP_VALID 0x80

static void
atl_rx_msix_handler (vlib_main_t *vm __clib_unused, vnet_dev_t *dev, u16 line)
{
  vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);

  if (!port || !port->interfaces || !port->rx_node_assigned)
    return;

  atl_reg_wr_u32 (dev, ATL_REG_INTR_MASK_SET, 1U << line);
  vlib_node_set_interrupt_pending (vlib_get_main_by_index (line - 1),
				   vnet_dev_get_port_rx_node_index (port));
}

static u16
atl_rxq_vector (atl_port_t *ap, vnet_dev_rx_queue_t *rxq)
{
  return clib_min (rxq->rx_thread_index + 1, ap->n_rx_vectors);
}

static void
atl_rx_irq_apply (vnet_dev_port_t *port, vnet_dev_rx_queue_t *target, int override)
{
  atl_port_t *ap = vnet_dev_get_port_data (port);
  u32 all = pow2_mask (ap->n_rx_vectors) << 1;
  u32 mask = 0;

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      int is_intr = q->interrupt_mode;

      if (override >= 0 && (target == 0 || target == q))
	is_intr = override;

      if (is_intr)
	mask |= 1U << atl_rxq_vector (ap, q);
    }

  atl_reg_wr_u32 (port->dev, ATL_REG_INTR_MASK_CLEAR, all & ~mask);
  atl_reg_wr_u32 (port->dev, ATL_REG_INTR_MASK_SET, mask);
}

static void
atl_rx_irq_map (vnet_dev_port_t *port)
{
  atl_port_t *ap = vnet_dev_get_port_data (port);
  u32 map[2] = {};

  foreach_vnet_dev_port_rx_queue (q, port)
    map[q->queue_id >> 1] |= (u32) (atl_rxq_vector (ap, q) | ATL_IRQ_MAP_VALID)
			     << (q->queue_id & 1 ? 0 : 8);

  for (u32 i = 0; i < ARRAY_LEN (map); i++)
    atl_reg_wr_u32 (port->dev, ATL_REG_INTR_MAP (i), map[i]);
}

static void
atl_interrupts_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  int i;

  atl_reg_wr (dev, ATL_REG_INTR_CTRL,
	      (atl_reg_t){
		.aq_intr_ctrl = {
		  .reset_dis = 1,
		  .irqmode = port->attr.caps.interrupt_mode ? 2 : 0,
		  .multivec = port->attr.caps.interrupt_mode,
		},
	      });

  atl_reg_wr_u32 (dev, ATL_REG_INTR_AUTOMASK, 0xffffffff);

  /* Map all interrupts to vector 0 (though disabled) */
  atl_reg_wr_u32 (dev, ATL_REG_AQ_GEN_INTR_MAP (0), 0);

  /* Initialize moderation timers (values in 2us units) */
  /* TX: min 20us (10), max 200us (100) */
  /* RX: min 6us (3), max 60us (30) */
  for (i = 0; i < 32; i++)
    {
      atl_reg_wr (dev, ATL_REG_AQ2_TX_INTR_MODERATION_CTL (i),
		  (atl_reg_t){
		    .intr_moderation_ctl = {
		      .min = 10,
		      .max = 100,
		      .en = 1,
		    },
		  });
      atl_reg_wr (dev, ATL_REG_RX_INTR_MODERATION_CTL (i),
		  (atl_reg_t){
		    .intr_moderation_ctl = {
		      .min = 3,
		      .max = 30,
		      .en = 1,
		    },
		  });
    }

  log_debug (dev, "interrupts init done");
}

vnet_dev_rv_t
atl_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv;
  atl_reg_t r = {};
#if 0
  u32 ver;
  u32 speed = 1;

  ver = atl_reg_rd_u32 (dev, ATL_REG_AQ2_HW_FPGA_VERSION);
  if (ver < 0x01000000)
    r.aq2_launchtime_ctrl.ratio = 1;
  else if (ver >= 0x01008502)
    r.aq2_launchtime_ctrl.ratio = 2;
  else
    r.aq2_launchtime_ctrl.ratio = 4;

  atl_reg_wr (dev, ATL_REG_AQ2_LAUNCHTIME_CTRL, r);
  log_debug (dev, "launchtime init done (speed %u, fpga ver %x)", speed, ver);
#endif

  atl_tx_path_init (port);

  rv = atl_rx_path_init (port);
  if (rv != VNET_DEV_OK)
    return rv;

  atl_buffers_init (port);

  /* enable new RPF control */
  r = atl_reg_rd (dev, ATL_REG_AQ2_RPF_NEW_CTRL);
  r.aq2_rpf_new_ctrl.enable = 1;
  atl_reg_wr (dev, ATL_REG_AQ2_RPF_NEW_CTRL, r);

  atl_interrupts_init (port);

  r = atl_reg_rd (dev, ATL_REG_TX_DMA_INT_DESC_WRWB_EN);
  r.tx_dma_int_desc_wrwb_en.wrwb_en = 0;
  atl_reg_wr (dev, ATL_REG_TX_DMA_INT_DESC_WRWB_EN, r);
  r.tx_dma_int_desc_wrwb_en.moderate_en = 0;
  atl_reg_wr (dev, ATL_REG_TX_DMA_INT_DESC_WRWB_EN, r);

  r = atl_reg_rd (dev, ATL_REG_RX_DMA_INT_DESC_WRWB_EN);
  r.rx_dma_int_desc_wrwb_en.wrwb_en = port->attr.caps.interrupt_mode;
  atl_reg_wr (dev, ATL_REG_RX_DMA_INT_DESC_WRWB_EN, r);
  r.rx_dma_int_desc_wrwb_en.moderate_en = 0;
  atl_reg_wr (dev, ATL_REG_RX_DMA_INT_DESC_WRWB_EN, r);

  atl_port_counters_init (vlib_get_main (), port);

  if (port->attr.caps.interrupt_mode)
    {
      atl_port_t *ap = vnet_dev_get_port_data (port);

      ap->n_rx_vectors = vlib_get_n_threads ();

      rv = vnet_dev_pci_msix_add_handler (vm, dev, &atl_rx_msix_handler, 1, ap->n_rx_vectors);
      if (rv != VNET_DEV_OK)
	return rv;

      ap->irq_registered = 1;

      rv = vnet_dev_pci_msix_enable (vm, dev, 1, ap->n_rx_vectors);
      if (rv != VNET_DEV_OK)
	return rv;

      for (u16 i = 0; i < ap->n_rx_vectors; i++)
	vnet_dev_pci_msix_set_polling_thread (vm, dev, i + 1, i);
    }

  return VNET_DEV_OK;
}

void
atl_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  atl_port_t *ap = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  if (!ap->irq_registered)
    return;

  /* coverity[tainted_data] - n_rx_vectors is set at port init */
  rv = vnet_dev_pci_msix_disable (vm, port->dev, 1, ap->n_rx_vectors);
  if (rv == VNET_DEV_OK)
    rv = vnet_dev_pci_msix_remove_handler (vm, port->dev, 1, ap->n_rx_vectors);

  if (rv != VNET_DEV_OK)
    log_err (port->dev, "port %u RX interrupt cleanup failed: %U", port->port_id,
	     format_vnet_dev_rv, rv);
  else
    ap->irq_registered = 0;
}

static vnet_dev_rv_t
atl_set_promisc (vnet_dev_port_t *port, int enabled)
{
  vnet_dev_t *dev = port->dev;
  atl_reg_t r;
  atl_aq2_art_tag_t tag = {};
  atl_aq2_art_tag_t mask = {};
  atl_aq2_art_action_t action = {};
  vnet_dev_rv_t rv;

  r = atl_reg_rd (dev, ATL_REG_AQ2_FW_INTERFACE_IN_REQUEST_POLICY);
  r.aq2_fw_interface_in_request_policy.promisc_all = enabled;
  r.aq2_fw_interface_in_request_policy.promisc_mcast = enabled;
  atl_reg_wr (dev, ATL_REG_AQ2_FW_INTERFACE_IN_REQUEST_POLICY, r);

  r = atl_reg_rd (dev, ATL_REG_RPF_L2BC);
  r.rpf_l2bc.promisc = enabled;
  atl_reg_wr (dev, ATL_REG_RPF_L2BC, r);

  action = enabled ? action : (atl_aq2_art_action_t){ .enable = 1 };

  mask = (atl_aq2_art_tag_t) { .uc = 0x3f, .allmc = 1 };
  rv = aq2_filter_art_set (dev, AQ2_RPF_INDEX_L2_PROMISC_OFF, tag, mask, action);
  if (rv != VNET_DEV_OK)
    return rv;

  mask = (atl_aq2_art_tag_t){ .vlan = 0xf, .untag = 1 };
  action = (atl_aq2_art_action_t){};
  rv = aq2_filter_art_set (dev, AQ2_RPF_INDEX_VLAN_PROMISC_OFF, tag, mask, action);
  return rv;
}

static void
atl_port_apply_link_options (vnet_dev_port_t *port)
{
  atl_port_t *ap = vnet_dev_get_port_data (port);
  u8 rate = ap->forced_rate ? ap->forced_rate : 0xff;
  u8 rate_hd = ap->forced_rate ? 0 : 0x7;

  atl_reg_wr (port->dev, ATL_REG_AQ2_FW_INTERFACE_IN_LINK_OPTIONS,
	      (atl_reg_t){
		.aq2_fw_interface_in_link_options = {
		  .link_up = 1,
		  .link_renegotiate = 1,
		  .rate = rate,
		  .rate_hd = rate_hd,
		  .pause_rx = 1,
		  .pause_tx = 1,
		  .downshift = 1,
		},
	      });
}

vnet_dev_rv_t
atl_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  atl_device_t *ad = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  f64 t0;
  atl_reg_rpb_rpf_rx_t rpb_rx;
  u32 v;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    if (rxq->enabled)
      {
	atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
	u16 mask = rxq->size - 1;
	u64 dma_addr = vnet_dev_get_dma_addr (vm, dev, aq->descs);
	u32 data_size = vnet_dev_get_rx_queue_buffer_data_size (vm, rxq);
	u32 buf_sz, desc_len, n_alloc, qid = rxq->queue_id;
	u16 hw_head;
	u8 bpi;

	mask = rxq->size - 1;

	clib_memset_u8 (aq->descs, 0, sizeof (aq->descs[0]) * rxq->size);

	buf_sz = atl_rx_buf_units (data_size);
	if (buf_sz == 0)
	  {
	    log_err (dev, "rx buffer data size %u is too small (min 1024)", data_size);
	    return VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
	  }

	desc_len = rxq->size / 8;

	atl_reg_wr_u32 (dev, ATL_REG_RX_DMA_DESC_BASE_ADDRLSW (qid), dma_addr);
	atl_reg_wr_u32 (dev, ATL_REG_RX_DMA_DESC_BASE_ADDRMSW (qid), dma_addr >> 32);
	aq->tail_reg = (u32 *) ((u8 *) ad->bar0 + ATL_REG_RX_DMA_DESC_TAIL_PTR (qid));

	atl_reg_wr (dev, ATL_REG_RX_DMA_DESC_DATA_HDR_SIZE (qid),
		    (atl_reg_t){
		      .rx_dma_desc_data_hdr_size = {
			.data_size = buf_sz,
		      },
		    });

	/* Disable ring initially */
	atl_reg_wr (dev, ATL_REG_RX_DMA_DESC_LEN (qid),
		    (atl_reg_t){
		      .rx_dma_desc_len = {
			.len = desc_len,
			.en = 0,
		      },
		    });

	hw_head = atl_reg_rd_u32 (dev, ATL_REG_RX_DMA_DESC_HEAD_PTR (qid)) & mask;

	bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
	n_alloc = ((hw_head + rxq->size - ATL_RX_REFILL_BATCH_SZ) & ~(ATL_RX_REFILL_BATCH_SZ - 1)) -
		  hw_head;
	if (!vlib_buffer_strict_alloc_to_ring_from_pool (vm, aq->buffer_indices, hw_head, rxq->size,
							 n_alloc, bpi))
	  {
	    rv = VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
	    goto done;
	  }

	for (u16 i = 0; i < n_alloc; i++)
	  {
	    u16 slot = (hw_head + i) & mask;
	    vlib_buffer_t *b = vlib_get_buffer (vm, aq->buffer_indices[slot]);

	    aq->descs[slot] = (atl_rx_desc_t) {
	      .buf_addr = vnet_dev_get_dma_addr (vm, dev, b->data),
	    };
	  }

	aq->head = hw_head;
	aq->tail = hw_head + n_alloc;
	atl_reg_wr_u32 (dev, ATL_REG_RX_DMA_DESC_TAIL_PTR (qid), aq->tail & mask);
	aq->next_index = 0;
      }

  rv = atl_rss_init (port);
  if (rv != VNET_DEV_OK)
    goto done;

  /* Invalidate Descriptor Cache */
  v = atl_reg_rd_u32 (dev, ATL_REG_RX_DMA_DESC_CACHE_INIT);
  atl_reg_wr_u32 (dev, ATL_REG_RX_DMA_DESC_CACHE_INIT, v & ~1U);
  atl_reg_wr_u32 (dev, ATL_REG_RX_DMA_DESC_CACHE_INIT, v | 1);
  t0 = vlib_time_now (vm);
  while (atl_reg_rd_u32 (dev, ATL_REG_RDM_RX_DMA_DESC_CACHE_INIT_DONE) == 0)
    if (vlib_time_now (vm) - t0 > 10e-3)
      {
	log_err (dev, "rx desc cache init timeout");
	rv = VNET_DEV_ERR_TIMEOUT;
	goto done;
      }

  /* Enable RX rings */
  foreach_vnet_dev_port_rx_queue (rxq, port)
    if (rxq->enabled)
      {
	atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
	u32 qid = rxq->queue_id;
	u32 desc_len = rxq->size / 8;
	u16 mask = rxq->size - 1;

	atl_reg_wr (dev, ATL_REG_RX_DMA_DESC_LEN (qid),
		    (atl_reg_t){
		      .rx_dma_desc_len = {
			.len = desc_len,
			.en = 1,
		      },
		    });

	CLIB_MEMORY_BARRIER ();
	atl_reg_wr_u32 (dev, ATL_REG_RX_DMA_DESC_TAIL_PTR (qid), aq->tail & mask);
      }

  rpb_rx = atl_reg_rd (dev, ATL_REG_RPB_RPF_RX).rpb_rpf_rx;
  rpb_rx.buf_en = 1;
  rpb_rx.tc_mode = 1;
  rpb_rx.fc_mode = 1;
  atl_reg_wr (dev, ATL_REG_RPB_RPF_RX,
	      (atl_reg_t){
		.rpb_rpf_rx = rpb_rx,
	      });

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      atl_txq_t *aq = vnet_dev_get_tx_queue_data (txq);
      u64 dma_addr;
      u32 qid = txq->queue_id;
      u32 desc_len = txq->size / 8;

      dma_addr = vnet_dev_get_dma_addr (vm, dev, aq->descs);

      atl_reg_wr_u32 (dev, ATL_REG_TX_DMA_DESC_BASE_ADDRLSW (qid), dma_addr);
      atl_reg_wr_u32 (dev, ATL_REG_TX_DMA_DESC_BASE_ADDRMSW (qid), dma_addr >> 32);

      aq->tail_reg = (u32 *) ((u8 *) ad->bar0 + ATL_REG_TX_DMA_DESC_TAIL_PTR (qid));

      aq->head_index = atl_reg_rd_u32 (dev, ATL_REG_TX_DMA_DESC_HEAD_PTR (qid)) & (txq->size - 1);
      aq->tail_index = aq->head_index;

      __atomic_store_n (aq->tail_reg, aq->tail_index, __ATOMIC_RELEASE);

      atl_reg_wr (dev, ATL_REG_TX_DMA_DESC_LEN (qid),
		  (atl_reg_t){
		    .tx_dma_desc_len = {
		      .len = desc_len,
		      .en = 1,
		    },
		  });
    }

  atl_reg_t lc = atl_reg_rd (dev, ATL_REG_AQ2_FW_INTERFACE_IN_LINK_CONTROL);
  lc.aq2_fw_interface_in_link_control.mode = 1; /* MODE_ACTIVE */
  atl_reg_wr (dev, ATL_REG_AQ2_FW_INTERFACE_IN_LINK_CONTROL, lc);
  atl_aq2_fw_wait_shared_ack (dev);

  atl_port_apply_link_options (port);

  atl_reg_wr_u32 (dev, ATL_REG_AQ2_FW_INTERFACE_IN_MTU, port->max_rx_frame_size);
  log_debug (dev, "max rx frame size set to %u", port->max_rx_frame_size);

  atl_reg_t rp = atl_reg_rd (dev, ATL_REG_AQ2_FW_INTERFACE_IN_REQUEST_POLICY);
  rp.aq2_fw_interface_in_request_policy.bcast_accept = 1;
  rp.aq2_fw_interface_in_request_policy.bcast_queue_or_tc = 1;
  rp.aq2_fw_interface_in_request_policy.bcast_rx_queue_tc_index = 0;
  rp.aq2_fw_interface_in_request_policy.mcast_accept = 1;
  rp.aq2_fw_interface_in_request_policy.mcast_queue_or_tc = 1;
  rp.aq2_fw_interface_in_request_policy.mcast_rx_queue_tc_index = 0;
  rp.aq2_fw_interface_in_request_policy.promisc_queue_or_tc = 1;
  rp.aq2_fw_interface_in_request_policy.promisc_rx_queue_tc_index = 0;
  atl_reg_wr (dev, ATL_REG_AQ2_FW_INTERFACE_IN_REQUEST_POLICY, rp);

  if (port->promisc)
    {
      rv = atl_set_promisc (port, 1);
      if (rv != VNET_DEV_OK)
	goto done;
    }

  rv = atl_aq2_fw_wait_shared_ack (dev);

  if (rv == VNET_DEV_OK)
    {
      atl_port_t *ap = vnet_dev_get_port_data (port);
      ap->last_link_status.as_u32 = 0;
      vnet_dev_poll_port_add (vm, port, 1, atl_port_counter_poll);
      vnet_dev_poll_port_add (vm, port, 1, atl_port_status_poll);

      if (port->attr.caps.interrupt_mode)
	{
	  atl_rx_irq_map (port);
	  atl_rx_irq_apply (port, 0, -1);
	}
    }

done:
  if (rv != VNET_DEV_OK)
    {
      foreach_vnet_dev_port_rx_queue (rxq, port)
	{
	  atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
	  u16 mask = rxq->size - 1;
	  u32 n_free = (u16) (aq->tail - aq->head);
	  u16 start = aq->head & mask;

	  if (n_free)
	    vlib_buffer_free_from_ring_no_next (vm, aq->buffer_indices, start, rxq->size, n_free);

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

	  aq->tail_reg = (u32 *) ((u8 *) ad->bar0 + ATL_REG_TX_DMA_DESC_TAIL_PTR (txq->queue_id));
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
  atl_port_t *ap = vnet_dev_get_port_data (port);

  if (port->attr.caps.interrupt_mode)
    atl_reg_wr_u32 (dev, ATL_REG_INTR_MASK_CLEAR, pow2_mask (ap->n_rx_vectors) << 1);

  r = atl_reg_rd (dev, ATL_REG_AQ2_FW_INTERFACE_IN_LINK_OPTIONS);
  r.aq2_fw_interface_in_link_options.link_up = 0;
  atl_reg_wr (dev, ATL_REG_AQ2_FW_INTERFACE_IN_LINK_OPTIONS, r);

  atl_aq2_fw_wait_shared_ack (dev);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
      u16 mask = rxq->size - 1;
      u32 n_free = (u16) (aq->tail - aq->head);
      u16 start = aq->head & mask;

      if (n_free)
	vlib_buffer_free_from_ring_no_next (vm, aq->buffer_indices, start, rxq->size, n_free);

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

      aq->tail_reg = (u32 *) ((u8 *) ad->bar0 + ATL_REG_TX_DMA_DESC_TAIL_PTR (txq->queue_id));
      aq->head_index = 0;
      aq->tail_index = 0;

      if (aq->tail_reg)
	__atomic_store_n (aq->tail_reg, 0, __ATOMIC_RELAXED);
    }

  vnet_dev_poll_port_remove (vm, port, atl_port_status_poll);
  vnet_dev_poll_port_remove (vm, port, atl_port_counter_poll);
}

static vnet_dev_rv_t
atl_rate_for_speed (u32 speed_kbps, u8 *rate)
{
  switch (speed_kbps)
    {
    case 0:
      *rate = 0;
      return VNET_DEV_OK;
    case 10000:
      *rate = 1 << 0;
      return VNET_DEV_OK;
    case 100000:
      *rate = 1 << 1;
      return VNET_DEV_OK;
    case 1000000:
      *rate = 1 << 2;
      return VNET_DEV_OK;
    case 2500000:
      *rate = 3 << 3;
      return VNET_DEV_OK;
    case 5000000:
      *rate = 3 << 5;
      return VNET_DEV_OK;
    case 10000000:
      *rate = 1 << 7;
      return VNET_DEV_OK;
    }
  return VNET_DEV_ERR_NOT_SUPPORTED;
}

vnet_dev_rv_t
atl_get_speed_caps (vnet_dev_t *dev, u32 *speed_caps)
{
  atl_reg_aq2_fw_interface_out_device_link_caps_t caps;
  vnet_dev_rv_t rv;

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_DEVICE_LINK_CAPS,
				      &caps.as_u32, 1);
  if (rv != VNET_DEV_OK)
    return rv;

  *speed_caps = 0;
  if (caps.rate_10m)
    *speed_caps |= VNET_HW_IF_SPEED_10M;
  if (caps.rate_100m)
    *speed_caps |= VNET_HW_IF_SPEED_100M;
  if (caps.rate_1g)
    *speed_caps |= VNET_HW_IF_SPEED_1G;
  if (caps.rate_2p5g)
    *speed_caps |= VNET_HW_IF_SPEED_2_5G;
  if (caps.rate_5g)
    *speed_caps |= VNET_HW_IF_SPEED_5G;
  if (caps.rate_10g)
    *speed_caps |= VNET_HW_IF_SPEED_10G;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
atl_port_cfg_change_validate (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port,
			      vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_ERR_NOT_SUPPORTED;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      rv = port->started ? VNET_DEV_ERR_PORT_STARTED : VNET_DEV_OK;
      break;

    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      if (port->attr.caps.interrupt_mode)
	rv = VNET_DEV_OK;
      break;

    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      rv = atl_rss_validate (port, &req->rss_config);
      break;

    case VNET_DEV_PORT_CFG_SET_LINK_SPEED:
      {
	u8 rate;
	rv = atl_rate_for_speed (req->link_speed, &rate);
	if (rv == VNET_DEV_OK && req->link_speed &&
	    (port->attr.speed_caps & vnet_hw_if_speed_from_kbps (req->link_speed)) == 0)
	  rv = VNET_DEV_ERR_NOT_SUPPORTED;
      }
      break;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      rv = VNET_DEV_OK;
      break;

    default:
      break;
    }

  return rv;
}

vnet_dev_rv_t
atl_port_cfg_change (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port,
		     vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      break;
    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      if (port->started)
	rv = atl_rss_apply (port, &req->rss_config);
      break;
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      if (port->started)
	{
	  vnet_dev_rx_queue_t *rxq = 0;

	  if (!req->all_queues)
	    rxq = vnet_dev_get_port_rx_queue_by_id (port, req->queue_id);

	  atl_rx_irq_apply (port, rxq, req->type == VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE);
	}
      break;
    case VNET_DEV_PORT_CFG_SET_LINK_SPEED:
      {
	atl_port_t *ap = vnet_dev_get_port_data (port);
	rv = atl_rate_for_speed (req->link_speed, &ap->forced_rate);
	if (rv != VNET_DEV_OK)
	  return rv;
	if (port->started)
	  {
	    atl_port_apply_link_options (port);
	    rv = atl_aq2_fw_wait_shared_ack (dev);
	  }
      }
      break;
    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      if (port->started)
	{
	  rv = atl_set_promisc (port, req->promisc);
	  if (rv != VNET_DEV_OK)
	    return rv;

	  rv = atl_aq2_fw_wait_shared_ack (dev);
	}
      break;
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      rv = atl_change_primary_hw_addr (port, &req->addr);
      break;
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      rv = atl_add_secondary_hw_addr (port, &req->addr);
      break;
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      rv = atl_remove_secondary_hw_addr (port, &req->addr);
      break;

    default:
      break;
    }

  return rv;
}
