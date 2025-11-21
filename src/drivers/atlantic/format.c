/* SPDX-License-Identifier: Apache-2.0 */
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <atlantic.h>

u8 *
format_atl_rx_desc (u8 *s, va_list *args)
{
  const atl_rx_desc_t *d = va_arg (*args, const atl_rx_desc_t *);
  u32 indent = format_get_indent (s) + 2;

#define _(b) ((b) ? '+' : '-')

  s = format (s, "buf 0x%016llx hdr 0x%016llx type 0x%08x rss 0x%08x", d->buf_addr, d->hdr_addr,
	      d->type, d->rss_hash);

  s = format (s,
	      "\n%Uflags rss_type 0x%x ether 0x%x proto 0x%x vlan1%c "
	      "vlan2%c l4csum%c",
	      format_white_space, indent, d->rss_type, d->ether_type, d->proto, _ (d->vlan1),
	      _ (d->vlan2), _ (d->l4_csum));

  s = format (s,
	      "\n%Ustatus dd%c eop%c macerr%c v4_sum_ng%c l4_sum_err%c "
	      "l4_sum_ok%c len %u vlan 0x%x next %u",
	      format_white_space, indent, _ (d->dd), _ (d->eop), _ (d->macerr), _ (d->v4_sum_ng),
	      _ (d->l4_sum_err), _ (d->l4_sum_ok), d->pkt_len, d->vlan, d->next_desc_ptr);

#undef _

  return s;
}

u8 *
atl_rx_trace (u8 *s, va_list *args)
{
  __clib_unused vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  __clib_unused vlib_node_t *node = va_arg (*args, vlib_node_t *);
  atl_rx_trace_t *t = va_arg (*args, atl_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface_api_visible_or_null (vnm, t->sw_if_index);

  s = format (s, "atl: %v (%u) qid %u buffer %u", hi ? hi->name : (u8 *) "(unknown)",
	      hi ? hi->hw_if_index : t->sw_if_index, t->queue_id, t->buffer_index);

  s = format (s, "\n%Udesc: %U", format_white_space, format_get_indent (s) + 2, format_atl_rx_desc,
	      &t->desc);
  return s;
}

u8 *
atl_tx_trace (u8 *s, va_list *args)
{
  __clib_unused vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  __clib_unused vlib_node_t *node = va_arg (*args, vlib_node_t *);
  atl_tx_trace_t *t = va_arg (*args, atl_tx_trace_t *);

  s = format (s, "sw_if_index %u queue %u buffer %u", t->sw_if_index, t->queue_id, t->buffer_index);
  s = format (s, "\n%U%U", format_white_space, format_get_indent (s) + 2, format_atl_tx_desc,
	      &t->desc);
  return s;
}

u8 *
format_atl_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  vnet_dev_t *dev = port->dev;
  atl_device_t *ad = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  atl_reg_aq2_fw_interface_out_link_status_t st;
  u32 indent, link_speed;
  static const u32 rate_lut[] = {
    0, 10000, 100000, 1000000, 2500000, 5000000, 10000000,
  };

  rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_LINK_STATUS, &st.as_u32, 1);
  if (rv != VNET_DEV_OK)
    return format (s, "link status read failed (rv %d)", rv);

  link_speed = (st.link_rate < ARRAY_LEN (rate_lut)) ? rate_lut[st.link_rate] : 0;

  if (a->debug > 0)
    indent = format_get_indent (s);

  s = format (s,
	      "link state %u link speed %u kbps duplex %s pause rx %u tx %u "
	      "eee %u",
	      st.link_state, link_speed, st.duplex ? "full" : "half", st.pause_rx, st.pause_tx,
	      st.eee);

  if (a->debug > 0)
    {
      u32 l2_idx = ad->l2_filters_base_index;
      u32 filter_caps[3];
      u32 base, n_entries, total_entries, l2uc_lsw;
      atl_reg_rpf_l2uc_msw_t l2uc_msw;
      atl_reg_rpf_l2bc_t l2bc;
      u8 base_index, count;
      vnet_dev_hw_addr_t l2uc_addr, l2uc_addr0;

      l2uc_lsw = atl_reg_rd_u32 (dev, ATL_REG_RPF_L2UC_LSW (l2_idx));
      l2uc_msw = atl_reg_rd (dev, ATL_REG_RPF_L2UC_MSW (l2_idx)).rpf_l2uc_msw;
      l2bc = atl_reg_rd (dev, ATL_REG_RPF_L2BC).rpf_l2bc;
      l2uc_addr.eth_mac[0] = l2uc_msw.macaddr_hi >> 8;
      l2uc_addr.eth_mac[1] = l2uc_msw.macaddr_hi;
      l2uc_addr.eth_mac[2] = l2uc_lsw >> 24;
      l2uc_addr.eth_mac[3] = l2uc_lsw >> 16;
      l2uc_addr.eth_mac[4] = l2uc_lsw >> 8;
      l2uc_addr.eth_mac[5] = l2uc_lsw;
      s = format_newline (s, indent);
      s = format (s, "L2UC[%u] en %u action %u tag %u mac %U", l2_idx, l2uc_msw.en, l2uc_msw.action,
		  l2uc_msw.tag, format_vnet_dev_hw_addr, &l2uc_addr);
      s = format_newline (s, indent);
      s = format (s, "L2BC en %u promisc %u action %u tag %u", l2bc.en, l2bc.promisc, l2bc.action,
		  atl_reg_rd (dev, ATL_REG_AQ2_RPF_L2BC_TAG).aq2_rpf_l2bc_tag.tag);

      if (l2_idx != 0)
	{
	  l2uc_lsw = atl_reg_rd_u32 (dev, ATL_REG_RPF_L2UC_LSW (0));
	  l2uc_msw = atl_reg_rd (dev, ATL_REG_RPF_L2UC_MSW (0)).rpf_l2uc_msw;
	  l2uc_addr0.eth_mac[0] = l2uc_msw.macaddr_hi >> 8;
	  l2uc_addr0.eth_mac[1] = l2uc_msw.macaddr_hi;
	  l2uc_addr0.eth_mac[2] = l2uc_lsw >> 24;
	  l2uc_addr0.eth_mac[3] = l2uc_lsw >> 16;
	  l2uc_addr0.eth_mac[4] = l2uc_lsw >> 8;
	  l2uc_addr0.eth_mac[5] = l2uc_lsw;
	  s = format_newline (s, indent);
	  s = format (s, "L2UC[0] en %u action %u tag %u mac %U", l2uc_msw.en, l2uc_msw.action,
		      l2uc_msw.tag, format_vnet_dev_hw_addr, &l2uc_addr0);
	}

      rv = atl_aq2_interface_buffer_read (dev, ATL_REG_AQ2_FW_INTERFACE_OUT_FILTER_CAPS,
					  filter_caps, ARRAY_LEN (filter_caps));

      if (rv != VNET_DEV_OK)
	{
	  s = format_newline (s, indent);
	  return format (s, "ART table: filter caps read failed (rv %d)", rv);
	}

      base_index = ((u8 *) filter_caps)[10];
      count = ((u8 *) filter_caps)[11];
      base = 8 * base_index;
      n_entries = 8 * count;
      total_entries = base + n_entries;

      s = format_newline (s, indent);
      s = format (s, "ART table (base %u count %u resolver_base %u)", base, n_entries,
		  ad->resolver_base);

      for (u32 idx = 0; idx < total_entries; idx++)
	{
	  u32 tag = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_TAG (idx));
	  u32 mask = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_MASK (idx));
	  u32 action_raw = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_ACTION (idx));
	  atl_reg_aq2_rpf_act_art_req_action_t act =
	    ((atl_reg_t){ .as_u32 = action_raw }).aq2_rpf_act_art_req_action;
	  if (tag == 0 && mask == 0 && action_raw == 0)
	    {
	      u32 run_start = idx;
	      u32 run_end = idx + 1;
	      for (; run_end < total_entries; run_end++)
		{
		  u32 next_tag = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_TAG (run_end));
		  u32 next_mask = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_MASK (run_end));
		  u32 next_action =
		    atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_ACT_ART_REQ_ACTION (run_end));
		  if (next_tag != 0 || next_mask != 0 || next_action != 0)
		    break;
		}

	      if (run_end - run_start > 1)
		{
		  s = format_newline (s, indent + 9);
		  s = format (s, "[ entries %u-%u skipped (all zero) ]", run_start, run_end - 1);
		  idx = run_end - 1;
		  continue;
		}
	    }
	  s = format_newline (s, indent + 2);
	  s = format (s, "%3u: tag 0x%08x mask 0x%08x index %u rss %u en %u action 0x%06x", idx,
		      tag, mask, act.index, act.rss, act.enable, act.action);
	}

      s = format_newline (s, indent);
      s = format (s, "RX queue map rpf_rx_tc_upt 0x%08x",
		  atl_reg_rd_u32 (dev, ATL_REG_RPF_RPB_RX_TC_UPT));
      s = format_newline (s, indent);
      s = format (
	s, "RX knobs rss_ctrl1 0x%08x rpf_l3_v6_v4 0x%08x rpf_new_ctrl 0x%08x rpb_rpf_rx 0x%08x",
	atl_reg_rd_u32 (dev, ATL_REG_RX_FLR_RSS_CONTROL1),
	atl_reg_rd_u32 (dev, ATL_REG_RPF_L3_V6_V4_SELECT),
	atl_reg_rd_u32 (dev, ATL_REG_AQ2_RPF_NEW_CTRL), atl_reg_rd_u32 (dev, ATL_REG_RPB_RPF_RX));
      foreach_vnet_dev_port_rx_queue (rxq, port)
	{
	  u32 qid = rxq->queue_id;
	  u32 base_lsw = atl_reg_rd_u32 (dev, ATL_REG_RX_DMA_DESC_BASE_ADDRLSW (qid));
	  u32 base_msw = atl_reg_rd_u32 (dev, ATL_REG_RX_DMA_DESC_BASE_ADDRMSW (qid));
	  u32 head = atl_reg_rd_u32 (dev, ATL_REG_RX_DMA_DESC_HEAD_PTR (qid));
	  u32 tail = atl_reg_rd_u32 (dev, ATL_REG_RX_DMA_DESC_TAIL_PTR (qid));
	  u32 stat = atl_reg_rd_u32 (dev, ATL_REG_RX_DMA_DESC_STAT (qid));
	  u32 tc_map = atl_reg_rd_u32 (dev, ATL_REG_AQ2_RX_Q_TC_MAP (qid));
	  atl_reg_rx_dma_desc_len_t desc_len =
	    atl_reg_rd (dev, ATL_REG_RX_DMA_DESC_LEN (qid)).rx_dma_desc_len;
	  atl_reg_rx_dma_desc_data_hdr_size_t hdr =
	    atl_reg_rd (dev, ATL_REG_RX_DMA_DESC_DATA_HDR_SIZE (qid)).rx_dma_desc_data_hdr_size;

	  s = format_newline (s, indent + 2);
	  s = format (s,
		      "RXQ[%u] size %u en %u len %u hdr_split %u vlan_strip %u "
		      "tc_map 0x%08x",
		      qid, rxq->size, desc_len.en, desc_len.len, desc_len.header_split,
		      desc_len.vlan_strip, tc_map);
	  s = format_newline (s, indent + 4);
	  s = format (s,
		      "base 0x%08x%08x head %u tail %u stat 0x%08x "
		      "data_sz %u hdr_sz %u",
		      base_msw, base_lsw, head, tail, stat, hdr.data_size, hdr.hdr_size);
	}
    }

  return s;
}

u8 *
format_atl_tx_desc (u8 *s, va_list *args)
{
  const atl_tx_desc_t *d = va_arg (*args, const atl_tx_desc_t *);
  u32 indent = format_get_indent (s) + 2;

#define _(b) ((b) ? '+' : '-')

  s = format (s, "addr 0x%016llx len %u ctx_en %u", d->addr, d->len, d->ctx_en);
  s = format (s,
	      "\n%Uflags type_txd%c type_txc%c dd%c eop%c vlan%c fcs%c "
	      "ip4csum%c l4csum%c wb%c blen %u",
	      format_white_space, indent, _ (d->type_txd), _ (d->type_txc), _ (d->dd), _ (d->eop),
	      _ (d->vlan), _ (d->fcs), _ (d->ip4csum), _ (d->l4csum), _ (d->wb), d->blen);

#undef _

  return s;
}
