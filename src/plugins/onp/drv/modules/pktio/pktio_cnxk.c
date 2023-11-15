/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/pktio/pktio_priv.h>
#include <onp/drv/modules/pktio/pktio_rx.h>
#include <onp/drv/modules/pci/pci.h>

#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vnet/vnet.h>
#include <vlib/log.h>

#define CNXK_PKTIO_INIT_MAGIC_NUM 0xafaf

STATIC_ASSERT (CNXK_FRAME_SIZE <= VLIB_FRAME_SIZE,
	       "CNXK_FRAME_SIZE greater than VLIB_FRAME_SIZE");

cnxk_pktio_main_t cnxk_pktio_main;

const u8 cnxk_pktio_default_rss_key[CNXK_PKTIO_RSS_KEY_LEN] = {
  0xFE, 0xED, 0x0B, 0xAD, 0xFE, 0xED, 0x0B, 0xAD, 0xAD, 0x0B, 0xED, 0xFE,
  0xAD, 0x0B, 0xED, 0xFE, 0x13, 0x57, 0x9B, 0xEF, 0x24, 0x68, 0xAC, 0x0E,
  0x91, 0x72, 0x53, 0x11, 0x82, 0x64, 0x20, 0x44, 0x12, 0xEF, 0x34, 0xCD,
  0x56, 0xBC, 0x78, 0x9A, 0x9A, 0x78, 0xBC, 0x56, 0xCD, 0x34, 0xEF, 0x12
};

u8 *
cnxk_pktio_format_rx_trace (u8 *s, va_list *va)
{
  union nix_rx_parse_u *hdr = va_arg (*va, union nix_rx_parse_u *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vnet_main_t * vnm) = va_arg (*va, vnet_main_t *);
  u32 indent = format_get_indent (s);

  if (hdr)
    {
      s = format (s,
		  "HW_META: chan 0x%x, desc_sizem1 %lu, imm_copy %u, "
		  "express %u, wqwd %u, errlev 0x%x, errcode 0x%x\n",
		  hdr->chan, hdr->desc_sizem1, hdr->imm_copy, hdr->express,
		  hdr->wqwd, hdr->errlev, hdr->errcode);

      s = format (s,
		  "%Ula (%u, %u, 0x%x), lb (%u, %u, 0x%x), lc (%u, "
		  "%u, 0x%x), ld (%u, %u, 0x%x)\n",
		  format_white_space, indent + 2, hdr->latype, hdr->laptr,
		  hdr->laflags, hdr->lbtype, hdr->lbptr, hdr->lbflags,
		  hdr->lctype, hdr->lcptr, hdr->lcflags, hdr->ldtype,
		  hdr->ldptr, hdr->ldflags);

      s = format (s,
		  "%Ule (%u, %u, 0x%x), lf (%u, %u, 0x%x), lg (%u, "
		  "%u, 0x%x), lh (%u, %u, 0x%x)\n",
		  format_white_space, indent + 2, hdr->letype, hdr->leptr,
		  hdr->leflags, hdr->lftype, hdr->lfptr, hdr->lfflags,
		  hdr->lgtype, hdr->lgptr, hdr->lgflags, hdr->lhtype,
		  hdr->lhptr, hdr->lhflags);

      s = format (s,
		  "%Upkt_lenm1 %lu, pkind %lu, l2m %u, l2b %u, l3m %u, "
		  "l3b %u\n",
		  format_white_space, indent + 2, hdr->pkt_lenm1, hdr->pkind,
		  hdr->l2m, hdr->l2b, hdr->l3m, hdr->l3b);

      s = format (s,
		  "%Uvlan0 (valid %u, gone %u, ptr %u, tci 0x%x), "
		  "vlan1 (valid %u, gone %u, ptr %u, tci 0x%x)\n",
		  format_white_space, indent + 2, hdr->vtag0_valid,
		  hdr->vtag0_gone, hdr->vtag0_ptr, hdr->vtag0_tci,
		  hdr->vtag1_valid, hdr->vtag1_gone, hdr->vtag1_ptr,
		  hdr->vtag1_tci);
      s = format (s,
		  "%Ueoh_ptr %u, wqe_aura 0x%x, pb_aura 0x%x, "
		  "match_id 0x%x, flow_key_alg %u",
		  format_white_space, indent + 2, hdr->eoh_ptr, hdr->wqe_aura,
		  hdr->pb_aura, hdr->match_id, hdr->flow_key_alg);
    }
  return s;
}

static cnxk_pktio_t *
cnxk_pktio_alloc (void)
{
  cnxk_pktio_main_t *em = cnxk_pktio_get_main ();
  cnxk_pktio_ops_map_t *pktio_ops;
  cnxk_pktio_t *pktio;
  u32 id;

  if (vec_len (em->pktio_ops))
    {
      for (id = 0; id < em->n_pktios; id++)
	{
	  pktio_ops = cnxk_pktio_get_pktio_ops (id);
	  pktio = &pktio_ops->pktio;
	  if (!pktio->is_used)
	    break;
	}
    }
  else
    {
      vec_validate_aligned (em->pktio_ops, CNXK_PKTIO_MAX_DEVICES,
			    CLIB_CACHE_LINE_BYTES);
      id = 0;
    }
  em->n_pktios++;

  ASSERT (em->n_pktios < CNXK_PKTIO_MAX_DEVICES);

  pktio_ops = cnxk_pktio_get_pktio_ops (id);
  pktio = &pktio_ops->pktio;

  pktio->is_used = 1;
  pktio->pktio_index = id;

  return pktio;
}

i32
cnxk_pktio_dev_mode_update (cnxk_pktio_t *pktio)
{
  u32 pci_dev_id;

  pci_dev_id = pktio->nix.pci_dev->id.device_id;
  switch (pci_dev_id)
    {
    case PCI_DEVID_CNXK_RVU_VF:
    case PCI_DEVID_CNXK_RVU_PF:
      pktio->pktio_link_type = CNXK_PKTIO_LINK_CGX;
      break;
    case PCI_DEVID_CNXK_RVU_AF_VF:
      pktio->pktio_link_type = CNXK_PKTIO_LINK_LBK;
      break;
    case PCI_DEVID_CNXK_RVU_SDP_VF:
      pktio->pktio_link_type = CNXK_PKTIO_LINK_PCI;
      break;
    default:
      cnxk_pktio_err ("Invalid pktio device id(%x) ", pci_dev_id);
      return -1;
    }

  return 0;
}

static i32
cnxk_pktio_nix_dev_init (cnxk_pktio_t *pktio, cnxk_plt_pci_device_t *dev)
{
  cnxk_pktio_ops_map_t *pktio_ops;
  int rv;

  pktio->nix.pci_dev = dev;
  pktio->nix.reta_sz = ROC_NIX_RSS_RETA_SZ_256;
  pktio->nix.max_sqb_count = CNXK_NIX_MAX_SQB;
  rv = roc_nix_dev_init (&pktio->nix);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_dev_init failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  pktio->npc.roc_nix = &pktio->nix;
  pktio->npc.flow_prealloc_size = CNXK_DEFAULT_MCAM_ENTRIES;
  pktio->npc.flow_max_priority = CNXK_NPC_MAX_FLOW_PRIORITY;

  rv = roc_npc_init (&pktio->npc);
  if (rv)
    {
      cnxk_pktio_err ("roc_npc_init failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  cnxk_pktio_dev_mode_update (pktio);

  pktio_ops = cnxk_pktio_get_pktio_ops (pktio->pktio_index);

  if (roc_model_is_cn10k ())
    clib_memcpy (&pktio_ops->fops, &eth_10k_ops, sizeof (cnxk_pktio_ops_t));
  else
    ASSERT (0);

  return pktio->pktio_index;
}

i32
cnxk_pktio_init (vlib_main_t *vm, vlib_pci_addr_t *addr,
		 vlib_pci_dev_handle_t *pci_handle)
{
  cnxk_plt_pci_device_t *dev;
  cnxk_pktio_t *pktio;

  dev = cnxk_pci_dev_probe (vm, addr, pci_handle);
  if (!dev)
    {
      cnxk_pktio_err ("Failed to probe PCI device %U", format_vlib_pci_addr,
		      addr);
      return -1;
    }

  switch (dev->id.device_id)
    {
    case PCI_DEVID_CNXK_RVU_PF:
    case PCI_DEVID_CNXK_RVU_VF:
    case PCI_DEVID_CNXK_RVU_AF_VF:
    case PCI_DEVID_CNXK_RVU_SDP_PF:
    case PCI_DEVID_CNXK_RVU_SDP_VF:
      pktio = cnxk_pktio_alloc ();
      return cnxk_pktio_nix_dev_init (pktio, dev);

    default:
      cnxk_pktio_err ("Invalid pktio device %U", format_vlib_pci_addr, addr);
    }

  return -1;
}

i32
cnxk_pktio_exit (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  return 0;
}

i32
cnxk_pktio_start (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  struct roc_nix *nix = &dev->nix;
  int rv;
  u32 i;

  if (dev->is_started)
    return -1;

  for (i = 0; i < pool_elts (dev->rqs); i++)
    {
      rv = roc_nix_rq_ena_dis (&dev->rqs[i], 1);
      if (rv)
	{
	  cnxk_pktio_err ("roc_nix_rq_ena_dis failed with '%s' error",
			  roc_error_msg_get (rv));
	  return -1;
	}
    }
  for (i = 0; i < pool_elts (dev->sqs); i++)
    {
      rv = roc_nix_tm_sq_aura_fc (&dev->sqs[i], 1);
      if (rv)
	{
	  cnxk_pktio_err ("roc_nix_tm_sq_aura_fc failed with '%s' error",
			  roc_error_msg_get (rv));
	  return -1;
	}
    }
  rv = roc_nix_npc_rx_ena_dis (nix, 1);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_npc_rx_ena_dis failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  dev->is_started = 1;

  return 0;
}

i32
cnxk_pktio_stop (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  struct roc_nix *nix = &dev->nix;
  int rv;
  u32 i;

  if (!dev->is_started)
    return -1;

  for (i = 0; i < pool_elts (dev->rqs); i++)
    {
      rv = roc_nix_rq_ena_dis (&dev->rqs[i], 0);
      if (rv)
	{
	  cnxk_pktio_err ("roc_nix_rq_ena_dis failed with '%s' error",
			  roc_error_msg_get (rv));
	  return -1;
	}
    }
  for (i = 0; i < pool_elts (dev->sqs); i++)
    {
      rv = roc_nix_tm_sq_aura_fc (&dev->sqs[i], 0);
      if (rv)
	{
	  cnxk_pktio_err ("roc_nix_tm_sq_aura_fc failed with '%s' error",
			  roc_error_msg_get (rv));
	  return -1;
	}
    }
  rv = roc_nix_npc_rx_ena_dis (nix, 0);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_npc_rx_ena_dis failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  dev->is_started = 0;

  return 0;
}

i32
cnxk_pktio_promisc_enable (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  struct roc_nix *nix = &dev->nix;
  int rv;

  if (roc_nix_is_vf_or_sdp (nix))
    return -1;

  rv = roc_nix_npc_promisc_ena_dis (nix, 1);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_npc_promisc_ena_dis failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  rv = roc_nix_mac_promisc_mode_enable (nix, 1);
  if (rv)
    {
      cnxk_pktio_err (
	"roc_nix_mac_promisc_mode_enable(1) failed with '%s' error",
	roc_error_msg_get (rv));
      return -1;
    }

  return 0;
}

i32
cnxk_pktio_promisc_disable (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  struct roc_nix *nix = &dev->nix;
  int rv;

  if (roc_nix_is_vf_or_sdp (nix))
    return -1;

  rv = roc_nix_npc_promisc_ena_dis (nix, 0);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_npc_promisc_ena_dis failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  rv = roc_nix_mac_promisc_mode_enable (nix, 0);
  if (rv)
    {
      cnxk_pktio_err (
	"roc_nix_mac_promisc_mode_enable(0) failed with '%s' error",
	roc_error_msg_get (rv));
      return -1;
    }

  return 0;
}

i32
cnxk_pktio_mtu_set (vlib_main_t *vm, cnxk_pktio_t *dev, u32 mtu)
{
  struct roc_nix *nix = &dev->nix;
  u32 max_len;
  i32 min_len;
  int rv;

  /* VPP adds driver overhead to total mtu size */
  min_len = (i32) mtu - CNXK_PKTIO_MAX_L2_SIZE;
  if (min_len < 0 || min_len < NIX_MIN_HW_FRS)
    {
      cnxk_pktio_err ("Given MTU is lesser than min supported (%d) value",
		      NIX_MIN_HW_FRS);
      return -1;
    }
  max_len = roc_nix_max_pkt_len (nix);
  if (mtu > max_len)
    {
      cnxk_pktio_err ("Given MTU(%d) exceeds hw supported(%d) value", mtu,
		      max_len);
      return -1;
    }

  /*
   * TODO: Flush SQ's before changing MTU
   */
  rv = roc_nix_mac_mtu_set (nix, mtu);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_mac_mtu_set failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  rv = roc_nix_mac_max_rx_len_set (nix, mtu);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_mac_max_rx_len_set failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  dev->pktio_mtu = mtu;

  return 0;
}

i32
cnxk_pktio_mtu_get (vlib_main_t *vm, cnxk_pktio_t *dev, u32 *mtu)
{
  *mtu = dev->pktio_mtu;
  return 0;
}

i32
cnxk_pktio_mac_addr_set (vlib_main_t *vm, cnxk_pktio_t *dev, char *addr)
{
  struct roc_nix *nix = &dev->nix;
  int rv;

  rv = roc_nix_npc_mac_addr_set (nix, (u8 *) addr);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_npc_mac_addr_set failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }
  return 0;
}

i32
cnxk_pktio_mac_addr_add (vlib_main_t *vm, cnxk_pktio_t *dev, char *addr)
{
  return 0;
}

i32
cnxk_pktio_mac_addr_del (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  cnxk_pktio_notice ("mac address del is not supported");
  return -1;
}

i32
cnxk_pktio_mac_addr_get (vlib_main_t *vm, cnxk_pktio_t *dev, char *addr)
{
  struct roc_nix *nix = &dev->nix;
  int rv;

  rv = roc_nix_npc_mac_addr_get (nix, (uint8_t *) addr);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_npc_mac_addr_get failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  return 0;
}

i32
cnxk_pktio_flowkey_set (vlib_main_t *vm, cnxk_pktio_t *dev,
			cnxk_pktio_rss_flow_key_t flowkey)
{
  struct roc_nix *nix = &dev->nix;
  u8 index;
  int rv;

  rv = roc_nix_rss_flowkey_set (nix, &index, flowkey, CNXK_DEFAULT_RSS_GROUP,
				CNXK_ANY_MCAM_INDEX);
  if (rv < 0)
    {
      cnxk_pktio_err ("roc_nix_rss_flowkey_set failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  return 0;
}

i32
cnxk_pktio_rss_key_set (vlib_main_t *vm, cnxk_pktio_t *dev, const u8 *rss_key,
			u8 rss_key_len)
{
  struct roc_nix *nix = &dev->nix;

  if (rss_key_len != CNXK_PKTIO_RSS_KEY_LEN)
    {
      cnxk_pktio_err ("Failed to set rss key: rss key length must be %u",
		      CNXK_PKTIO_RSS_KEY_LEN);
      return -1;
    }

  roc_nix_rss_key_set (nix, rss_key);

  return 0;
}

i32
cnxk_pktio_queue_stats_get (vlib_main_t *vm, cnxk_pktio_t *dev, u16 qid,
			    cnxk_pktio_queue_stats_t *qstats, bool is_rxq)
{
  struct roc_nix_stats_queue roc_qstats = { 0 };
  struct roc_nix *nix = &dev->nix;
  int rv;

  rv = roc_nix_stats_queue_get (nix, qid, is_rxq, &roc_qstats);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_stats_queue_get failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  if (is_rxq)
    {
      qstats->rx_pkts = roc_qstats.rx_pkts;
      qstats->rx_octs = roc_qstats.rx_octs;
      qstats->rx_drop_pkts = roc_qstats.rx_drop_pkts;
      qstats->rx_drop_octs = roc_qstats.rx_drop_octs;
      qstats->rx_error_pkts = roc_qstats.rx_error_pkts;
    }
  else
    {
      qstats->tx_pkts = roc_qstats.tx_pkts;
      qstats->tx_octs = roc_qstats.tx_octs;
      qstats->tx_drop_pkts = roc_qstats.tx_drop_pkts;
      qstats->tx_drop_octs = roc_qstats.tx_drop_octs;
    }

  return 0;
}

i32
cnxk_pktio_stats_get (vlib_main_t *vm, cnxk_pktio_t *dev,
		      cnxk_pktio_stats_t *stats)
{
  struct roc_nix_stats nix_stats;
  struct roc_nix *nix = &dev->nix;
  int rv;

  rv = roc_nix_stats_get (nix, &nix_stats);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_stats_get failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }
  stats->rx_octets = nix_stats.rx_octs;
  stats->rx_drop_octets = nix_stats.rx_drop_octs;
  stats->rx_ucast_pkts = nix_stats.rx_ucast;
  stats->rx_mcast_pkts = nix_stats.rx_bcast;
  stats->rx_bcast_pkts = nix_stats.rx_mcast;
  stats->rx_drop_pkts = nix_stats.rx_drop;
  stats->rx_drop_bcast_pkts = nix_stats.rx_drop_bcast;
  stats->rx_drop_mcast_pkts = nix_stats.rx_drop_mcast;
  stats->rx_fcs_pkts = nix_stats.rx_fcs;
  stats->rx_err = nix_stats.rx_err;
  stats->tx_octets = nix_stats.tx_octs;
  stats->tx_ucast_pkts = nix_stats.tx_ucast;
  stats->tx_mcast_pkts = nix_stats.tx_mcast;
  stats->tx_bcast_pkts = nix_stats.tx_bcast;
  stats->tx_drop_pkts = nix_stats.tx_drop;

  return 0;
}

i32
cnxk_pktio_xstats_count_get (vlib_main_t *vm, cnxk_pktio_t *dev, u32 *n_xstats)
{
  struct roc_nix *nix = &dev->nix;
  int count;

  count = roc_nix_xstats_names_get (nix, NULL, 0);
  *n_xstats = clib_min (CNXK_PKTIO_MAX_XSTATS_COUNT, count);

  return 0;
}

i32
cnxk_pktio_xstats_names_get (vlib_main_t *vm, cnxk_pktio_t *dev,
			     u8 *xstats_names[], u32 n_xstats)
{
  struct roc_nix_xstat_name roc_xstats_names[CNXK_PKTIO_MAX_XSTATS_COUNT];
  struct roc_nix *nix = &dev->nix;
  int rv, i;

  rv = roc_nix_xstats_names_get (nix, roc_xstats_names, n_xstats);
  if (rv < 0)
    {
      cnxk_pktio_err ("roc_nix_xstats_names_get failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  for (i = 0; i < n_xstats; i++)
    xstats_names[i] =
      format (xstats_names[i], "%s%c", &roc_xstats_names[i].name, 0);

  return 0;
}

i32
cnxk_pktio_xstats_get (vlib_main_t *vm, cnxk_pktio_t *dev, u64 *xstats,
		       u32 n_xstats)
{
  struct roc_nix_xstat roc_nix_xstats[CNXK_PKTIO_MAX_XSTATS_COUNT] = { 0 };
  struct roc_nix *nix = &dev->nix;
  int rv, i;

  rv = roc_nix_xstats_get (nix, roc_nix_xstats, n_xstats);
  if (rv < 0)
    {
      cnxk_pktio_err ("roc_nix_xstats_get failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  for (i = 0; i < n_xstats; i++)
    xstats[i] = roc_nix_xstats[i].value;

  return 0;
}

i32
cnxk_pktio_link_info_get (vlib_main_t *vm, cnxk_pktio_t *dev,
			  cnxk_pktio_link_info_t *link_info)
{
  struct roc_nix_link_info nix_info = {};
  struct roc_nix *nix = &dev->nix;
  int rv;

  if (roc_nix_is_lbk (&dev->nix) || roc_nix_is_sdp (&dev->nix))
    {
      link_info->is_up = 1;
      link_info->is_full_duplex = 1;
      link_info->speed = CNXK_PKTIO_LINK_SPEED_100G;
    }
  else
    {
      rv = roc_nix_mac_link_info_get (nix, &nix_info);
      if (rv)
	{
	  cnxk_pktio_err (
	    "roc_nix_mac_link_info_get failed with '%s' error on dev %d",
	    roc_error_msg_get (rv), dev->pktio_index, rv);
	  return -1;
	}

      link_info->is_up = nix_info.status;
      link_info->is_full_duplex = nix_info.full_duplex;
      link_info->speed = nix_info.speed;
    }
  return 0;
}

i32
cnxk_pktio_stats_clear (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  struct roc_nix *nix = &dev->nix;
  int rv;

  rv = roc_nix_stats_reset (nix);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_stats_reset failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  return 0;
}

i32
cnxk_pktio_queue_stats_clear (vlib_main_t *vm, cnxk_pktio_t *dev, u16 qid,
			      bool is_rxq)
{
  struct roc_nix *nix = &dev->nix;
  int rv;

  rv = roc_nix_stats_queue_reset (nix, qid, is_rxq);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_stats_queue_reset failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  return 0;
}

i32
cnxk_drv_pktio_pkts_recv (vlib_main_t *vm, vlib_node_runtime_t *node, u32 rxq,
			  u16 req_pkts, cnxk_per_thread_data_t *ptd,
			  const u64 mode, const u64 flags)
{
  cnxk_pktio_ops_map_t *ops_map;

  ASSERT (req_pkts <= CNXK_FRAME_SIZE);

  ops_map = cnxk_pktio_get_pktio_ops (ptd->pktio_index);
  ptd->out_user_nstats = 0;
  return ops_map->fops.pktio_pkts_recv (vm, node, rxq, req_pkts, ptd, mode,
					flags);
}

i32
cnxk_drv_pktio_pkts_send (vlib_main_t *vm, vlib_node_runtime_t *node, u32 txq,
			  u16 tx_pkts, cnxk_per_thread_data_t *ptd,
			  const u64 mode, const u64 flags)
{
  cnxk_pktio_ops_map_t *ops_map;

  ASSERT (tx_pkts <= CNXK_FRAME_SIZE);

  ops_map = cnxk_pktio_get_pktio_ops (ptd->pktio_index);
  return ops_map->fops.pktio_pkts_send (vm, node, txq, tx_pkts, ptd, mode,
					flags);
}

i32
cnxk_drv_pktio_init (vlib_main_t *vm, vlib_pci_addr_t *addr,
		     vlib_pci_dev_handle_t *phandle)
{
  ASSERT (vm->thread_index == 0);

  return cnxk_pktio_init (vm, addr, phandle);
}

i32
cnxk_drv_pktio_exit (vlib_main_t *vm, u16 pktio_index)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  return ops_map->fops.pktio_exit (vm, &ops_map->pktio);
}

i32
cnxk_drv_pktio_config (vlib_main_t *vm, u16 pktio_index,
		       cnxk_pktio_config_t *pktio_config)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_config (vm, &ops_map->pktio, pktio_config);
}

i32
cnxk_drv_pktio_capa_get (vlib_main_t *vm, u16 pktio_index,
			 cnxk_pktio_capa_t *pktio_capa)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_capa_get (vm, &ops_map->pktio, pktio_capa);
}

i32
cnxk_drv_pktio_flowkey_set (vlib_main_t *vm, u16 pktio_index,
			    cnxk_pktio_rss_flow_key_t flowkey)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_flowkey_set (vm, &ops_map->pktio, flowkey);
}

i32
cnxk_drv_pktio_rxq_setup (vlib_main_t *vm, u16 pktio_index,
			  cnxk_pktio_rxq_conf_t *rxq_conf)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_rxq_setup (vm, &ops_map->pktio, rxq_conf);
}

i32
cnxk_drv_pktio_txq_setup (vlib_main_t *vm, u16 pktio_index,
			  cnxk_pktio_txq_conf_t *txq_conf)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_txq_setup (vm, &ops_map->pktio, txq_conf);
}

i32
cnxk_drv_pktio_rxq_fp_set (vlib_main_t *vm, u16 pktio_idx, u32 rxq_id,
			   cnxk_pktio_rxq_fn_conf_t *rxq_fn_conf)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_idx);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_rxq_fp_set (vm, &ops_map->pktio, rxq_id,
					 rxq_fn_conf);
}

i32
cnxk_drv_pktio_txq_fp_set (vlib_main_t *vm, u16 pktio_idx, u32 txq_id,
			   cnxk_pktio_txq_fn_conf_t *txq_fn_conf)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_idx);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_txq_fp_set (vm, &ops_map->pktio, txq_id,
					 txq_fn_conf);
}

i32
cnxk_drv_pktio_promisc_enable (vlib_main_t *vm, u16 pktio_index)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_promisc_enable (vm, &ops_map->pktio);
}

i32
cnxk_drv_pktio_promisc_disable (vlib_main_t *vm, u16 pktio_index)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_promisc_disable (vm, &ops_map->pktio);
}

i32
cnxk_drv_pktio_mac_addr_set (vlib_main_t *vm, u16 pktio_index, char *mac_addr)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_mac_addr_set (vm, &ops_map->pktio, mac_addr);
}

i32
cnxk_drv_pktio_mac_addr_get (vlib_main_t *vm, u16 pktio_index, char *mac_addr)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_mac_addr_get (vm, &ops_map->pktio, mac_addr);
}

i32
cnxk_drv_pktio_mac_addr_add (vlib_main_t *vm, u16 pktio_index, char *mac_addr)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_mac_addr_add (vm, &ops_map->pktio, mac_addr);
}

i32
cnxk_drv_pktio_mac_addr_del (vlib_main_t *vm, u16 pktio_index)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_mac_addr_del (vm, &ops_map->pktio);
}

i32
cnxk_drv_pktio_mtu_set (vlib_main_t *vm, u16 pktio_index, u32 mtu)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_mtu_set (vm, &ops_map->pktio, mtu);
}

i32
cnxk_drv_pktio_mtu_get (vlib_main_t *vm, u16 pktio_index, u32 *mtu)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_mtu_get (vm, &ops_map->pktio, mtu);
}

i32
cnxk_drv_pktio_queue_stats_get (vlib_main_t *vm, u16 pktio_index, u16 qid,
				cnxk_pktio_queue_stats_t *queue_stats,
				bool is_rxq)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_queue_stats_get (vm, &ops_map->pktio, qid,
					      queue_stats, is_rxq);
}

i32
cnxk_drv_pktio_stats_get (vlib_main_t *vm, u16 pktio_index,
			  cnxk_pktio_stats_t *pktio_stats)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_stats_get (vm, &ops_map->pktio, pktio_stats);
}

i32
cnxk_drv_pktio_xstats_count_get (vlib_main_t *vm, u16 pktio_index,
				 u32 *n_xstats)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_xstats_count_get (vm, &ops_map->pktio, n_xstats);
}

i32
cnxk_drv_pktio_xstats_get (vlib_main_t *vm, u16 pktio_index, u64 *pktio_stats,
			   u32 count)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_xstats_get (vm, &ops_map->pktio, pktio_stats,
					 count);
}

i32
cnxk_drv_pktio_xstats_names_get (vlib_main_t *vm, u16 pktio_index,
				 u8 *xstats_names[], u32 count)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_xstats_names_get (vm, &ops_map->pktio,
					       xstats_names, count);
}

i32
cnxk_drv_pktio_stats_clear (vlib_main_t *vm, u16 pktio_index)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_stats_clear (vm, &ops_map->pktio);
}

i32
cnxk_drv_pktio_queue_stats_clear (vlib_main_t *vm, u16 pktio_index, u16 qid,
				  bool is_rxq)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_queue_stats_clear (vm, &ops_map->pktio, qid,
						is_rxq);
}

i32
cnxk_drv_pktio_start (vlib_main_t *vm, u16 pktio_index)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_start (vm, &ops_map->pktio);
}

i32
cnxk_drv_pktio_stop (vlib_main_t *vm, u16 pktio_index)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_stop (vm, &ops_map->pktio);
}

i32
cnxk_drv_pktio_link_info_get (vlib_main_t *vm, u16 pktio_index,
			      cnxk_pktio_link_info_t *link_info)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  ASSERT (vm->thread_index == 0);

  return ops_map->fops.pktio_link_info_get (vm, &ops_map->pktio, link_info);
}

u8 *
cnxk_drv_pktio_format_rx_trace (u8 *s, va_list *va)
{
  u32 pktio_index = va_arg (*va, u32);
  cnxk_pktio_ops_map_t *ops_map;

  ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  return (ops_map->fops.pktio_format_rx_trace (s, va));
}

i32
cnxk_drv_pktio_flow_update (vnet_main_t *vnm, vnet_flow_dev_op_t op,
			    u32 dev_instance, vnet_flow_t *flow,
			    uword *private_data)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (dev_instance);

  return (ops_map->fops.pktio_flow_update (vnm, op, &ops_map->pktio, flow,
					   private_data));
}

u32
cnxk_drv_pktio_flow_query (vlib_main_t *vm, u32 pktio_index, u32 flow_index,
			   cnxk_flow_stats_t *stats)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  return ops_map->fops.pktio_flow_query (vm, &ops_map->pktio, flow_index,
					 stats);
}

u32
cnxk_drv_pktio_flow_dump (vlib_main_t *vm, u32 pktio_index)
{
  cnxk_pktio_ops_map_t *ops_map = cnxk_pktio_get_pktio_ops (pktio_index);

  return ops_map->fops.pktio_flow_dump (vm, &ops_map->pktio);
}

VLIB_REGISTER_LOG_CLASS (cnxk_pktio_log) = {
  .class_name = "onp/pktio",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
