/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/pktio/pktio_priv.h>
#include <onp/drv/modules/pktio/pktio_rx.h>
#include <onp/drv/modules/pktio/pktio_fp_tx_cn10k.h>

#include <onp/drv/modules/pktio/pktio_fp_ops.h>

/* clang-format off */

#define _(trace, o_cksum, name)                                               \
                                                                              \
i32                                                                           \
CLIB_MULTIARCH_FN(cn10k_recv_pkts_##name) (vlib_main_t *vm,                   \
                        vlib_node_runtime_t *node, u32 rxq, u16 rx_pkts,      \
                        cnxk_per_thread_data_t *ptd)                          \
{                                                                             \
  u64 rx_off_flags = o_cksum ? CNXK_PKTIO_RX_OFF_FLAG_OUTER_CKSUM : 0;        \
  u64 fp_flags = trace ? CNXK_PKTIO_FP_FLAG_TRACE_EN : 0;                     \
                                                                              \
  return cnxk_pkts_recv (vm, node, rxq, rx_pkts, ptd, fp_flags,               \
			 rx_off_flags);                                       \
}                                                                             \
CLIB_MARCH_FN_REGISTRATION(cn10k_recv_pkts_##name);                           \
                                                                              \
i32                                                                           \
CLIB_MULTIARCH_FN(cn10k_recv_mseg_pkts_##name) (vlib_main_t *vm,              \
                        vlib_node_runtime_t *node,u32 rxq, u16 rx_pkts,       \
                        cnxk_per_thread_data_t *ptd)                          \
{                                                                             \
  u64 rx_off_flags = o_cksum ? CNXK_PKTIO_RX_OFF_FLAG_OUTER_CKSUM : 0;        \
  u64 fp_flags = trace ? CNXK_PKTIO_FP_FLAG_TRACE_EN : 0;                     \
                                                                              \
  return cnxk_pkts_recv (vm, node, rxq, rx_pkts, ptd, fp_flags,               \
                         rx_off_flags | CNXK_PKTIO_RX_OFF_FLAG_MSEG);         \
}                                                                             \
CLIB_MARCH_FN_REGISTRATION(cn10k_recv_mseg_pkts_##name);

foreach_pktio_rx_func
#undef _

#define _(o_cksum, desc_sz, name)                                             \
                                                                              \
i32                                                                           \
CLIB_MULTIARCH_FN(cn10k_send_pkts_##name) (vlib_main_t *vm,                   \
                        vlib_node_runtime_t *node,u32 txq, u16 tx_pkts,       \
                        cnxk_per_thread_data_t *ptd)                          \
{                                                                             \
  u64 tx_off_flags = o_cksum ? CNXK_PKTIO_TX_OFF_FLAG_OUTER_CKSUM : 0;        \
  u64 fp_flags = 0;                                                           \
                                                                              \
    return cn10k_pkts_send (vm, node, txq, tx_pkts, ptd, desc_sz,             \
                            fp_flags, tx_off_flags);                          \
}                                                                             \
CLIB_MARCH_FN_REGISTRATION(cn10k_send_pkts_##name);                           \
                                                                              \
i32                                                                           \
CLIB_MULTIARCH_FN(cn10k_send_mseg_pkts_##name) (vlib_main_t *vm,              \
                         vlib_node_runtime_t *node, u32 txq, u16 tx_pkts,     \
                         cnxk_per_thread_data_t *ptd)                         \
{                                                                             \
  u64 tx_off_flags = o_cksum ? CNXK_PKTIO_TX_OFF_FLAG_OUTER_CKSUM : 0;        \
  u64 fp_flags = 0;                                                           \
									      \
    return cn10k_pkts_send (vm, node, txq, tx_pkts, ptd, desc_sz + 8,         \
                            fp_flags,                                         \
                            tx_off_flags | CNXK_PKTIO_TX_OFF_FLAG_MSEG);      \
}                                                                             \
CLIB_MARCH_FN_REGISTRATION(cn10k_send_mseg_pkts_##name);

foreach_pktio_tx_func
;
#undef _

/* clang-format on */

#ifndef CLIB_MARCH_VARIANT
i32
cn10k_pktio_pkts_recv (vlib_main_t *vm, vlib_node_runtime_t *node, u32 rxq,
		       u16 rx_pkts, cnxk_per_thread_data_t *ptd,
		       const u64 fp_flags, const u64 off_flags)
{
  ASSERT (rx_pkts);

  return cnxk_pkts_recv (vm, node, rxq, rx_pkts, ptd, fp_flags, off_flags);
}

i32
cn10k_pktio_pkts_send (vlib_main_t *vm, vlib_node_runtime_t *node, u32 txq,
		       u16 tx_pkts, cnxk_per_thread_data_t *ptd,
		       const u64 fp_flags, const u64 off_flags)
{
  ASSERT (tx_pkts);

  return cn10k_pkts_send (vm, node, txq, tx_pkts, ptd, 16, fp_flags,
			  off_flags);
}

static i32
cn10k_pktio_config (vlib_main_t *vm, cnxk_pktio_t *dev,
		    cnxk_pktio_config_t *config)
{
  u32 rx_queues, tx_max_len, rx_max_len, tx_queues;
  u32 flow_key_cfg = CNXK_DEFAULT_RSS_FLOW_KEY;
  u64 rx_cfg = CNXK_PKTIO_DEFAULT_RX_CFG;
  struct roc_nix *nix = &dev->nix;
  bool tm_xmit_enable;
  int rv;

  tx_max_len = rx_max_len = roc_nix_max_pkt_len (nix);

  /* Allocate all queues at once */
  rx_queues = config->n_rx_queues;
  tx_queues = config->n_tx_queues;
  rv = roc_nix_lf_alloc (nix, rx_queues, tx_queues, rx_cfg);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_lf_alloc failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  dev->n_rx_queues = config->n_rx_queues;
  dev->n_tx_queues = config->n_tx_queues;

  /* Get channel base from kernel */
  dev->npc.channel = roc_nix_get_base_chan (nix);

  rv = roc_nix_tm_init (nix);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_tm_init failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  tm_xmit_enable = false;
  rv = roc_nix_tm_hierarchy_enable (nix, ROC_NIX_TM_DEFAULT, tm_xmit_enable);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_tm_hierarchy_enable failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  rv = roc_nix_mac_mtu_set (nix, tx_max_len);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_mac_mtu_set failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  rv = roc_nix_mac_max_rx_len_set (nix, rx_max_len);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_mac_max_rx_len_set failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  dev->pktio_mtu = roc_nix_max_pkt_len (nix);

  rv = roc_nix_rss_default_setup (nix, flow_key_cfg);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_rss_default_setup failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  /* Update RSS key */
  roc_nix_rss_key_set (nix, cnxk_pktio_default_rss_key);

  dev->is_configured = 1;

  return 0;
}

static i32
cn10k_pktio_fprq_setup (vlib_main_t *vm, cnxk_pktio_t *dev, u32 qid,
			struct roc_nix_rq *rq, struct roc_nix_cq *cq,
			cnxk_pktio_rxq_conf_t *conf,
			cnxk_pktio_rq_type_t rxq_type)
{
  cnxk_fprq_t *fprq = NULL;

  pool_get_zero (dev->fprqs, fprq);

  if (fprq != vec_elt_at_index (dev->fprqs, qid))
    {
      cnxk_pktio_err ("Given rxq(%d) is not configured yet", qid);
      return -1;
    }

  fprq->cq_status = cq->status;
  fprq->cq_door = cq->door;
  fprq->desc = (uintptr_t) cq->desc_base;
  fprq->rq = qid;
  fprq->wdata = cq->wdata;
  fprq->head = cq->head;
  fprq->qmask = cq->qmask;
  fprq->data_off = sizeof (vlib_buffer_t);

  fprq->pktio_rx_sw_if_index = conf->pktio_sw_if_index;

  if (rxq_type == CNXK_PKTIO_RQ_TYPE_RSS)
    {
      fprq->rxq_min_vec_size = conf->rxq_min_vec_size;
      fprq->rxq_max_vec_size = conf->rxq_max_vec_size;
      fprq->cnxk_pool_index = conf->cnxk_pool_index;
      fprq->vlib_buffer_pool_index = conf->vlib_buffer_pool_index;
      fprq->n_queue_desc = conf->rx_desc;
    }

  fprq->cached_pkts = 0;
  fprq->last_time_since_dequeued = 0.0;

  return 0;
}

static i32
cn10k_pktio_rxq_setup (vlib_main_t *vm, cnxk_pktio_t *dev,
		       cnxk_pktio_rxq_conf_t *conf)
{
  u32 rx_queues, first_skip, i, n_desc;
  struct roc_nix *nix = &dev->nix;
  cnxk_pktio_rq_type_t rq_type;
  struct roc_nix_cq *cq = NULL;
  struct roc_nix_rq *rq = NULL;
  u64 aura_handle = 0;
  int rv;

  aura_handle = cnxk_pool_get_aura_handle (conf->cnxk_pool_index);
  rx_queues = dev->n_rx_queues;
  rq_type = CNXK_PKTIO_RQ_TYPE_RSS;
  n_desc = conf->rx_desc;

  for (i = 0; i < rx_queues; i++)
    {
      pool_get_zero (dev->cqs, cq);
      cq->nb_desc = n_desc;
      cq->qid = cq - dev->cqs;
      rv = roc_nix_cq_init (nix, cq);
      if (rv)
	{
	  cnxk_pktio_err ("roc_nix_cq_init failed (rxq=%d) with '%s' error", i,
			  roc_error_msg_get (rv));
	  return -1;
	}

      pool_get_zero (dev->rqs, rq);

      rq->qid = rq - dev->rqs;
      rq->cqid = cq->qid;
      rq->aura_handle = aura_handle;
      first_skip = sizeof (vlib_buffer_t);
      rq->first_skip = rq->later_skip = first_skip;
      rq->lpb_size = vlib_buffer_get_default_data_size (vm) + first_skip;
      rq->flow_tag_width = CNXK_RSS_FLOW_TAG_BITS;

      rv = roc_nix_rq_init (nix, rq, 0 /* disable */);
      if (rv)
	{
	  cnxk_pktio_err (
	    "roc_nix_rq_init failed (rxq=%d) failed with '%s' error", i,
	    roc_error_msg_get (rv));
	  return -1;
	}

      /* Configure inline device rq */
      rv = roc_nix_inl_dev_rq_get (rq, 0 /* disable */);
      if (rv)
	{
	  cnxk_pktio_err (
	    "roc_nix_inl_dev_rq_get failed (rxq=%d) with '%s' error", i,
	    roc_error_msg_get (rv));

	  return -1;
	}

      if (cn10k_pktio_fprq_setup (vm, dev, i, rq, cq, conf, rq_type) < 0)
	return -1;
    }
  return 0;
}

static i32
cn10k_pktio_fpsq_setup (cnxk_pktio_t *dev, u32 qid, struct roc_nix_sq *sq,
			struct roc_nix_cq *cq, cnxk_pktio_txq_conf_t *txq_conf)
{
  cnxk_fpsq_t *fpsq = NULL;

  if (qid < dev->n_tx_queues)
    {
      pool_get_zero (dev->fpsqs, fpsq);
      if (fpsq != vec_elt_at_index (dev->fpsqs, qid))
	{
	  cnxk_pktio_err ("Given txq(%d) is not configured yet", qid);
	  return -1;
	}
    }
  else
    {
      cnxk_pktio_err ("Given txq(%d) is not in range (0:%d)", qid,
		      dev->n_tx_queues - 1);
      return -1;
    }
  fpsq->sq_id = sq->qid;
  fpsq->cached_pkts = 0;

  return 0;
}

static i32
cn10k_pktio_txq_setup (vlib_main_t *vm, cnxk_pktio_t *dev,
		       cnxk_pktio_txq_conf_t *conf)
{
  enum roc_nix_sq_max_sqe_sz max_sqe_sz;
  struct roc_nix *nix = &dev->nix;
  struct roc_nix_sq *sq = NULL;
  u32 i, n_tx_queues;
  int rv;

  n_tx_queues = dev->n_tx_queues;
  if (conf->txq_offloads & CNXK_PKTIO_TX_OFF_FLAG_MSEG)
    max_sqe_sz = NIX_MAXSQESZ_W16;
  else
    max_sqe_sz = NIX_MAXSQESZ_W8;

  for (i = 0; i < n_tx_queues; i++)
    {
      pool_get_zero (dev->sqs, sq);

      sq->qid = sq - dev->sqs;
      sq->nb_desc = conf->tx_desc;
      sq->max_sqe_sz = max_sqe_sz;
      rv = roc_nix_sq_init (nix, sq);
      if (rv)
	{
	  cnxk_pktio_err ("roc_nix_sq_init failed (txq=%d) with '%s' error", i,
			  roc_error_msg_get (rv));
	  return -1;
	}
      sq->lmt_addr = (void *) nix->lmt_base;

      if (cn10k_pktio_fpsq_setup (dev, i, sq, NULL /* cq */, conf) < 0)
	return -1;
    }

  return 0;
}

static i32
cn10k_pktio_rxq_fp_set (vlib_main_t *vm, cnxk_pktio_t *dev, u32 rxq_id,
			cnxk_pktio_rxq_fn_conf_t *rxq_fn_conf)
{
  cnxk_drv_pktio_rxq_recv_func_t mseg_rx_func[2][2];
  cnxk_drv_pktio_rxq_recv_func_t rx_func[2][2];
  u64 flags = rxq_fn_conf->offload_flags;
  u64 fp_flags = rxq_fn_conf->fp_flags;

  /* clang-format off */
#define _(trace, o_cksum, name)                                               \
  rx_func[trace][o_cksum] = CLIB_MARCH_FN_POINTER(cn10k_recv_pkts_##name);

   foreach_pktio_rx_func
#undef _

#define _(trace, o_cksum, name)                                               \
  mseg_rx_func[trace][o_cksum] = CLIB_MARCH_FN_POINTER(cn10k_recv_mseg_pkts_##name);

   foreach_pktio_rx_func
#undef _

  if (flags & CNXK_PKTIO_RX_OFF_FLAG_MSEG)
    rxq_fn_conf->pktio_recv_func_ptr = mseg_rx_func
                                  [!!(fp_flags & CNXK_PKTIO_FP_FLAG_TRACE_EN)]
                                  [!!(flags & CNXK_PKTIO_RX_OFF_FLAG_OUTER_CKSUM)];
  else
    rxq_fn_conf->pktio_recv_func_ptr = rx_func
                                  [!!(fp_flags & CNXK_PKTIO_FP_FLAG_TRACE_EN)]
                                  [!!(flags & CNXK_PKTIO_RX_OFF_FLAG_OUTER_CKSUM)];

  /* clang-format on */

  ASSERT (rxq_fn_conf->pktio_recv_func_ptr);
  if (!rxq_fn_conf->pktio_recv_func_ptr)
    return -1;

  return 0;
}

static i32
cn10k_pktio_txq_fp_set (vlib_main_t *vm, cnxk_pktio_t *dev, u32 txq_id,
			cnxk_pktio_txq_fn_conf_t *txq_fn_conf)
{
  cnxk_drv_pktio_txq_send_func_t mseg_tx_func[2];
  cnxk_drv_pktio_txq_send_func_t tx_func[2];
  u64 flags = txq_fn_conf->offload_flags;

  /* clang-format off */
#define _(o_cksum, desc_sz, name)                                             \
  tx_func[o_cksum] = CLIB_MARCH_FN_POINTER(                                   \
                                          cn10k_send_pkts_##name);            \

    foreach_pktio_tx_func
#undef _

#define _(o_cksum, desc_sz, name)                                             \
  mseg_tx_func[o_cksum] = CLIB_MARCH_FN_POINTER(                              \
                                               cn10k_send_mseg_pkts_##name);  \

    foreach_pktio_tx_func
#undef _

  if (flags & CNXK_PKTIO_TX_OFF_FLAG_MSEG)
    txq_fn_conf->pktio_send_func_ptr =  mseg_tx_func
                                [!!(flags & CNXK_PKTIO_TX_OFF_FLAG_OUTER_CKSUM)];
  else
    txq_fn_conf->pktio_send_func_ptr =  tx_func
                                [!!(flags & CNXK_PKTIO_TX_OFF_FLAG_OUTER_CKSUM)];
  /* clang-format on */

  ASSERT (txq_fn_conf->pktio_send_func_ptr);
  if (!txq_fn_conf->pktio_send_func_ptr)
    return -1;

  return 0;
}

static i32
cn10k_pktio_capa_get (vlib_main_t *vm, cnxk_pktio_t *dev,
		      cnxk_pktio_capa_t *capa)
{
  struct roc_nix *nix = &dev->nix;
  cnxk_pktio_main_t *pm;
  u32 max_len;

  clib_memset (capa, 0, sizeof (*capa));

  pm = cnxk_pktio_get_main ();
  max_len = roc_nix_max_pkt_len (nix);

  capa->mtu.min_frame_size = CNXK_PKTIO_MIN_HW_FRS;
  capa->mtu.max_frame_size = max_len;
  capa->mtu.frame_overhead = CNXK_PKTIO_MAX_L2_SIZE;

  return 0;
}

cnxk_pktio_ops_t eth_10k_ops = {
  .pktio_queue_stats_clear = cnxk_pktio_queue_stats_clear,
  .pktio_xstats_count_get = cnxk_pktio_xstats_count_get,
  .pktio_xstats_names_get = cnxk_pktio_xstats_names_get,
  .pktio_format_rx_trace = cnxk_pktio_format_rx_trace,
  .pktio_promisc_disable = cnxk_pktio_promisc_disable,
  .pktio_queue_stats_get = cnxk_pktio_queue_stats_get,
  .pktio_promisc_enable = cnxk_pktio_promisc_enable,
  .pktio_link_info_get = cnxk_pktio_link_info_get,
  .pktio_mac_addr_set = cnxk_pktio_mac_addr_set,
  .pktio_mac_addr_get = cnxk_pktio_mac_addr_get,
  .pktio_mac_addr_add = cnxk_pktio_mac_addr_add,
  .pktio_mac_addr_del = cnxk_pktio_mac_addr_del,
  .pktio_stats_clear = cnxk_pktio_stats_clear,
  .pktio_flow_update = cnxk_pktio_flow_update,
  .pktio_flowkey_set = cnxk_pktio_flowkey_set,
  .pktio_rss_key_set = cnxk_pktio_rss_key_set,
  .pktio_rxq_fp_set = cn10k_pktio_rxq_fp_set,
  .pktio_txq_fp_set = cn10k_pktio_txq_fp_set,
  .pktio_flow_query = cnxk_pktio_flow_query,
  .pktio_xstats_get = cnxk_pktio_xstats_get,
  .pktio_pkts_recv = cn10k_pktio_pkts_recv,
  .pktio_pkts_send = cn10k_pktio_pkts_send,
  .pktio_rxq_setup = cn10k_pktio_rxq_setup,
  .pktio_txq_setup = cn10k_pktio_txq_setup,
  .pktio_stats_get = cnxk_pktio_stats_get,
  .pktio_flow_dump = cnxk_pktio_flow_dump,
  .pktio_capa_get = cn10k_pktio_capa_get,
  .pktio_mtu_set = cnxk_pktio_mtu_set,
  .pktio_mtu_get = cnxk_pktio_mtu_get,
  .pktio_config = cn10k_pktio_config,
  .pktio_start = cnxk_pktio_start,
  .pktio_stop = cnxk_pktio_stop,
  .pktio_init = cnxk_pktio_init,
  .pktio_exit = cnxk_pktio_exit,
};
#endif /* CLIB_MARCH_VARIANT */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
