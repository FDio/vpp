/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_pktio_pktio_priv_h
#define included_onp_drv_modules_pktio_pktio_priv_h

#include <onp/drv/inc/common.h>
#include <onp/drv/inc/pktio.h>
#include <onp/drv/inc/pool.h>
#include <onp/drv/modules/pool/pool_priv.h>

#define CNXK_MAC_ADDRESS_LEN	   6
#define CNXK_NIX_MAX_SQB	   512
#define CNXK_RSS_FLOW_TAG_BITS	   32
#define CNXK_DEFAULT_RSS_GROUP	   0
#define CNXK_ANY_MCAM_INDEX	   -1
#define CNXK_DEFAULT_MCAM_ENTRIES  1
#define CNXK_NPC_MAX_FLOW_PRIORITY 7

/*
 * L2 header size includes
 * DST MAC + SRC MAC +
 * 2 VLAN TAGS + ETH TYPE + PTP
 */
#define CNXK_PKTIO_MAX_L2_SIZE 30
#define CNXK_PKTIO_MIN_HW_FRS  60

#define CNXK_PKTIO_RSS_KEY_LEN ROC_NIX_RSS_KEY_LEN
#define CNXK_PKTIO_MAX_DEVICES 32

#define CNXK_DEFAULT_RSS_FLOW_KEY                                             \
  (FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP |              \
   FLOW_KEY_TYPE_UDP | FLOW_KEY_TYPE_SCTP)

#define CNXK_PKTIO_DEFAULT_RX_CFG                                             \
  (ROC_NIX_LF_RX_CFG_DIS_APAD | ROC_NIX_LF_RX_CFG_IP6_UDP_OPT |               \
   ROC_NIX_LF_RX_CFG_L2_LEN_ERR | ROC_NIX_LF_RX_CFG_DROP_RE |                 \
   ROC_NIX_LF_RX_CFG_CSUM_OL4 | ROC_NIX_LF_RX_CFG_CSUM_IL4 |                  \
   ROC_NIX_LF_RX_CFG_LEN_OL3 | ROC_NIX_LF_RX_CFG_LEN_OL4 |                    \
   ROC_NIX_LF_RX_CFG_LEN_IL3 | ROC_NIX_LF_RX_CFG_LEN_IL4)

STATIC_ASSERT (CNXK_PKTIO_MAX_XSTATS_COUNT <= 256,
	       "Extended stats count is too large");

typedef union
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  union nix_rx_parse_u parse;
#ifdef CLIB_HAVE_VEC128
  u8x16 as_u8x16[3];
#endif
  u64 u[8];
} cnxk_pktio_nix_parse_t;

typedef enum
{
  /* RSS RQ */
  CNXK_PKTIO_RQ_TYPE_RSS,
} cnxk_pktio_rq_type_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /* CQ status and doorbell */
  int64_t *cq_status;
  uintptr_t cq_door;
  uintptr_t desc;
  u64 wdata;
  /* RQ id */
  u32 rq;

  /* Pending packets yet to be processed from CQ */
  u32 cached_pkts;

  /* Head and Qmask of CQ */
  u32 head;
  u32 qmask;
  i32 data_off;

  /* Required to fill in vlib buffer */
  u32 pktio_rx_sw_if_index;

  /* Number of rx descriptors configured */
  u16 n_queue_desc;

  u8 cnxk_pool_index;
  u8 vlib_buffer_pool_index;

  CLIB_ALIGN_MARK (cacheline0_second_64b, 64);
  f64 last_time_since_dequeued;
  u16 rxq_max_vec_size;
  u16 rxq_min_vec_size;
} cnxk_fprq_t __cnxk_cache_aligned;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 sq_id;
  i32 cached_pkts;
} cnxk_fpsq_t __cnxk_cache_aligned;

typedef struct
{
  /* vnet flow index */
  u32 vnet_flow_index;
  /* Internal flow object */
  struct roc_npc_flow *npc_flow;
} cnxk_flow_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  cnxk_fprq_t *fprqs;
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  cnxk_fpsq_t *fpsqs;
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  struct roc_nix_rq *rqs;
  struct roc_nix_sq *sqs;
  struct roc_nix_cq *cqs;
  struct roc_nix nix;
  struct roc_npc npc;
  u32 tx_cached_pkts;
  /* Flow vector */
  cnxk_flow_t *flow_entries;
  u32 n_tx_queues;
  u32 n_rx_queues;
  u32 pktio_mtu;
  cnxk_pktio_link_type_t pktio_link_type; /* CGX, LBK, PCI */
  char mac_address[CNXK_MAC_ADDRESS_LEN];
  u8 pktio_index;
  u8 is_used;
  u8 is_configured;
  u8 is_started;
} cnxk_pktio_t;

typedef struct cnxk_pktio_ops
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  i32 (*pktio_pkts_recv) (vlib_main_t *vm, vlib_node_runtime_t *node, u32 rxq,
			  u16 req_pkts, cnxk_per_thread_data_t *rxptd,
			  const u64 mode, const u64 flags);

  i32 (*pktio_pkts_send) (vlib_main_t *vm, vlib_node_runtime_t *node, u32 txq,
			  u16 tx_pkts, cnxk_per_thread_data_t *txptd,
			  const u64 mode, const u64 flags);

  i32 (*pktio_init) (vlib_main_t *vm, vlib_pci_addr_t *addr,
		     vlib_pci_dev_handle_t *);

  i32 (*pktio_exit) (vlib_main_t *vm, cnxk_pktio_t *dev);

  i32 (*pktio_start) (vlib_main_t *vm, cnxk_pktio_t *dev);

  i32 (*pktio_stop) (vlib_main_t *vm, cnxk_pktio_t *dev);

  i32 (*pktio_flowkey_set) (vlib_main_t *vm, cnxk_pktio_t *dev,
			    cnxk_pktio_rss_flow_key_t flowkey);

  i32 (*pktio_rss_key_set) (vlib_main_t *vm, cnxk_pktio_t *dev,
			    const u8 *rss_key, u8 rss_key_len);

  i32 (*pktio_capa_get) (vlib_main_t *vm, cnxk_pktio_t *dev,
			 cnxk_pktio_capa_t *capa);

  i32 (*pktio_config) (vlib_main_t *vm, cnxk_pktio_t *dev,
		       cnxk_pktio_config_t *config);

  i32 (*pktio_rxq_setup) (vlib_main_t *vm, cnxk_pktio_t *dev,
			  cnxk_pktio_rxq_conf_t *rxconf);

  i32 (*pktio_txq_setup) (vlib_main_t *vm, cnxk_pktio_t *dev,
			  cnxk_pktio_txq_conf_t *txconf);

  i32 (*pktio_rxq_fp_set) (vlib_main_t *vm, cnxk_pktio_t *dev, u32 rxq_id,
			   cnxk_pktio_rxq_fn_conf_t *rxq_fn_conf);

  i32 (*pktio_txq_fp_set) (vlib_main_t *vm, cnxk_pktio_t *dev, u32 txq_id,
			   cnxk_pktio_txq_fn_conf_t *txq_fn_conf);

  i32 (*pktio_promisc_enable) (vlib_main_t *vm, cnxk_pktio_t *dev);

  i32 (*pktio_promisc_disable) (vlib_main_t *vm, cnxk_pktio_t *dev);

  i32 (*pktio_mtu_set) (vlib_main_t *vm, cnxk_pktio_t *dev, u32 mtu);
  i32 (*pktio_link_info_get) (vlib_main_t *vm, cnxk_pktio_t *dev,
			      cnxk_pktio_link_info_t *link_info);

  i32 (*pktio_mtu_get) (vlib_main_t *vm, cnxk_pktio_t *dev, u32 *mtu);

  i32 (*pktio_mac_addr_set) (vlib_main_t *vm, cnxk_pktio_t *dev, char *addr);

  i32 (*pktio_mac_addr_get) (vlib_main_t *vm, cnxk_pktio_t *dev, char *addr);

  i32 (*pktio_mac_addr_add) (vlib_main_t *vm, cnxk_pktio_t *dev, char *addr);

  i32 (*pktio_mac_addr_del) (vlib_main_t *vm, cnxk_pktio_t *dev);

  i32 (*pktio_queue_stats_get) (vlib_main_t *vm, cnxk_pktio_t *dev, u16 qid,
				cnxk_pktio_queue_stats_t *qstats, bool is_rxq);
  i32 (*pktio_stats_get) (vlib_main_t *vm, cnxk_pktio_t *dev,
			  cnxk_pktio_stats_t *stats);

  i32 (*pktio_xstats_count_get) (vlib_main_t *vm, cnxk_pktio_t *dev,
				 u32 *n_xstats);

  i32 (*pktio_xstats_names_get) (vlib_main_t *vm, cnxk_pktio_t *dev,
				 u8 *xstats_names[], u32 count);

  i32 (*pktio_xstats_get) (vlib_main_t *vm, cnxk_pktio_t *dev, u64 *xstats,
			   u32 count);

  i32 (*pktio_stats_clear) (vlib_main_t *vm, cnxk_pktio_t *dev);

  i32 (*pktio_queue_stats_clear) (vlib_main_t *vm, cnxk_pktio_t *dev, u16 qid,
				  bool is_rxq);
  u8 (*pktio_is_inl_dev) (vlib_main_t *vm, cnxk_pktio_t *dev);

  u8 *(*pktio_format_rx_trace) (u8 *, va_list *);

  i32 (*pktio_flow_update) (vnet_main_t *vnm, vnet_flow_dev_op_t op,
			    cnxk_pktio_t *dev, vnet_flow_t *flow,
			    uword *private_data);

  u32 (*pktio_flow_query) (vlib_main_t *vm, cnxk_pktio_t *dev, u32 flow_index,
			   cnxk_flow_stats_t *stats);

  u32 (*pktio_flow_dump) (vlib_main_t *vm, cnxk_pktio_t *dev);

} cnxk_pktio_ops_t;

typedef struct
{
  /* Pktio index */
  cnxk_pktio_t pktio;

  /* Function ops */
  cnxk_pktio_ops_t fops;
} cnxk_pktio_ops_map_t;

typedef struct
{
  cnxk_pktio_ops_map_t *pktio_ops;
  u32 n_pktios;
  struct
  {
    struct roc_nix_inl_dev dev;
    uintptr_t inb_sa_base;
    u32 inb_spi_mask;
    u8 is_enabled;
  } inl_dev;
} cnxk_pktio_main_t;

extern cnxk_pktio_ops_t eth_10k_ops;
extern cnxk_pktio_ops_t cn10k_inl_dev_pktio_ops;
extern cnxk_pktio_main_t cnxk_pktio_main;
extern const u8 cnxk_pktio_default_rss_key[CNXK_PKTIO_RSS_KEY_LEN];

static_always_inline cnxk_pktio_main_t *
cnxk_pktio_get_main (void)
{
  return &(cnxk_pktio_main);
}

static_always_inline cnxk_pktio_ops_map_t *
cnxk_pktio_get_pktio_ops (u32 pktio_index)
{
  cnxk_pktio_main_t *p = cnxk_pktio_get_main ();

  ASSERT (pktio_index < p->n_pktios);
  return (p->pktio_ops + pktio_index);
}

static_always_inline u32
cnxk_pktio_get_tx_vlib_buf_segs (vlib_main_t *vm, vlib_buffer_t *b,
				 const u64 offload_flags)
{
  /* Each buffer will have atleast 1 segment */
  u32 n_segs = 1;

  if (!(offload_flags & CNXK_PKTIO_TX_OFF_FLAG_MSEG))
    return 1;

  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_NEXT_PRESENT)))
    return n_segs;

  do
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      n_segs++;
    }
  while (b->flags & VLIB_BUFFER_NEXT_PRESENT);

  return n_segs;
}

i32 cnxk_pktio_init (vlib_main_t *vm, vlib_pci_addr_t *addr,
		     vlib_pci_dev_handle_t *);
i32 cnxk_pktio_exit (vlib_main_t *vm, cnxk_pktio_t *dev);
i32 cnxk_pktio_start (vlib_main_t *vm, cnxk_pktio_t *dev);
i32 cnxk_pktio_stop (vlib_main_t *vm, cnxk_pktio_t *dev);
i32 cnxk_pktio_flowkey_set (vlib_main_t *vm, cnxk_pktio_t *dev,
			    cnxk_pktio_rss_flow_key_t flowkey);
i32 cnxk_pktio_rss_key_set (vlib_main_t *vm, cnxk_pktio_t *dev,
			    const u8 *rss_key, u8 rss_key_len);
i32 cnxk_pktio_promisc_enable (vlib_main_t *vm, cnxk_pktio_t *dev);

i32 cnxk_pktio_promisc_disable (vlib_main_t *vm, cnxk_pktio_t *dev);
i32 cnxk_pktio_mtu_set (vlib_main_t *vm, cnxk_pktio_t *dev, u32 mtu);
i32 cnxk_pktio_mtu_get (vlib_main_t *vm, cnxk_pktio_t *dev, u32 *mtu);
i32 cnxk_pktio_mac_addr_set (vlib_main_t *vm, cnxk_pktio_t *dev, char *addr);
i32 cnxk_pktio_mac_addr_get (vlib_main_t *vm, cnxk_pktio_t *dev, char *addr);
i32 cnxk_pktio_mac_addr_add (vlib_main_t *vm, cnxk_pktio_t *dev, char *addr);
i32 cnxk_pktio_mac_addr_del (vlib_main_t *vm, cnxk_pktio_t *dev);
i32 cnxk_pktio_stats_get (vlib_main_t *vm, cnxk_pktio_t *dev,
			  cnxk_pktio_stats_t *stats);
i32 cnxk_pktio_queue_stats_get (vlib_main_t *vm, cnxk_pktio_t *dev, u16 qid,
				cnxk_pktio_queue_stats_t *qstats, bool is_rxq);
i32 cnxk_pktio_xstats_count_get (vlib_main_t *vm, cnxk_pktio_t *dev,
				 u32 *n_xstats);
i32 cnxk_pktio_xstats_names_get (vlib_main_t *vm, cnxk_pktio_t *dev,
				 u8 *xstats_names[], u32 count);
i32 cnxk_pktio_xstats_get (vlib_main_t *vm, cnxk_pktio_t *dev, u64 *xstats,
			   u32 count);
i32 cnxk_pktio_stats_clear (vlib_main_t *vm, cnxk_pktio_t *dev);
i32 cnxk_pktio_queue_stats_clear (vlib_main_t *vm, cnxk_pktio_t *dev, u16 qid,
				  bool is_rxq);
u8 cn10k_pktio_is_inl_dev (vlib_main_t *vm, cnxk_pktio_t *dev);
i32 cnxk_pktio_link_info_get (vlib_main_t *vm, cnxk_pktio_t *dev,
			      cnxk_pktio_link_info_t *link_info);
u8 *cnxk_pktio_format_rx_trace (u8 *s, va_list *args);
u32 cnxk_pktio_flow_query (vlib_main_t *vm, cnxk_pktio_t *dev, u32 flow_index,
			   cnxk_flow_stats_t *stats);
u32 cnxk_pktio_flow_dump (vlib_main_t *vm, cnxk_pktio_t *dev);
i32 cnxk_pktio_flow_update (vnet_main_t *vnm, vnet_flow_dev_op_t op,
			    cnxk_pktio_t *dev, vnet_flow_t *flow,
			    uword *private_data);

#endif /* included_onp_drv_modules_pktio_pktio_priv_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
