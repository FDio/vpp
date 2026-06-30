/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _PP2_H_
#define _PP2_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vppinfra/devicetree.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#include <net/if.h>

#include <pp2/pp2_hw.h>

struct ethtool_gstrings;
struct mv_pp2x_prs_shadow;
#define MVCONF_DBG_LEVEL	       0
#define MVCONF_PP2_BPOOL_COOKIE_SIZE   32
#define MVCONF_PP2_BPOOL_DMA_ADDR_SIZE 64
#define MVCONF_DMA_PHYS_ADDR_T_SIZE    64
#define MVPP2_MAX_NUM_DEVICES	       4
#define MVCONF_TYPES_PUBLIC
#define MVCONF_DMA_PHYS_ADDR_T_PUBLIC

#define MVPP2_NUM_HIFS	       9
#define MVPP2_REGSPACE_SIZE	  0x10000
#define MVPP2_NUM_BPOOLS       16
#define MVPP2_MAX_THREADS      4
#define MRVL_PP2_BUFF_BATCH_SZ 32
#define MVPP2_LOOPBACK_PORT	  3
#define MVPP2_LOOPBACK_TXQ_ID	  ((MVPP2_MAX_TCONT + MVPP2_LOOPBACK_PORT) * MVPP2_MAX_TXQ)
#define MV_SYS_DMA_MAX_NUM_MEM_ID 4
#define MVPP2_PORT_MAX_TCS	  32
#define MVPP2_PORT_MAX_RX_QUEUES  32
#define MVPP2_PORT_MAX_TX_QUEUES  8
#define MVPP2_TC_MAX_BPOOLS	  2

typedef u8 eth_addr_t[6];

enum mvpp2_port_hash_type
{
  MVPP2_PORT_HASH_NONE = 0,
  MVPP2_PORT_HASH_2_TUPLE,
  MVPP2_PORT_HASH_5_TUPLE,
  MVPP2_PORT_HASH_OUT_OF_RANGE,
};

enum mvpp2_port_eth_start_hdr
{
  MVPP2_PORT_HDR_ETH = 0,
  MVPP2_PORT_HDR_ETH_DSA,
  MVPP2_PORT_HDR_ETH_EXT_DSA,
  MVPP2_PORT_HDR_ETH_CUSTOM,
  MVPP2_PORT_HDR_OUT_OF_RANGE,
};

enum mvpp2_port_color
{
  MVPP2_PORT_COLOR_GREEN = 0,
  MVPP2_PORT_COLOR_YELLOW,
  MVPP2_PORT_COLOR_RED,
};

enum mvpp2_txq_sched_mode
{
  MVPP2_TXQ_SCHED_WRR = 0,
  MVPP2_TXQ_SCHED_SP,
};

typedef struct
{
  u8 id;
  u32 buf_sz;
  uintptr_t virt_base;
  uintptr_t phys_base;
  u8 fc_not_supported : 1;
  u8 is_initialized : 1;
} mvpp2_bpool_t;

typedef struct
{
  vlib_main_t *vm;
  vnet_dev_t *dev;
  u8 id;
  u32 buff_len;
  int dummy_short_pool;
} mvpp2_bpool_params_t;

typedef struct
{
  u64 addr;
  u64 cookie;
} mvpp2_buff_info_t;

typedef enum
{
  MVPP2_BM_POOL_TYPE_SHORT,
  MVPP2_BM_POOL_TYPE_LONG,
} mvpp2_bm_pool_type_t;

#define MV_DSA_N_SRC	       32
#define PP2_HW_PORT_NUM_RXQS   32

struct mvpp2_port_link_info
{
  u8 up : 1;
  u8 full_duplex : 1;
  u32 speed;
};

typedef struct
{
  uintptr_t base;
  unsigned int obj_size;
} mvpp2_mac_unit_desc_t;

struct mvpp2_tc_config
{
  u16 pkt_offset;
  u8 num_in_qs;
  u8 first_rxq;
  mvpp2_bpool_t *pools[MV_SYS_DMA_MAX_NUM_MEM_ID][MVPP2_TC_MAX_BPOOLS];
  enum mvpp2_port_color default_color;
};

typedef struct
{
  struct mvpp2_tc_config tc_config;
} mvpp2_tc_t;

struct pp2_txq_config
{
  u16 size;
  enum mvpp2_txq_sched_mode sched_mode;
  u16 weight;
};

#define foreach_mv_dsa_tag_field                                              \
  _ (12, vid)                                                                 \
  _ (1, _zero13)                                                              \
  _ (3, pri)                                                                  \
  _ (1, cfi_dei)                                                              \
  _ (1, _unused17)                                                            \
  _ (1, src_is_lag)                                                           \
  _ (5, src_port_or_lag)                                                      \
  _ (5, src_dev)                                                              \
  _ (1, src_tagged)                                                           \
  _ (2, tag_type)

typedef enum
{
  MV_DSA_TAG_TYPE_TO_CPU = 0,
  MV_DSA_TAG_TYPE_FROM_CPU = 1,
  MV_DSA_TAG_TYPE_TO_SNIFFER = 2,
  MV_DSA_TAG_TYPE_FORWARD = 3
} mv_dsa_tag_type_t;

typedef enum
{
  MVPP2_PORT_DSA_ENABLED_OFF = 0,
  MVPP2_PORT_DSA_ENABLED_ON = 1,
  MVPP2_PORT_DSA_ENABLED_AUTO = 2,
} mvpp2_port_dsa_enabled_t;

typedef union
{
  struct
  {
#define _(b, n) u32 (n) : (b);
    foreach_mv_dsa_tag_field
#undef _
  };
  u32 as_u32;
} mv_dsa_tag_t;

STATIC_ASSERT_SIZEOF (mv_dsa_tag_t, 4);

static_always_inline mv_dsa_tag_t
mv_dsa_tag_read (void *p)
{
  return (mv_dsa_tag_t){ .as_u32 = clib_net_to_host_u32 (*(u32u *) p) };
}

static_always_inline void
mv_dsa_tag_write (void *p, mv_dsa_tag_t tag)
{
  ((mv_dsa_tag_t *) p)->as_u32 = clib_host_to_net_u32 (tag.as_u32);
}

typedef struct
{
  u64 rx_bytes;
  u64 rx_packets;
  u64 rx_unicast_packets;
  u64 rx_errors;
  u64 rx_fullq_dropped;
  u32 rx_bm_dropped;
  u32 rx_early_dropped;
  u32 rx_fifo_dropped;
  u32 rx_cls_dropped;
  u64 tx_bytes;
  u64 tx_packets;
  u64 tx_unicast_packets;
  u64 tx_errors;
} mvpp2_port_statistics_t;

typedef struct
{
  u64 enq_desc;
  u32 drop_fullq;
  u16 drop_early;
  u16 drop_bm;
} mvpp2_rxq_statistics_t;

typedef struct
{
  u64 enq_desc;
  u64 enq_dec_to_ddr;
  u64 enq_buf_to_ddr;
  u64 deq_desc;
} mvpp2_txq_statistics_t;

typedef struct
{
  u16 next;
  u16 n_enq;
  u32 *buffers;
  u32 hw_id;
  u32 desc_total;
  uintptr_t desc_phys_arr;
  uintptr_t hif_base;
  mvpp2_tx_desc_t *desc_virt_arr;
  u32 desc_rsrvd[MVPP2_MAX_THREADS];
  int disabled;
  mvpp2_txq_statistics_t stats;
} mvpp2_txq_t;

typedef struct
{
  u32 desc_total;
  u32 free_count;
  u32 desc_next_idx;
  mvpp2_tx_desc_t *descs;
} mvpp2_dm_if_t;

typedef struct
{
  mvpp2_rx_desc_t *desc_ptrs[VLIB_FRAME_SIZE];
  mvpp2_tx_desc_t bpool_desc_template;
  u16 n_bpool_refill;
  u32 hw_id;
  u32 desc_total;
  uintptr_t desc_phys_arr;
  u32 bm_pool_id[MVPP2_TC_MAX_BPOOLS];
  u32 desc_received;
  u32 desc_next_idx;
  mvpp2_rx_desc_t *hw_descs;
  mvpp2_rxq_statistics_t stats;
} mvpp2_rxq_t;

typedef struct
{
  u32 hif_id;
  uintptr_t hif_base;
  mvpp2_dm_if_t dm_if;
} mvpp2_dev_thread_t;

typedef struct
{
  u16 hw_tbl;
  u16 num_in_q;
} mvpp2_rss_tbl_map_t;

typedef struct
{
  u8 pp_id;
  u8 lbk_is_initialized : 1;
  u8 classifier_initialized : 1;
  u16 free_bpools;
  u16 hif_reserved_map;
  u16 bm_pool_reserved_map;
  uintptr_t pp_base;
  mvpp2_mac_unit_desc_t gop_hw_gmac;
  mvpp2_mac_unit_desc_t gop_hw_xlg_mac;
  uintptr_t gop_hw_mspg;
  uintptr_t cm3_base;
  mvpp2_tx_desc_t *lbk_desc_virt_arr;
  u32 lbk_desc_rsrvd[MVPP2_MAX_THREADS];
  struct mv_pp2x_prs_shadow *prs_shadow;
  mvpp2_rss_tbl_map_t rss_tbl_map[MVPP22_RSS_TBL_NUM];
  u32 num_rss_tables;
  mvpp2_bpool_t dummy_short_bpool;
  mvpp2_dev_thread_t threads[MVPP2_MAX_THREADS];
} mvpp2_device_t;

static_always_inline uintptr_t
mvpp2_hif_base (mvpp2_device_t *md, u32 id)
{
  ASSERT (id < MVPP2_NUM_HIFS);
  return md->pp_base + id * MVPP2_REGSPACE_SIZE;
}

static_always_inline u32
mvpp2_reg_read (uintptr_t base, u32 offset)
{
  volatile u32 *addr = (void *) (base + offset);
  u32 value;

  value = __atomic_load_n (addr, __ATOMIC_RELAXED);
  asm volatile ("dsb ld" : : : "memory");
  return value;
}

static_always_inline void
mvpp2_reg_write (uintptr_t base, u32 offset, u32 value)
{
  volatile u32 *addr = (void *) (base + offset);

  asm volatile ("dsb st" : : : "memory");
  __atomic_store_n (addr, value, __ATOMIC_RELAXED);
}

typedef struct
{
  u8 addr[6];
} mvpp2_uc_addr_t;

typedef struct
{
  u8 is_enabled : 1;
  u8 is_dsa : 1;
  u8 rss_en : 1;
  u8 tx_pause_en : 1;
  u8 rx_pause_en : 1;
  u8 is_xlg : 1;
  u8 is_open;
  u8 gop_index;
  u32 id;
  u32 if_index;
  struct pp2_txq_config txq_config[MVPP2_PORT_MAX_TX_QUEUES];
  u32 num_tcs;
  u32 first_rxq;
  mvpp2_port_statistics_t stats;
  uintptr_t hif_base;
  char *phy_mode;
  mvpp2_tc_t tc;
  enum mvpp2_port_hash_type hash_type;
  mvpp2_uc_addr_t *added_uc_addrs;
  u32 num_added_mc_addr;
  u32 saved_rx_isr[PP2_MAX_NUM_USED_INTERRUPTS];
  struct ethtool_gstrings *stats_name;
  struct mvpp2_port_link_info last_link_info;
  mvpp2_bpool_t bpool;
  clib_dt_node_t *switch_node;
  clib_dt_node_t *switch_port_node;

  uword valid_dsa_src_bitmap[1024 / uword_bits];
  u16 dsa_to_sec_if[1024];
} mvpp2_port_t;

static_always_inline char *
mvpp2_port_ifname (vnet_dev_port_t *port, char ifname[IFNAMSIZ])
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  if (if_indextoname (mp->if_index, ifname) == 0)
    ifname[0] = 0;
  return ifname;
}

static_always_inline u32
mvpp2_port_id (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  return mp->id;
}

/* classifier.c */
void mvpp2_cls_mng_init (vnet_dev_t *);
void mvpp2_cls_mng_config_default_cos_queue (vnet_dev_port_t *);
int mvpp2_cls_mng_modify_default_flows (vnet_dev_port_t *, int);
vnet_dev_rv_t mvpp2_cls_rss_enable (vnet_dev_port_t *, int);
void mvpp2x_cls_oversize_rxq_set (vnet_dev_port_t *);

/* parser.c */
vnet_dev_rv_t mvpp2_parser_init (vnet_dev_t *);
void mvpp2_port_clear_prs_vlans (vnet_dev_port_t *);
int mvpp2_port_flush_mac_addrs (vnet_dev_port_t *, u32, u32);
int mvpp2_parser_eth_start_header_set (vnet_dev_port_t *, enum mvpp2_port_eth_start_hdr);
vnet_dev_rv_t mvpp2_port_set_mac_addr (vnet_dev_port_t *, const eth_addr_t);
vnet_dev_rv_t mvpp2_port_add_mac_addr (vnet_dev_port_t *, const eth_addr_t);
vnet_dev_rv_t mvpp2_port_remove_mac_addr (vnet_dev_port_t *, const eth_addr_t);
vnet_dev_rv_t mvpp2_port_set_promisc (vnet_dev_port_t *, int);

/* rss.c */
void mvpp2_rss_port_init (vnet_dev_port_t *);

/* bpool.c */
vnet_dev_rv_t mvpp2_bpool_init (mvpp2_bpool_params_t *, mvpp2_bpool_t *);
void mvpp2_bpool_deinit (vlib_main_t *, vnet_dev_t *, mvpp2_bpool_t *);
vnet_dev_rv_t mvpp2_bpool_get_buff (vlib_main_t *, vnet_dev_t *, mvpp2_bpool_t *,
				    mvpp2_buff_info_t *);
void mvpp2_bm_flush_pools (vnet_dev_t *, uintptr_t, u16);
void mvpp2_bm_pool_assign (vnet_dev_port_t *, u32, u32, mvpp2_bm_pool_type_t);

/* loopback.c */
vnet_dev_rv_t mvpp2_loopback_init (vnet_dev_t *);
vnet_dev_rv_t mvpp2_loopback_deinit (vnet_dev_t *);

/* netdev.c */
vnet_dev_rv_t mvpp2_netdev_ioctl (vnet_dev_t *, u32, struct ifreq *);
vnet_dev_rv_t mvpp2_netdev_set_enable (vnet_dev_port_t *, int);
vnet_dev_rv_t mvpp2_netdev_set_priv_flags (vnet_dev_port_t *, u32);
vnet_dev_rv_t mvpp2_netdev_set_vlan_filtering (vnet_dev_port_t *, int);
vnet_dev_rv_t mvpp2_netdev_clear_vlan (vnet_dev_port_t *, u16);
vnet_dev_rv_t mvpp2_netdev_clear_kernel_unicast (vnet_dev_port_t *);

typedef struct
{
  mvpp2_rx_desc_t desc;
  u32 sw_if_index;
  u16 next_index;
  mv_dsa_tag_t dsa_tag;
} mvpp2_rx_trace_t;

/* counters.c */
void mvpp2_port_add_counters (vlib_main_t *, vnet_dev_port_t *);
void mvpp2_port_counters_init (vnet_dev_port_t *);
void mvpp2_port_counters_deinit (vnet_dev_port_t *);
void mvpp2_port_clear_counters (vlib_main_t *, vnet_dev_port_t *);
void mvpp2_rxq_clear_counters (vlib_main_t *, vnet_dev_rx_queue_t *);
void mvpp2_txq_clear_counters (vlib_main_t *, vnet_dev_tx_queue_t *);
vnet_dev_rv_t mvpp2_port_get_stats (vlib_main_t *, vnet_dev_port_t *);

/* flow_control.c */
void mvpp2_port_clear_fc_isr (vnet_dev_port_t *);
void mvpp2_port_interrupts_disable (vnet_dev_port_t *);
void mvpp2_port_rxqs_fc_state_reset (vnet_dev_port_t *);
void mvpp2_port_restore_fc_isr (vnet_dev_port_t *);

/* format.c */
format_function_t format_mvpp2_port_link_info;
format_function_t format_mvpp2_port_status;
format_function_t format_mvpp2_dev_info;
format_function_t format_mvpp2_rx_trace;
format_function_t format_mvpp2_rx_desc;
format_function_t format_mv_dsa_tag;

/* gop.c */
vnet_dev_rv_t mvpp2_gop_get_link_info (vnet_dev_port_t *, struct mvpp2_port_link_info *);
void mvpp2_gop_max_rx_size_set (vnet_dev_port_t *);

/* hif.c */
vnet_dev_rv_t mvpp2_hif_init (vlib_main_t *, vnet_dev_t *, u32, u8, u32);
void mvpp2_hif_deinit (vlib_main_t *, vnet_dev_t *, u32);

/* port.c */
vnet_dev_port_op_t mvpp2_port_init;
vnet_dev_port_op_no_rv_t mvpp2_port_deinit;
vnet_dev_port_op_t mvpp2_port_start;
vnet_dev_port_op_no_rv_t mvpp2_port_stop;
vnet_dev_port_op_with_ptr_t mvpp2_port_add_sec_if;
vnet_dev_port_op_with_ptr_t mvpp2_port_del_sec_if;
vnet_dev_rv_t mvpp2_port_set_rx_pause (vnet_dev_port_t *, int);
vnet_dev_rv_t mvpp2_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
				     vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t
mvpp2_port_cfg_change_validate (vlib_main_t *, vnet_dev_port_t *,
				vnet_dev_port_cfg_change_req_t *);

/* queue.c */
vnet_dev_tx_queue_op_t mvpp2_txq_alloc;
vnet_dev_tx_queue_op_no_rv_t mvpp2_txq_free;

/* rx_queue.c */
void mvpp2_rxqs_create (vnet_dev_port_t *);
void mvpp2_rxq_init (vnet_dev_rx_queue_t *);
void mvpp2_rxq_deinit (vnet_dev_rx_queue_t *);

/* tx_queue.c */
void mvpp2_txq_init (vnet_dev_tx_queue_t *);
void mvpp2_port_txq_deinit (vnet_dev_tx_queue_t *);
vnet_dev_rv_t mvpp2_port_set_txq_state (vnet_dev_tx_queue_t *, int);

/* tx_sched.c */
vnet_dev_rv_t mvpp2_tx_sched_config (vnet_dev_port_t *);

/* inline funcs */

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, mvpp2_log.class, "%U" f,                    \
	    format_vnet_dev_log, (dev),                                       \
	    clib_string_skip_prefix (__func__, "mvpp2_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_INFO, mvpp2_log.class, "%U" f,                     \
	    format_vnet_dev_log, (dev), 0, ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, mvpp2_log.class, "%U" f,                   \
	    format_vnet_dev_log, (dev), 0, ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, mvpp2_log.class, "%U" f,                  \
	    format_vnet_dev_log, (dev), 0, ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, mvpp2_log.class, "%U" f, format_vnet_dev_log, \
	    (dev), 0, ##__VA_ARGS__)

#define foreach_mvpp2_tx_node_counter                                                              \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx slots")                                      \
  _ (SEND, send, ERROR, "send errors")                                                             \
  _ (GET_NUM_TX_DONE, get_num_tx_done, ERROR, "get number of completed tx errors")

typedef enum
{
#define _(f, n, s, d) MVPP2_TX_NODE_CTR_##f,
  foreach_mvpp2_tx_node_counter
#undef _
} mvpp2_tx_node_counter_t;

#define foreach_mvpp2_rx_node_counter                                                              \
  _ (BPOOL_GET_NUM_BUFFS, bpool_get_num_bufs, ERROR, "mvpp2_bpool_get_num_buffs error")            \
  _ (BUFFER_ALLOC, buffer_alloc, ERROR, "buffer alloc error")                                      \
  _ (UNKNOWN_DSA_SRC, unknown_dsa_src, ERROR, "unknown DSA source")                                \
  _ (MAC_CE, mac_ce, ERROR, "MAC error (CRC error)")                                               \
  _ (MAC_OR, mac_or, ERROR, "overrun error")                                                       \
  _ (MAC_RSVD, mac_rsvd, ERROR, "unknown MAC error")                                               \
  _ (MAC_RE, mac_re, ERROR, "resource error")                                                      \
  _ (IP_HDR, ip_hdr, ERROR, "ip4 header error")

typedef enum
{
#define _(f, n, s, d) MVPP2_RX_NODE_CTR_##f,
  foreach_mvpp2_rx_node_counter
#undef _
} mvpp2_rx_node_counter_t;

u32 mrvl_pp2_bpool_put_no_inline (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);

#endif /* _PP2_H_ */
