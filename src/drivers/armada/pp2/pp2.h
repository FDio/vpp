/* SPDX-License-Identifier: Apache-2.0
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

#include <musdk.h>

struct ethtool_gstrings;
struct pp2_dm_if;
struct pp2_inst;
struct pp2_ppio_sg_pkts;
struct pp2_tx_queue;

struct pp2_dm_if *pp2_dm_if_get (struct pp2_port *, struct pp2_hif *);
struct pp2_tx_queue *pp2_port_txq_get (struct pp2_port *, u8);
u16 pp2_port_enqueue (struct pp2_port *, struct pp2_dm_if *, u8, u16, struct pp2_ppio_desc[],
		      struct pp2_ppio_sg_pkts *);

#define MVCONF_DBG_LEVEL	       0
#define MVCONF_PP2_BPOOL_COOKIE_SIZE   32
#define MVCONF_PP2_BPOOL_DMA_ADDR_SIZE 64
#define MVCONF_DMA_PHYS_ADDR_T_SIZE    64
#define MVCONF_SYS_DMA_UIO
#define MVCONF_TYPES_PUBLIC
#define MVCONF_DMA_PHYS_ADDR_T_PUBLIC

#define MVPP2_NUM_HIFS	       9
#define MVPP2_NUM_BPOOLS       16
#define MVPP2_MAX_THREADS      4
#define MRVL_PP2_BUFF_BATCH_SZ 32
#define MV_DSA_N_SRC	       32

struct pp2_desc
{
  u32 cmd0;
  u32 cmd1;
  u32 cmd2;
  u32 cmd3;
  u32 cmd4;
  u32 cmd5;
  u32 cmd6;
  u32 cmd7;
};

struct pp2_hif
{
  vlib_main_t *vm;
  int regspace_slot;
  struct pp2_ppio_desc *rel_descs;
};

struct pp2_dm_if
{
  u32 id;
  u32 desc_total;
  u32 free_count;
  u32 desc_next_idx;
  uintptr_t desc_phys_arr;
  struct pp2_desc *desc_virt_arr;
  struct pp2_inst *parent;
  uintptr_t cpu_slot;
};

struct pp2_txq_dm_if
{
  u32 desc_rsrvd;
};

struct pp2_tx_queue
{
  u32 id;
  u32 log_id;
  u32 desc_total;
  uintptr_t desc_phys_arr;
  struct pp2_desc *desc_virt_arr;
  struct pp2_txq_dm_if txq_dm_if[MVPP2_NUM_HIFS];
  int disabled;
};

struct pp2_ppio_sg_pkts
{
  u16 num;
  u8 *frags;
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
  u8 pp_id;
  u16 free_bpools;
  struct pp2_bpool *dummy_short_bpool;
  struct pp2_hif *hif[MVPP2_NUM_HIFS];
} mvpp2_device_t;

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
  u8 is_enabled : 1;
  u8 is_dsa : 1;
  struct pp2_port *pp_port;
  int uio_port_fd;
  u32 id;
  u16 port_mru;
  u16 port_mtu;
  mvpp2_port_statistics_t stats;
  uintptr_t cpu_slot;
  char linux_name[16];
  struct ethtool_gstrings *stats_name;
  struct pp2_ppio_link_info last_link_info;
  struct pp2_bpool *bpool;
  clib_dt_node_t *switch_node;
  clib_dt_node_t *switch_port_node;

  uword valid_dsa_src_bitmap[1024 / uword_bits];
  u16 dsa_to_sec_if[1024];
} mvpp2_port_t;

typedef struct
{
  u16 next;
  u16 n_enq;
  u32 *buffers;
  u32 log_id;
  mvpp2_txq_statistics_t stats;
} mvpp2_txq_t;

typedef struct
{
  struct pp2_ppio_desc descs[VLIB_FRAME_SIZE];
  struct pp2_ppio_desc *desc_ptrs[VLIB_FRAME_SIZE];
  struct buff_release_entry bre[MRVL_PP2_BUFF_BATCH_SZ];
  u16 n_bpool_refill;
  u32 hw_id;
  u32 desc_total;
  u32 desc_received;
  u32 desc_next_idx;
  struct pp2_ppio_desc *hw_descs;
  mvpp2_rxq_statistics_t stats;
} mvpp2_rxq_t;

typedef struct
{
  struct pp2_ppio_desc desc;
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

/* format.c */
format_function_t format_pp2_ppio_link_info;
format_function_t format_mvpp2_port_status;
format_function_t format_mvpp2_dev_info;
format_function_t format_mvpp2_rx_trace;
format_function_t format_mvpp2_rx_desc;
format_function_t format_mv_dsa_tag;

/* port.c */
vnet_dev_port_op_t mvpp2_port_init;
vnet_dev_port_op_no_rv_t mvpp2_port_deinit;
vnet_dev_port_op_t mvpp2_port_start;
vnet_dev_port_op_no_rv_t mvpp2_port_stop;
vnet_dev_port_op_with_ptr_t mvpp2_port_add_sec_if;
vnet_dev_port_op_with_ptr_t mvpp2_port_del_sec_if;
vnet_dev_rv_t mvpp2_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
				     vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t
mvpp2_port_cfg_change_validate (vlib_main_t *, vnet_dev_port_t *,
				vnet_dev_port_cfg_change_req_t *);

/* queue.c */
vnet_dev_tx_queue_op_t mvpp2_txq_alloc;
vnet_dev_tx_queue_op_no_rv_t mvpp2_txq_free;

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

#define foreach_mvpp2_tx_node_counter                                         \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx slots")                 \
  _ (PPIO_SEND, ppio_semd, ERROR, "pp2_ppio_send errors")                     \
  _ (PPIO_GET_NUM_OUTQ_DONE, ppio_get_num_outq_done, ERROR,                   \
     "pp2_ppio_get_num_outq_done errors")

typedef enum
{
#define _(f, n, s, d) MVPP2_TX_NODE_CTR_##f,
  foreach_mvpp2_tx_node_counter
#undef _
} mvpp2_tx_node_counter_t;

#define foreach_mvpp2_rx_node_counter                                         \
  _ (PPIO_RECV, ppio_recv, ERROR, "pp2_ppio_recv error")                      \
  _ (BPOOL_GET_NUM_BUFFS, bpool_get_num_bufs, ERROR,                          \
     "pp2_bpool_get_num_buffs error")                                         \
  _ (BPOOL_PUT_BUFFS, bpool_put_buffs, ERROR, "pp2_bpool_put_buffs error")    \
  _ (BUFFER_ALLOC, buffer_alloc, ERROR, "buffer alloc error")                 \
  _ (UNKNOWN_DSA_SRC, unknown_dsa_src, ERROR, "unknown DSA source")           \
  _ (MAC_CE, mac_ce, ERROR, "MAC error (CRC error)")                          \
  _ (MAC_OR, mac_or, ERROR, "overrun error")                                  \
  _ (MAC_RSVD, mac_rsvd, ERROR, "unknown MAC error")                          \
  _ (MAC_RE, mac_re, ERROR, "resource error")                                 \
  _ (IP_HDR, ip_hdr, ERROR, "ip4 header error")

typedef enum
{
#define _(f, n, s, d) MVPP2_RX_NODE_CTR_##f,
  foreach_mvpp2_rx_node_counter
#undef _
} mvpp2_rx_node_counter_t;

u32 mrvl_pp2_bpool_put_no_inline (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);

#endif /* _PP2_H_ */
