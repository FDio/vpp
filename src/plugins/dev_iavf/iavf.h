/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _IIAVF_H_
#define _IIAVF_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_iavf/iavf_desc.h>
#include <dev_iavf/virtchnl.h>

#define IAVF_ITR_INT		  250
#define IAVF_RX_MAX_DESC_IN_CHAIN 5
#define IAVF_MAX_RSS_KEY_SIZE	  52
#define IAVF_MAX_RSS_LUT_SIZE	  64
#define IIAVF_AQ_POLL_INTERVAL	  0.2
#define IIAVF_AQ_BUF_SIZE	  4096

typedef struct iavf_adminq_dma_mem iavf_adminq_dma_mem_t;

typedef struct
{
  u8 adminq_active : 1;
  void *bar0;

  /* Admin queues */
  iavf_adminq_dma_mem_t *aq_mem;
  u16 atq_next_slot;
  u16 arq_next_slot;
  virtchnl_pf_event_t *events;
} iavf_device_t;

typedef struct
{
  u32 flow_id;
  u16 next_index;
  i16 buffer_advance;
} iavf_flow_lookup_entry_t;

typedef struct
{
  u8 admin_up : 1;
  u8 flow_offload : 1;
  iavf_flow_lookup_entry_t *flow_lookup_entries;
  u64 intr_mode_per_rxq_bitmap;
  u32 vf_cap_flags;
  u16 vsi_id;
  u16 rss_key_size;
  u16 rss_lut_size;
  u16 num_qp;
  u16 max_vectors;
  u16 n_rx_vectors;
} iavf_port_t;

typedef struct
{
  u32 *qtx_tail;
  u32 *buffer_indices;
  iavf_tx_desc_t *descs;
  u16 next;
  u16 n_enqueued;
  u16 *rs_slots;
  iavf_tx_desc_t *tmp_descs;
  u32 *tmp_bufs;
  u32 *ph_bufs;
} iavf_txq_t;

typedef struct
{
  u32 *qrx_tail;
  u32 *buffer_indices;
  iavf_rx_desc_t *descs;
  u16 next;
  u16 n_enqueued;
} iavf_rxq_t;

typedef struct
{
  u16 qid;
  u16 next_index;
  u32 hw_if_index;
  u32 flow_id;
  u64 qw1s[IAVF_RX_MAX_DESC_IN_CHAIN];
} iavf_rx_trace_t;

/* adminq.c */
vnet_dev_rv_t iavf_aq_alloc (vlib_main_t *, vnet_dev_t *);
void iavf_aq_init (vlib_main_t *, vnet_dev_t *);
void iavf_aq_poll_on (vlib_main_t *, vnet_dev_t *);
void iavf_aq_poll_off (vlib_main_t *, vnet_dev_t *);
void iavf_aq_deinit (vlib_main_t *, vnet_dev_t *);
void iavf_aq_free (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t iavf_aq_atq_enq (vlib_main_t *, vnet_dev_t *, iavf_aq_desc_t *,
			       const u8 *, u16, f64);
int iavf_aq_arq_next_acq (vlib_main_t *, vnet_dev_t *, iavf_aq_desc_t **,
			  u8 **, f64);
void iavf_aq_arq_next_rel (vlib_main_t *, vnet_dev_t *);
format_function_t format_virtchnl_op_name;
format_function_t format_virtchnl_status;

/* format.c */
format_function_t format_iavf_vf_cap_flags;
format_function_t format_iavf_rx_trace;
format_function_t format_iavf_port_status;

/* port.c */
vnet_dev_rv_t iavf_port_init (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t iavf_port_start (vlib_main_t *, vnet_dev_port_t *);
void iavf_port_stop (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t iavf_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
				    vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t iavf_port_cfg_change_validate (vlib_main_t *, vnet_dev_port_t *,
					     vnet_dev_port_cfg_change_req_t *);

/* queue.c */
vnet_dev_rv_t iavf_rx_queue_alloc (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t iavf_tx_queue_alloc (vlib_main_t *, vnet_dev_tx_queue_t *);
vnet_dev_rv_t iavf_rx_queue_start (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t iavf_tx_queue_start (vlib_main_t *, vnet_dev_tx_queue_t *);
void iavf_rx_queue_stop (vlib_main_t *, vnet_dev_rx_queue_t *);
void iavf_tx_queue_stop (vlib_main_t *, vnet_dev_tx_queue_t *);
void iavf_rx_queue_free (vlib_main_t *, vnet_dev_rx_queue_t *);
void iavf_tx_queue_free (vlib_main_t *, vnet_dev_tx_queue_t *);

/* counter.c */
void iavf_port_poll_stats (vlib_main_t *, vnet_dev_port_t *);
void iavf_port_add_counters (vlib_main_t *, vnet_dev_port_t *);

/* inline funcs */

static inline u32
iavf_get_u32 (void *start, int offset)
{
  return *(u32 *) (((u8 *) start) + offset);
}

static inline void
iavf_reg_write (iavf_device_t *ad, u32 addr, u32 val)
{
  __atomic_store_n ((u32 *) ((u8 *) ad->bar0 + addr), val, __ATOMIC_RELEASE);
}

static inline u32
iavf_reg_read (iavf_device_t *ad, u32 addr)
{
  return __atomic_load_n ((u32 *) (ad->bar0 + addr), __ATOMIC_RELAXED);
  ;
}

static inline void
iavf_reg_flush (iavf_device_t *ad)
{
  iavf_reg_read (ad, IAVF_VFGEN_RSTAT);
  asm volatile("" ::: "memory");
}

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, iavf_log._class, "%U" f,                     \
	    format_vnet_dev_log, (dev),                                       \
	    clib_string_skip_prefix (__func__, "iavf_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_INFO, iavf_log._class, "%U: " f,                    \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, iavf_log._class, "%U: " f,                  \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, iavf_log._class, "%U: " f,                 \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, iavf_log._class, "%U: " f,                     \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)

/* temp */
#define IAVF_RX_VECTOR_SZ VLIB_FRAME_SIZE

typedef struct
{
  u64 qw1s[IAVF_RX_MAX_DESC_IN_CHAIN - 1];
  u32 buffers[IAVF_RX_MAX_DESC_IN_CHAIN - 1];
} iavf_rx_tail_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_buffer_t *bufs[IAVF_RX_VECTOR_SZ];
  u16 next[IAVF_RX_VECTOR_SZ];
  u64 qw1s[IAVF_RX_VECTOR_SZ];
  u32 flow_ids[IAVF_RX_VECTOR_SZ];
  iavf_rx_tail_t tails[IAVF_RX_VECTOR_SZ];
} iavf_rt_data_t;

#define foreach_iavf_tx_node_counter                                          \
  _ (SEG_SZ_EXCEEDED, seg_sz_exceeded, ERROR, "segment size exceeded")        \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx slots")

typedef enum
{
#define _(f, n, s, d) IAVF_TX_NODE_CTR_##f,
  foreach_iavf_tx_node_counter
#undef _
} iavf_tx_node_counter_t;

#define foreach_iavf_rx_node_counter                                          \
  _ (BUFFER_ALLOC, buffer_alloc, ERROR, "buffer alloc error")

typedef enum
{
#define _(f, n, s, d) IAVF_RX_NODE_CTR_##f,
  foreach_iavf_rx_node_counter
#undef _
} iavf_rx_node_counter_t;

#endif /* _IIAVF_H_ */
