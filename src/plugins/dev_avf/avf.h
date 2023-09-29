/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _AVF_H_
#define _AVF_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_avf/virtchnl.h>

#define AVF_ITR_INT		 250
#define AVF_RX_MAX_DESC_IN_CHAIN 5

typedef struct avf_adminq_dma_mem avf_adminq_dma_mem_t;

typedef struct
{
  union
  {
    struct
    {
      u64 mirr : 13;
      u64 rsv1 : 3;
      u64 l2tag1 : 16;
      u64 filter_status : 32;
      u64 status : 19;
      u64 error : 8;
      u64 rsv2 : 3;
      u64 ptype : 8;
      u64 length : 26;

      u64 rsv3 : 64;
      u32 flex_lo;
      u32 fdid_flex_hi;
    };
    u64 qword[4];
#ifdef CLIB_HAVE_VEC256
    u64x4 as_u64x4;
#endif
  };
} avf_rx_desc_t;

STATIC_ASSERT_SIZEOF (avf_rx_desc_t, 32);

typedef struct
{
  union
  {
    u64 qword[2];
#ifdef CLIB_HAVE_VEC128
    u64x2 as_u64x2;
#endif
  };
} avf_tx_desc_t;

STATIC_ASSERT_SIZEOF (avf_tx_desc_t, 16);

typedef struct
{
  u8 adminq_active : 1;
  void *bar0;

  u16 vsi_id;
  u32 vf_cap_flags;
  u32 rss_key_size;
  u32 rss_lut_size;

  u32 avail_rxq_bmp;
  u32 avail_txq_bmp;

  /* Admin queues */
  avf_adminq_dma_mem_t *aq_mem;
  u16 atq_next_slot;
  u16 arq_next_slot;
  virtchnl_pf_event_t *events;

} avf_device_t;

typedef struct
{
  u32 flow_id;
  u16 next_index;
  i16 buffer_advance;
} avf_flow_lookup_entry_t;

typedef struct
{
  u8 link_up : 1;
  u8 admin_up : 1;
  u8 flow_offload : 1;
  u32 speed;
  avf_flow_lookup_entry_t *flow_lookup_entries;
} avf_port_t;

typedef struct
{
  u32 *qtx_tail;
  u32 *buffer_indices;
  avf_tx_desc_t *descs;
  u16 next;
  u16 n_enqueued;
  u16 *rs_slots;
  avf_tx_desc_t *tmp_descs;
  u32 *tmp_bufs;
  u32 *ph_bufs;
} avf_txq_t;

typedef struct
{
  u32 *qrx_tail;
  u32 *buffer_indices;
  avf_rx_desc_t *descs;
  u16 next;
  u16 n_enqueued;
} avf_rxq_t;

typedef struct
{
  u16 qid;
  u16 next_index;
  u32 hw_if_index;
  u32 flow_id;
  u64 qw1s[AVF_RX_MAX_DESC_IN_CHAIN];
} avf_rx_trace_t;

/* adminq.c */
vnet_dev_rv_t avf_aq_alloc (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t avf_aq_init (vlib_main_t *, vnet_dev_t *);
void avf_aq_deinit (vlib_main_t *, vnet_dev_t *);
void avf_aq_free (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t avf_aq_atq_enq (vlib_main_t *, vnet_dev_t *, avf_aq_desc_t *,
			      const u8 *, u16, f64);
int avf_aq_arq_next_acq (vlib_main_t *, vnet_dev_t *, avf_aq_desc_t **, u8 **,
			 f64);
void avf_aq_arq_next_rel (vlib_main_t *, vnet_dev_t *);
format_function_t format_virtchnl_op_name;
format_function_t format_virtchnl_status;

/* format.c */
format_function_t format_avf_vf_cap_flags;

/* port.c */
vnet_dev_rv_t avf_port_init (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t avf_port_start (vlib_main_t *, vnet_dev_port_t *);
void avf_port_stop (vlib_main_t *, vnet_dev_port_t *);

/* inline funcs */

static inline u32
avf_get_u32 (void *start, int offset)
{
  return *(u32 *) (((u8 *) start) + offset);
}

static inline void
avf_reg_write (avf_device_t *ad, u32 addr, u32 val)
{
  __atomic_store_n ((u32 *) ((u8 *) ad->bar0 + addr), val, __ATOMIC_RELEASE);
}

static inline u32
avf_reg_read (avf_device_t *ad, u32 addr)
{
  u32 val = *(volatile u32 *) (ad->bar0 + addr);
  return val;
}

static inline void
avf_reg_flush (avf_device_t *ad)
{
  avf_reg_read (ad, AVFGEN_RSTAT);
  asm volatile("" ::: "memory");
}

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, avf_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_INFO, avf_log.class, "%U: " f,                     \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, avf_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, avf_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, avf_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)

/* temp */
#define AVF_RX_VECTOR_SZ VLIB_FRAME_SIZE

typedef struct
{
  u64 qw1s[AVF_RX_MAX_DESC_IN_CHAIN - 1];
  u32 buffers[AVF_RX_MAX_DESC_IN_CHAIN - 1];
} avf_rx_tail_t;
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_buffer_t *bufs[AVF_RX_VECTOR_SZ];
  u16 next[AVF_RX_VECTOR_SZ];
  u64 qw1s[AVF_RX_VECTOR_SZ];
  u32 flow_ids[AVF_RX_VECTOR_SZ];
  avf_rx_tail_t tails[AVF_RX_VECTOR_SZ];
  vlib_buffer_t buffer_template;
} avf_per_thread_data_t;

typedef struct
{
  avf_per_thread_data_t *per_thread_data;
} avf_main_t;
extern avf_main_t avf_main;

#define foreach_avf_tx_func_error                                             \
  _ (SEGMENT_SIZE_EXCEEDED, "segment size exceeded")                          \
  _ (NO_FREE_SLOTS, "no free tx slots")

typedef enum
{
#define _(f, s) AVF_TX_ERROR_##f,
  foreach_avf_tx_func_error
#undef _
    AVF_TX_N_ERROR,
} avf_tx_func_error_t;

#endif /* _AVF_H_ */
