/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#ifndef _AVF_H_
#define _AVF_H_

#include <avf/virtchnl.h>

#include <vlib/log.h>

#include <vnet/devices/devices.h>
#include <vnet/flow/flow.h>

#define AVF_QUEUE_SZ_MAX                4096
#define AVF_QUEUE_SZ_MIN                64

#define AVF_AQ_ENQ_SUSPEND_TIME		50e-6
#define AVF_AQ_ENQ_MAX_WAIT_TIME	250e-3

#define AVF_RESET_SUSPEND_TIME		20e-3
#define AVF_RESET_MAX_WAIT_TIME		1

#define AVF_SEND_TO_PF_SUSPEND_TIME	10e-3
#define AVF_SEND_TO_PF_MAX_WAIT_TIME	1

#define AVF_RXD_STATUS(x)		(1ULL << x)
#define AVF_RXD_STATUS_DD		AVF_RXD_STATUS(0)
#define AVF_RXD_STATUS_EOP		AVF_RXD_STATUS(1)
#define AVF_RXD_ERROR_SHIFT		19
#define AVF_RXD_PTYPE_SHIFT		30
#define AVF_RXD_LEN_SHIFT		38
#define AVF_RX_MAX_DESC_IN_CHAIN	5

#define AVF_RXD_ERROR_IPE		(1ULL << (AVF_RXD_ERROR_SHIFT + 3))
#define AVF_RXD_ERROR_L4E		(1ULL << (AVF_RXD_ERROR_SHIFT + 4))

#define AVF_TXD_CMD(x)			(1 << (x + 4))
#define AVF_TXD_CMD_EXT(x, val)         ((u64)val << (x + 4))
#define AVF_TXD_CMD_EOP			AVF_TXD_CMD(0)
#define AVF_TXD_CMD_RS			AVF_TXD_CMD(1)
#define AVF_TXD_CMD_RSV			AVF_TXD_CMD(2)

#define AVF_TXD_CMD_IIPT_NONE           AVF_TXD_CMD_EXT(5, 0)
#define AVF_TXD_CMD_IIPT_IPV6           AVF_TXD_CMD_EXT(5, 1)
#define AVF_TXD_CMD_IIPT_IPV4_NO_CSUM   AVF_TXD_CMD_EXT(5, 2)
#define AVF_TXD_CMD_IIPT_IPV4           AVF_TXD_CMD_EXT(5, 3)

#define AVF_TXD_CMD_L4T_UNKNOWN         AVF_TXD_CMD_EXT(8, 0)
#define AVF_TXD_CMD_L4T_TCP             AVF_TXD_CMD_EXT(8, 1)
#define AVF_TXD_CMD_L4T_SCTP            AVF_TXD_CMD_EXT(8, 2)
#define AVF_TXD_CMD_L4T_UDP             AVF_TXD_CMD_EXT(8, 3)

#define AVF_TXD_OFFSET(x,factor,val)    (((u64)val/(u64)factor) << (16 + x))
#define AVF_TXD_OFFSET_MACLEN(val)      AVF_TXD_OFFSET( 0, 2, val)
#define AVF_TXD_OFFSET_IPLEN(val)       AVF_TXD_OFFSET( 7, 4, val)
#define AVF_TXD_OFFSET_L4LEN(val)       AVF_TXD_OFFSET(14, 4, val)

extern vlib_log_class_registration_t avf_log;

#define avf_log_err(dev, f, ...)                        \
  vlib_log (VLIB_LOG_LEVEL_ERR, avf_log.class, "%U: " f, \
            format_vlib_pci_addr, &dev->pci_addr, \
            ## __VA_ARGS__)

#define avf_log_warn(dev, f, ...)                        \
  vlib_log (VLIB_LOG_LEVEL_WARNING, avf_log.class, "%U: " f, \
            format_vlib_pci_addr, &dev->pci_addr, \
            ## __VA_ARGS__)

#define avf_log_debug(dev, f, ...)                        \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, avf_log.class, "%U: " f, \
            format_vlib_pci_addr, &dev->pci_addr, \
            ## __VA_ARGS__)

#define foreach_avf_device_flags \
  _(0, INITIALIZED, "initialized") \
  _(1, ERROR, "error") \
  _(2, ADMIN_UP, "admin-up") \
  _(3, VA_DMA, "vaddr-dma") \
  _(4, LINK_UP, "link-up") \
  _(5, SHARED_TXQ_LOCK, "shared-txq-lock") \
  _(6, ELOG, "elog") \
  _(7, PROMISC, "promisc") \
  _(8, RX_INT, "rx-interrupts") \
  _(9, RX_FLOW_OFFLOAD, "rx-flow-offload") \

enum
{
#define _(a, b, c) AVF_DEVICE_F_##b = (1 << a),
  foreach_avf_device_flags
#undef _
};

typedef volatile struct
{
  union
  {
    struct
    {
      u64 mirr:13;
      u64 rsv1:3;
      u64 l2tag1:16;
      u64 filter_status:32;
      u64 status:19;
      u64 error:8;
      u64 rsv2:3;
      u64 ptype:8;
      u64 length:26;
    };
    u64 qword[4];
#ifdef CLIB_HAVE_VEC256
    u64x4 as_u64x4;
#endif
  };
} avf_rx_desc_t;

STATIC_ASSERT_SIZEOF (avf_rx_desc_t, 32);

typedef volatile struct
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
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 *qrx_tail;
  u16 next;
  u16 size;
  avf_rx_desc_t *descs;
  u32 *bufs;
  u16 n_enqueued;
  u8 int_mode;
  u8 buffer_pool_index;
} avf_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 *qtx_tail;
  u16 next;
  u16 size;
  clib_spinlock_t lock;
  avf_tx_desc_t *descs;
  u32 *bufs;
  u16 n_enqueued;
  u16 *rs_slots;
} avf_txq_t;

typedef struct
{
  u32 flow_index;
  u32 mark;
  struct iavf_fdir_conf *rcfg;
} avf_flow_entry_t;

typedef struct
{
  u32 flow_id;
  u16 next_index;
  i16 buffer_advance;
} avf_flow_lookup_entry_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 flags;
  u32 per_interface_next_index;

  u32 dev_instance;
  u32 sw_if_index;
  u32 hw_if_index;
  vlib_pci_dev_handle_t pci_dev_handle;
  u32 numa_node;
  void *bar0;
  u8 *name;

  /* queues */
  avf_rxq_t *rxqs;
  avf_txq_t *txqs;
  u16 n_tx_queues;
  u16 n_rx_queues;

  /* Admin queues */
  avf_aq_desc_t *atq;
  avf_aq_desc_t *arq;
  void *atq_bufs;
  void *arq_bufs;
  u64 atq_bufs_pa;
  u64 arq_bufs_pa;
  u16 atq_next_slot;
  u16 arq_next_slot;
  virtchnl_pf_event_t *events;

  u16 vsi_id;
  u32 feature_bitmap;
  u8 hwaddr[6];
  u16 num_queue_pairs;
  u16 max_vectors;
  u16 n_rx_irqs;
  u16 max_mtu;
  u32 rss_key_size;
  u32 rss_lut_size;
  virtchnl_link_speed_t link_speed;
  vlib_pci_addr_t pci_addr;

  /* flow */
  avf_flow_entry_t *flow_entries;	/* pool */
  avf_flow_lookup_entry_t *flow_lookup_entries;	/* pool */

  /* stats */
  virtchnl_eth_stats_t eth_stats;
  virtchnl_eth_stats_t last_cleared_eth_stats;

  /* error */
  clib_error_t *error;
} avf_device_t;

#define AVF_RX_VECTOR_SZ VLIB_FRAME_SIZE

typedef enum
{
  AVF_PROCESS_EVENT_START = 1,
  AVF_PROCESS_EVENT_DELETE_IF = 2,
  AVF_PROCESS_EVENT_AQ_INT = 3,
  AVF_PROCESS_EVENT_REQ = 4,
} avf_process_event_t;

typedef enum
{
  AVF_PROCESS_REQ_ADD_DEL_ETH_ADDR = 1,
  AVF_PROCESS_REQ_CONFIG_PROMISC_MDDE = 2,
  AVF_PROCESS_REQ_GENERAL_VC = 3,
} avf_process_req_type_t;

typedef struct
{
  avf_process_req_type_t type;
  u32 dev_instance;
  u32 calling_process_index;
  u8 eth_addr[6];
  int is_add, is_enable;

  /* used for general virtchannel event */
  virtchnl_ops_t event_op;
  u8 *in;
  u32 in_len;
  u8 *out;
  u32 out_len;

  clib_error_t *error;
} avf_process_req_t;

typedef struct
{
  u64 qw1s[AVF_RX_MAX_DESC_IN_CHAIN - 1];
  u32 buffers[AVF_RX_MAX_DESC_IN_CHAIN - 1];
} avf_rx_tail_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_buffer_t *bufs[AVF_RX_VECTOR_SZ];
  u64 qw1s[AVF_RX_VECTOR_SZ];
  avf_rx_tail_t tails[AVF_RX_VECTOR_SZ];
  vlib_buffer_t buffer_template;
} avf_per_thread_data_t;

typedef struct
{
  u16 msg_id_base;

  avf_device_t **devices;
  avf_per_thread_data_t *per_thread_data;
} avf_main_t;

extern avf_main_t avf_main;

typedef struct
{
  vlib_pci_addr_t addr;
  u8 *name;
  int enable_elog;
  u16 rxq_num;
  u16 rxq_size;
  u16 txq_size;
  /* return */
  int rv;
  u32 sw_if_index;
  clib_error_t *error;
} avf_create_if_args_t;

void avf_create_if (vlib_main_t * vm, avf_create_if_args_t * args);

extern vlib_node_registration_t avf_input_node;
extern vlib_node_registration_t avf_process_node;
extern vnet_device_class_t avf_device_class;

int
avf_flow_ops_fn (vnet_main_t * vnm, vnet_flow_dev_op_t op, u32 dev_instance,
		 u32 flow_index, uword * private_data);

clib_error_t *avf_general_virtchnl_event_request (u32 dev_instance,
						  virtchnl_ops_t op,
						  u8 * in, u32 in_len,
						  u8 * out, u32 out_len);


/* format.c */
format_function_t format_avf_device;
format_function_t format_avf_device_name;
format_function_t format_avf_input_trace;
vnet_flow_dev_ops_function_t avf_flow_ops_fn;

static_always_inline avf_device_t *
avf_get_device (u32 dev_instance)
{
  return pool_elt_at_index (avf_main.devices, dev_instance)[0];
}

static inline u32
avf_get_u32 (void *start, int offset)
{
  return *(u32 *) (((u8 *) start) + offset);
}

static inline u64
avf_get_u64 (void *start, int offset)
{
  return *(u64 *) (((u8 *) start) + offset);
}

static inline u32
avf_get_u32_bits (void *start, int offset, int first, int last)
{
  u32 value = avf_get_u32 (start, offset);
  if ((last == 0) && (first == 31))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

static inline u64
avf_get_u64_bits (void *start, int offset, int first, int last)
{
  u64 value = avf_get_u64 (start, offset);
  if ((last == 0) && (first == 63))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

static inline void
avf_set_u32 (void *start, int offset, u32 value)
{
  (*(u32 *) (((u8 *) start) + offset)) = value;
}

static inline void
avf_reg_write (avf_device_t * ad, u32 addr, u32 val)
{
  *(volatile u32 *) ((u8 *) ad->bar0 + addr) = val;
}

static inline u32
avf_reg_read (avf_device_t * ad, u32 addr)
{
  return *(volatile u32 *) (ad->bar0 + addr);
}

static inline void
avf_reg_flush (avf_device_t * ad)
{
  avf_reg_read (ad, AVFGEN_RSTAT);
  asm volatile ("":::"memory");
}

static_always_inline int
avf_rxd_is_not_eop (avf_rx_desc_t * d)
{
  return (d->qword[1] & AVF_RXD_STATUS_EOP) == 0;
}

static_always_inline int
avf_rxd_is_not_dd (avf_rx_desc_t * d)
{
  return (d->qword[1] & AVF_RXD_STATUS_DD) == 0;
}

typedef struct
{
  u16 qid;
  u16 next_index;
  u32 hw_if_index;
  u64 qw1s[AVF_RX_MAX_DESC_IN_CHAIN];
} avf_input_trace_t;

#define foreach_avf_tx_func_error	       \
  _(SEGMENT_SIZE_EXCEEDED, "segment size exceeded")	\
  _(NO_FREE_SLOTS, "no free tx slots")

typedef enum
{
#define _(f,s) AVF_TX_ERROR_##f,
  foreach_avf_tx_func_error
#undef _
    AVF_TX_N_ERROR,
} avf_tx_func_error_t;

#endif /* AVF_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
