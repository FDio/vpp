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

#ifndef _IGB_H_
#define _IGB_H_

#include <vlib/log.h>

#define IGB_AQ_ENQ_SUSPEND_TIME		50e-6
#define IGB_AQ_ENQ_MAX_WAIT_TIME	250e-3

#define IGB_RESET_SUSPEND_TIME		20e-3
#define IGB_RESET_MAX_WAIT_TIME		1

#define IGB_SEND_TO_PF_SUSPEND_TIME	10e-3
#define IGB_SEND_TO_PF_MAX_WAIT_TIME	1

#define IGB_RXD_STATUS(x)		(1ULL << x)
#define IGB_RXD_STATUS_DD		IGB_RXD_STATUS(0)
#define IGB_RXD_STATUS_EOP		IGB_RXD_STATUS(1)
#define IGB_RXD_ERROR_SHIFT		19
#define IGB_RXD_PTYPE_SHIFT		30
#define IGB_RXD_LEN_SHIFT		38
#define IGB_RX_MAX_DESC_IN_CHAIN	5

#define IGB_RXD_ERROR_IPE		(1ULL << (IGB_RXD_ERROR_SHIFT + 3))
#define IGB_RXD_ERROR_L4E		(1ULL << (IGB_RXD_ERROR_SHIFT + 4))

#define IGB_TXD_CMD(x)			(1 << (x + 4))
#define IGB_TXD_CMD_EOP			IGB_TXD_CMD(0)
#define IGB_TXD_CMD_RS			IGB_TXD_CMD(1)
#define IGB_TXD_CMD_RSV			IGB_TXD_CMD(2)

#define igb_log_err(dev, f, ...)                        \
  vlib_log (VLIB_LOG_LEVEL_ERR, igb_main.log_class, "%U: " f, \
            format_vlib_pci_addr, &dev->pci_addr, \
            ## __VA_ARGS__)

#define igb_log_warn(dev, f, ...)                        \
  vlib_log (VLIB_LOG_LEVEL_WARNING, igb_main.log_class, "%U: " f, \
            format_vlib_pci_addr, &dev->pci_addr, \
            ## __VA_ARGS__)

#define igb_log_debug(dev, f, ...)                        \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, igb_main.log_class, "%U: " f, \
            format_vlib_pci_addr, &dev->pci_addr, \
            ## __VA_ARGS__)

#define foreach_igb_device_flags \
  _(0, INITIALIZED, "initialized") \
  _(1, ERROR, "error") \
  _(2, ADMIN_UP, "admin-up") \
  _(3, VA_DMA, "vaddr-dma") \
  _(4, LINK_UP, "link-up") \
  _(5, SHARED_TXQ_LOCK, "shared-txq-lock") \
  _(6, ELOG, "elog") \
  _(7, PROMISC, "promisc")

enum
{
#define _(a, b, c) IGB_DEVICE_F_##b = (1 << a),
  foreach_igb_device_flags
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
} igb_rx_desc_t;

STATIC_ASSERT_SIZEOF (igb_rx_desc_t, 32);

typedef volatile struct
{
  union
  {
    u64 qword[2];
#ifdef CLIB_HAVE_VEC128
    u64x2 as_u64x2;
#endif
  };
} igb_tx_desc_t;

STATIC_ASSERT_SIZEOF (igb_tx_desc_t, 16);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 *qrx_tail;
  u16 next;
  u16 size;
  igb_rx_desc_t *descs;
  u32 *bufs;
  u16 n_enqueued;
  u8 int_mode;
  u8 buffer_pool_index;
} igb_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 *qtx_tail;
  u16 next;
  u16 size;
  clib_spinlock_t lock;
  igb_tx_desc_t *descs;
  u32 *bufs;
  u16 n_enqueued;
  u16 *rs_slots;
} igb_txq_t;

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
  igb_rxq_t *rxqs;
  igb_txq_t *txqs;
  u16 n_tx_queues;
  u16 n_rx_queues;

  u8 hwaddr[6];
  vlib_pci_addr_t pci_addr;

  /* error */
  clib_error_t *error;
} igb_device_t;

#define IGB_RX_VECTOR_SZ VLIB_FRAME_SIZE

typedef enum
{
  IGB_PROCESS_EVENT_START = 1,
  IGB_PROCESS_EVENT_STOP = 2,
  IGB_PROCESS_EVENT_AQ_INT = 3,
} igb_process_event_t;

typedef struct
{
  u64 qw1s[IGB_RX_MAX_DESC_IN_CHAIN - 1];
  u32 buffers[IGB_RX_MAX_DESC_IN_CHAIN - 1];
} igb_rx_tail_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_buffer_t *bufs[IGB_RX_VECTOR_SZ];
  u64 qw1s[IGB_RX_VECTOR_SZ];
  igb_rx_tail_t tails[IGB_RX_VECTOR_SZ];
  vlib_buffer_t buffer_template;
} igb_per_thread_data_t;

typedef struct
{
  u16 msg_id_base;

  igb_device_t *devices;
  igb_per_thread_data_t *per_thread_data;

  vlib_log_class_t log_class;
} igb_main_t;

extern igb_main_t igb_main;

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
} igb_create_if_args_t;

void igb_create_if (vlib_main_t * vm, igb_create_if_args_t * args);
void igb_delete_if (vlib_main_t * vm, igb_device_t * ad);

extern vlib_node_registration_t igb_input_node;
extern vnet_device_class_t igb_device_class;

/* format.c */
format_function_t format_igb_device;
format_function_t format_igb_device_name;
format_function_t format_igb_input_trace;

static inline u32
igb_get_u32 (void *start, int offset)
{
  return *(u32 *) (((u8 *) start) + offset);
}

static inline u64
igb_get_u64 (void *start, int offset)
{
  return *(u64 *) (((u8 *) start) + offset);
}

static inline u32
igb_get_u32_bits (void *start, int offset, int first, int last)
{
  u32 value = igb_get_u32 (start, offset);
  if ((last == 0) && (first == 31))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

static inline u64
igb_get_u64_bits (void *start, int offset, int first, int last)
{
  u64 value = igb_get_u64 (start, offset);
  if ((last == 0) && (first == 63))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

static inline void
igb_set_u32 (void *start, int offset, u32 value)
{
  (*(u32 *) (((u8 *) start) + offset)) = value;
}

static inline void
igb_reg_write (igb_device_t * ad, u32 addr, u32 val)
{
  *(volatile u32 *) ((u8 *) ad->bar0 + addr) = val;
}

static inline u32
igb_reg_read (igb_device_t * ad, u32 addr)
{
  return *(volatile u32 *) (ad->bar0 + addr);
}

typedef struct
{
  u16 qid;
  u16 next_index;
  u32 hw_if_index;
  u64 qw1s[IGB_RX_MAX_DESC_IN_CHAIN];
} igb_input_trace_t;

#define foreach_igb_tx_func_error	       \
  _(SEGMENT_SIZE_EXCEEDED, "segment size exceeded")	\
  _(NO_FREE_SLOTS, "no free tx slots")

typedef enum
{
#define _(f,s) IGB_TX_ERROR_##f,
  foreach_igb_tx_func_error
#undef _
    IGB_TX_N_ERROR,
} igb_tx_func_error_t;

#endif /* IGB_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
