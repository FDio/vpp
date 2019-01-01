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

#ifndef _RGE_H_
#define _RGE_H_

#include <vlib/log.h>

#define foreach_rge_device_flags \
  _(0, INITIALIZED, "initialized") \
  _(1, ERROR, "error") \
  _(2, ADMIN_UP, "admin-up") \
  _(3, VA_DMA, "vaddr-dma") \
  _(4, LINK_UP, "link-up") \
  _(5, SHARED_TXQ_LOCK, "shared-txq-lock") \
  _(6, ELOG, "elog")

enum
{
#define _(a, b, c) RGE_DEVICE_F_##b = (1 << a),
  foreach_rge_device_flags
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
} rge_rx_desc_t;

STATIC_ASSERT_SIZEOF (rge_rx_desc_t, 32);

typedef volatile struct
{
  union
  {
    u64 qword[2];
#ifdef CLIB_HAVE_VEC128
    u64x2 as_u64x2;
#endif
  };
} rge_tx_desc_t;

STATIC_ASSERT_SIZEOF (rge_tx_desc_t, 16);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 *qrx_tail;
  u16 next;
  u16 size;
  rge_rx_desc_t *descs;
  u32 *bufs;
  u16 n_enqueued;
  u8 int_mode;
} rge_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 *qtx_tail;
  u16 next;
  u16 size;
  clib_spinlock_t lock;
  rge_tx_desc_t *descs;
  u32 *bufs;
  u16 n_enqueued;
  u16 *rs_slots;
} rge_txq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 flags;
  u32 per_interface_next_index;

  u32 dev_instance;
  u32 sw_if_index;
  u32 hw_if_index;
  vlib_pci_dev_handle_t pci_dev_handle;
  void *bar0;
  u8 *name;
  u8 hwaddr[6];
  char *type;

  /* queues */
  rge_rxq_t *rxqs;
  rge_txq_t *txqs;
  u16 n_tx_queues;
  u16 n_rx_queues;

  /* error */
  clib_error_t *error;
} rge_device_t;

#define RGE_RX_VECTOR_SZ VLIB_FRAME_SIZE

typedef enum
{
  RGE_PROCESS_EVENT_START = 1,
  RGE_PROCESS_EVENT_STOP = 2,
  RGE_PROCESS_EVENT_AQ_INT = 3,
} rge_process_event_t;

typedef struct
{
  u16 msg_id_base;

  rge_device_t *devices;

  vlib_log_class_t log_class;
} rge_main_t;

extern rge_main_t rge_main;

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
} rge_create_if_args_t;

void rge_create_if (vlib_main_t * vm, rge_create_if_args_t * args);
void rge_delete_if (vlib_main_t * vm, rge_device_t * ad);

extern vlib_node_registration_t rge_input_node;
extern vnet_device_class_t rge_device_class;

/* format.c */
format_function_t format_rge_device;
format_function_t format_rge_device_name;
format_function_t format_rge_input_trace;

static inline u32
rge_get_u32 (void *start, int offset)
{
  return *(u32 *) (((u8 *) start) + offset);
}

static inline u64
rge_get_u64 (void *start, int offset)
{
  return *(u64 *) (((u8 *) start) + offset);
}

static inline u32
rge_get_u32_bits (void *start, int offset, int first, int last)
{
  u32 value = rge_get_u32 (start, offset);
  if ((last == 0) && (first == 31))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

static inline u64
rge_get_u64_bits (void *start, int offset, int first, int last)
{
  u64 value = rge_get_u64 (start, offset);
  if ((last == 0) && (first == 63))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

static inline void
rge_set_u32 (void *start, int offset, u32 value)
{
  (*(u32 *) (((u8 *) start) + offset)) = value;
}

static inline void
rge_reg_write (rge_device_t * ad, u32 addr, u32 val)
{
  *(volatile u32 *) ((u8 *) ad->bar0 + addr) = val;
}

static inline u32
rge_reg_read (rge_device_t * ad, u32 addr)
{
  return *(volatile u32 *) (ad->bar0 + addr);
}

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
} rge_input_trace_t;

#define foreach_rge_tx_func_error	       \
_(NO_FREE_SLOTS, "no free tx slots")

typedef enum
{
#define _(f,s) RGE_TX_ERROR_##f,
  foreach_rge_tx_func_error
#undef _
    RGE_TX_N_ERROR,
} rge_tx_func_error_t;

#endif /* RGE_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
