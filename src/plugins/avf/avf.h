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

#include <avf/virtchnl.h>

#define foreach_avf_device_flags \
  _(0, INITIALIZED, "initialized") \
  _(1, ERROR, "error") \
  _(2, ADMIN_UP, "admin-up")

enum
{
#define _(a, b, c) AVF_DEVICE_F_##b = (1 << a),
  foreach_avf_device_flags
#undef _
};

typedef struct
{
  u64 qword[4];
} avf_rx_desc_t;

STATIC_ASSERT_SIZEOF (avf_rx_desc_t, 32);

typedef struct
{
  union
  {
    u64 qword[2];
    u64x2 as_u64x2;
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
  u16 n_bufs;
} avf_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 *qtx_tail;
  u16 next;
  u16 size;
  avf_tx_desc_t *descs;
  u32 *bufs;
  u16 n_bufs;
} avf_txq_t;

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

  /* queues */
  avf_rxq_t *rxqs;
  avf_txq_t *txqs;

  /* Admin queues */
  avf_aq_desc_t *atq;
  avf_aq_desc_t *arq;
  void *atq_bufs;
  void *arq_bufs;
  u64 atq_bufs_pa;
  u64 arq_bufs_pa;
  u16 atq_next_slot;
  u16 arq_next_slot;

  u16 vsi_id;
  u32 feature_bitmap;
  u8 hwaddr[6];

  /* stats */
  virtchnl_eth_stats_t eth_stats;

  /* error */
  clib_error_t *error;
} avf_device_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
} avf_per_thread_data_t;

typedef struct
{
  avf_device_t *devices;
  avf_per_thread_data_t *per_thread_data;
  vlib_physmem_region_index_t physmem_region;
} avf_main_t;

extern avf_main_t avf_main;

typedef struct
{
  vlib_pci_addr_t addr;
  /* return */
  int rv;
  clib_error_t *error;
} avf_create_if_args_t;

void avf_create_if (avf_create_if_args_t * args);
void avf_delete_if (avf_device_t * ad);

extern vlib_node_registration_t avf_input_node;
extern vnet_device_class_t avf_device_class;
uword avf_interface_tx (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * frame);

/* format.c */
format_function_t format_avf_device;
format_function_t format_avf_device_name;
format_function_t format_avf_input_trace;

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

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  avf_rx_desc_t desc;
} avf_input_trace_t;

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
