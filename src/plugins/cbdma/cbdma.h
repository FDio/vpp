/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 */

typedef struct
{
  u32 size;
  union
  {
    u32 ctl;
    struct
    {
      u32 int_en:1;
      u32 src_snoop_dis:1;
      u32 dst_snoop_dis:1;
      u32 compl_write:1;
      u32 fence:1;
      u32 nt:1;
      u32 src_pg_brk:1;
      u32 dst_pg_brk:1;
      u32 bundle:1;
      u32 dest_dca:1;
      u32 hint:1;
      u32 rsvd2:13;
      u32 op:8;
    } ctl_f;
  };
  u64 src_addr;
  u64 dst_addr;
  u64 next_desc;
  u64 next_src_addr;
  u64 next_dst_addr;
  u64 reserved[2];
} cbdma_desc_t;

STATIC_ASSERT_SIZEOF (cbdma_desc_t, 64);

typedef struct
{
  cbdma_desc_t *desc;
  u32 next;

  u16 n_desc;
  vlib_physmem_region_index_t physmem_region;

  vlib_pci_dev_handle_t pci_dev_handle;
  void *bar;
  u8 engine;
  u8 channel;
} cbdma_channel_t;

typedef struct
{
  cbdma_channel_t *channels;
  vlib_physmem_region_index_t physmem_region;
  u8 numa_node;
} cbdma_engine_t;

typedef struct
{
  cbdma_engine_t *engines;
} cbdma_main_t;

extern cbdma_main_t cbdma_main;

#define forach_cbdma_channel_state \
  _(0, ACTIVE, "active")			\
  _(1, IDLE, "idle")				\
  _(2, SUSPENDED, "suspended")			\
  _(3, HALTED, "halted")			\
  _(4, ARMED, "armed")

typedef enum
{
#define _(a,b, str) CBDMA_CHANNEL_STATE_ ##b = a,
  forach_cbdma_channel_state
#undef _
} cbdma_channel_state_t;

static inline u32
cbdma_get_bits (void *start, int offset, int first, int last)
{
  u32 value = *((u32 *) ((u8 *) start + offset));
  if ((last == 0) && (first == 31))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

static inline void
cbdma_set_u32 (void *start, int offset, u32 value)
{
  (*(u32 *) (((u8 *) start) + offset)) = value;
}

static inline void
cbdma_set_u64 (void *start, int offset, u64 value)
{
  (*(u64 *) (((u8 *) start) + offset)) = value;
}

static inline u32
cbdma_get_u32 (void *start, int offset)
{
  return (*(u32 *) (((u8 *) start) + offset));
}

static inline u64
cbdma_get_u64 (void *start, int offset)
{
  return (*(u64 *) (((u8 *) start) + offset));
}

static inline cbdma_channel_t *
cbdma_get_channel (u8 engine, u8 channel)
{
  cbdma_main_t *cm = &cbdma_main;
  cbdma_engine_t *ce;
  cbdma_channel_t *cc;

  if (engine >= vec_len (cm->engines))
    return 0;
  ce = vec_elt_at_index (cm->engines, engine);
  if (channel >= vec_len (ce->channels))
    return 0;
  cc = vec_elt_at_index (ce->channels, channel);
  return cc->bar ? cc : 0;
}

static_always_inline cbdma_channel_state_t
cbdma_get_channel_state (cbdma_channel_t * cc)
{
  return cbdma_get_bits (cc->bar, 0x88, 2, 0);
}

static_always_inline void
cbdma_add_req (cbdma_channel_t * cc, u64 src_pa, u64 dst_pa, u32 size)
{
  cbdma_desc_t *d;
  u16 mask = cc->n_desc - 1;

  d = cc->desc + (cc->next & mask);
  d->src_addr = src_pa;
  d->dst_addr = dst_pa;
  d->size = size;
  cc->next++;
}

static_always_inline void
cbdma_run (cbdma_channel_t * cc)
{
  CLIB_MEMORY_STORE_BARRIER ();
  /* set DMACOUNT */
  cbdma_set_u32 (cc->bar, 0x86, cc->next);
}

clib_error_t *cbdma_channel_init (vlib_main_t * vm, cbdma_channel_t * cc);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
