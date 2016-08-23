/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

typedef struct
{
  u8 type;
#define MEMIF_MSG_TYPE_CONNECT 0
#define MEMIF_MSG_TYPE_DISCONNECT 1
  u8 log2_ring_size;
  u16 num_s2m_rings;
  u16 num_m2s_rings;
  u16 buffer_size;
  u32 shared_mem_size;
} memif_msg_t;

typedef struct __attribute__ ((packed))
{
  /* index of the underlying shared memory region */
  u16 region;
  /* total size of the buffer */
  u16 buffer_length;
  /* size of the currently stored packet */
  u16 length;
  /* unused */
  u8 reserved[2];
  /* buffer offset relative to the start of the shared memory segment */
  u64 offset;
  /* keep the size a multiple of cacheline size and as small as possible */
} memif_desc_t;

STATIC_ASSERT_SIZEOF (memif_desc_t, 16);

typedef struct
{
  u16 head;
  u8 pad0[CLIB_CACHE_LINE_BYTES - 2];
  u16 tail;
  u8 pad1[CLIB_CACHE_LINE_BYTES - 2];
  memif_desc_t desc[0];
} memif_ring_t;

STATIC_ASSERT_SIZEOF (memif_ring_t, CLIB_CACHE_LINE_BYTES*2);

typedef struct
{
  u32 cookie;
  u8 pad[CLIB_CACHE_LINE_BYTES - 4];
} memif_shm_t;

STATIC_ASSERT_SIZEOF (memif_shm_t, CLIB_CACHE_LINE_BYTES);

typedef struct
{
  u16 last_head;
  /* TODO: implement per-ring locking */
  volatile u32 *lockp;
} memif_ring_data_t;

typedef struct
{
  void *mem;
  u32 size;
  int fd;
} memif_region_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 *lockp;
  u32 flags;
#define MEMIF_IF_FLAG_ADMIN_UP (1 << 0)
#define MEMIF_IF_FLAG_IS_SLAVE (1 << 1)
#define MEMIF_IF_FLAG_CONNECTED (1 << 2)

  uword if_index;
  u32 hw_if_index;
  u32 sw_if_index;

  u32 per_interface_next_index;

  int sock_fd;
  int conn_fd;
  u32 sock_file_index;
  u32 conn_file_index;
  u8 *socket_file_name;

  memif_region_t *regions;

  u8 log2_ring_size;
  u8 num_s2m_rings;
  u8 num_m2s_rings;
  u16 buffer_size;

  memif_ring_data_t *ring_data;

  /* remote info */
  pid_t remote_pid;
  uid_t remote_uid;
} memif_if_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  memif_if_t *interfaces;

  /* bitmap of pending rx interfaces */
  uword *pending_input_bitmap; // TODO: interrupt mode

  /* rx buffer cache */
  u32 **rx_buffers;

  /* hash of socket file names */
  mhash_t if_index_by_sock_file_name;

  /* first cpu index */
  u32 input_cpu_first_index;

  /* total cpu count */
  u32 input_cpu_count;
} memif_main_t;

extern memif_main_t memif_main;
extern vnet_device_class_t memif_device_class;
extern vlib_node_registration_t memif_input_node;

typedef struct
{
  u8 *socket_file_name;
  u8 is_master;
  u8 log2_ring_size;

  /* return */
  u32 sw_if_index;
} memif_create_if_args_t;

int memif_create_if (vlib_main_t * vm, memif_create_if_args_t * args);
int memif_delete_if (vlib_main_t * vm, u8 * host_if_name);

typedef enum
{
  MEMIF_RING_S2M = 0,
  MEMIF_RING_M2S = 1
} memif_ring_type_t;

static_always_inline int
memif_get_ring_size(memif_if_t * mif)
{
  int ring_size =
    sizeof (memif_ring_t) +
    sizeof (memif_desc_t) * (1 << mif->log2_ring_size);
  /* add padding to fully fill up the last cache line */
  ring_size = (ring_size + (CLIB_CACHE_LINE_BYTES-1)) & ~CLIB_CACHE_LINE_BYTES;
  return ring_size;
}

static_always_inline memif_ring_t *
memif_get_ring (memif_if_t * mif, memif_ring_type_t type, u16 ring_num)
{
  if (vec_len(mif->regions) == 0)
    return NULL;

  void *p = mif->regions[0].mem; // TODO: support multiple regions
  p += sizeof (memif_shm_t);
  p += (ring_num + type * mif->num_s2m_rings) * memif_get_ring_size(mif);
  return (memif_ring_t *) p;
}

static_always_inline void *
memif_get_buffer (memif_if_t * mif, memif_ring_t * ring, u16 slot)
{
  u16 region = ring->desc[slot].region;
  return mif->regions[region].mem + ring->desc[slot].offset;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
