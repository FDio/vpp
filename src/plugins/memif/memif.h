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

#include <vppinfra/lock.h>

typedef struct
{
  u16 version;
#define MEMIF_VERSION_MAJOR 0
#define MEMIF_VERSION_MINOR 1
#define MEMIF_VERSION ((MEMIF_VERSION_MAJOR << 8) | MEMIF_VERSION_MINOR)
  u8 type;
#define MEMIF_MSG_TYPE_CONNECT_REQ  0
#define MEMIF_MSG_TYPE_CONNECT_RESP 1
#define MEMIF_MSG_TYPE_DISCONNECT   2

  /* Connection-request parameters: */
  u64 key;
  u8 log2_ring_size;
#define MEMIF_DEFAULT_RING_SIZE 1024
  u16 num_s2m_rings;
  u16 num_m2s_rings;
  u16 buffer_size;
#define MEMIF_DEFAULT_BUFFER_SIZE 2048
  u32 shared_mem_size;

  /* Connection-response parameters: */
  u8 retval;
} memif_msg_t;

typedef struct __attribute__ ((packed))
{
  u16 flags;
#define MEMIF_DESC_FLAG_NEXT (1 << 0)
  u16 region;
  u32 buffer_length;
  u32 length;;
  u8 reserved[4];
  u64 offset;
  u64 metadata;
} memif_desc_t;

STATIC_ASSERT_SIZEOF (memif_desc_t, 32);

typedef struct
{
  u16 head __attribute__ ((aligned (128)));
  u16 tail __attribute__ ((aligned (128)));
  memif_desc_t desc[0] __attribute__ ((aligned (128)));
} memif_ring_t;

typedef struct
{
  u32 cookie __attribute__ ((aligned (128)));
} memif_shm_t;


typedef struct
{
  u16 last_head;
  u16 last_tail;
} memif_ring_data_t;

typedef struct
{
  int fd;
  u32 index;
} memif_file_t;

typedef struct
{
  uword index;
  dev_t sock_dev;
  ino_t sock_ino;
  memif_file_t socket;
  u16 usage_counter;
} memif_listener_t;

typedef struct
{
  uword index;
  memif_file_t connection;
  uword listener_index;
} memif_pending_conn_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_spinlock_t lockp;
  u32 flags;
#define MEMIF_IF_FLAG_ADMIN_UP   (1 << 0)
#define MEMIF_IF_FLAG_IS_SLAVE   (1 << 1)
#define MEMIF_IF_FLAG_CONNECTING (1 << 2)
#define MEMIF_IF_FLAG_CONNECTED  (1 << 3)
#define MEMIF_IF_FLAG_DELETING   (1 << 4)

  u64 key;
  uword if_index;
  u32 hw_if_index;
  u32 sw_if_index;

  u32 per_interface_next_index;

  uword listener_index;
  memif_file_t connection;
  memif_file_t interrupt_line;
  u8 *socket_filename;

  void **regions;

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

  /** API message ID base */
  u16 msg_id_base;

  /* pool of all memory interfaces */
  memif_if_t *interfaces;

  /* pool of all listeners */
  memif_listener_t *listeners;

  /* pool of pending connections */
  memif_pending_conn_t *pending_conns;

  /* bitmap of pending rx interfaces */
  uword *pending_input_bitmap;

  /* rx buffer cache */
  u32 **rx_buffers;

  /* hash of all registered keys */
  mhash_t if_index_by_key;

  /* first cpu index */
  u32 input_cpu_first_index;

  /* total cpu count */
  u32 input_cpu_count;

  /* configuration */
  u8 *default_socket_filename;
#define MEMIF_DEFAULT_SOCKET_FILENAME  "/var/vpp/memif.sock"
} memif_main_t;

extern memif_main_t memif_main;
extern vnet_device_class_t memif_device_class;
extern vlib_node_registration_t memif_input_node;

enum
{
  MEMIF_PROCESS_EVENT_START = 1,
  MEMIF_PROCESS_EVENT_STOP = 2,
} memif_process_event_t;

typedef struct
{
  u64 key;
  u8 *socket_filename;
  u8 is_master;
  u8 log2_ring_size;
  u16 buffer_size;
  u8 hw_addr_set;
  u8 hw_addr[6];

  /* return */
  u32 sw_if_index;
} memif_create_if_args_t;

int memif_create_if (vlib_main_t * vm, memif_create_if_args_t * args);
int memif_delete_if (vlib_main_t * vm, u64 key);
void memif_disconnect (vlib_main_t * vm, memif_if_t * mif);
clib_error_t *memif_plugin_api_hookup (vlib_main_t * vm);

#ifndef __NR_memfd_create
#if defined __x86_64__
#define __NR_memfd_create 319
#elif defined __arm__
#define __NR_memfd_create 385
#elif defined __aarch64__
#define __NR_memfd_create 279
#else
#error "__NR_memfd_create unknown for this architecture"
#endif
#endif

static inline int
memfd_create (const char *name, unsigned int flags)
{
  return syscall (__NR_memfd_create, name, flags);
}

typedef enum
{
  MEMIF_RING_S2M = 0,
  MEMIF_RING_M2S = 1
} memif_ring_type_t;

static_always_inline memif_ring_t *
memif_get_ring (memif_if_t * mif, memif_ring_type_t type, u16 ring_num)
{
  if (vec_len (mif->regions) == 0)
    return NULL;
  void *p = mif->regions[0];
  int ring_size =
    sizeof (memif_ring_t) +
    sizeof (memif_desc_t) * (1 << mif->log2_ring_size);
  p += sizeof (memif_shm_t);
  p += (ring_num + type * mif->num_s2m_rings) * ring_size;

  return (memif_ring_t *) p;
}

static_always_inline void *
memif_get_buffer (memif_if_t * mif, memif_ring_t * ring, u16 slot)
{
  u16 region = ring->desc[slot].region;
  return mif->regions[region] + ring->desc[slot].offset;
}

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif
#define MFD_ALLOW_SEALING       0x0002U
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_SEAL_SEAL     0x0001	/* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002	/* prevent file from shrinking */
#define F_SEAL_GROW     0x0004	/* prevent file from growing */
#define F_SEAL_WRITE    0x0008	/* prevent writes */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
