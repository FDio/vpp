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

#define MEMIF_DEFAULT_SOCKET_DIR "/run/vpp"
#define MEMIF_DEFAULT_SOCKET_FILENAME  "memif.sock"
#define MEMIF_DEFAULT_RING_SIZE 1024
#define MEMIF_DEFAULT_RX_QUEUES 1
#define MEMIF_DEFAULT_TX_QUEUES 1
#define MEMIF_DEFAULT_BUFFER_SIZE 2048

#define MEMIF_MAX_FDS 512

#define MEMIF_VERSION_MAJOR 0
#define MEMIF_VERSION_MINOR 1
#define MEMIF_VERSION ((MEMIF_VERSION_MAJOR << 8) | MEMIF_VERSION_MINOR)
#define MEMIF_COOKIE 0xdeadbeef

#define MEMIF_DEBUG 0

#if MEMIF_DEBUG == 1
#define DBG(...) clib_warning(__VA_ARGS__)
#define DBG_UNIX_LOG(...) clib_unix_warning(__VA_ARGS__)
#else
#define DBG(...)
#define DBG_UNIX_LOG(...)
#endif

#if MEMIF_DEBUG == 1
#define memif_file_add(a, b) do {					\
  ASSERT (*a == ~0);							\
  *a = unix_file_add (&unix_main, b);					\
  clib_warning ("unix_file_add fd %d private_data %u idx %u",		\
		(b)->file_descriptor, (b)->private_data, *a);		\
} while (0)

#define memif_file_del(a) do {						\
  clib_warning ("unix_file_del idx %u",a - unix_main.file_pool);	\
  unix_file_del (&unix_main, a);					\
} while (0)

#define memif_file_del_by_index(a) do {					\
  clib_warning ("unix_file_del idx %u", a);				\
  unix_file_del_by_index (&unix_main, a);				\
} while (0)
#else
#define memif_file_add(a, b) do {					\
  ASSERT (*a == ~0);							\
  *a = unix_file_add (&unix_main, b);					\
} while (0)
#define memif_file_del(a) unix_file_del(&unix_main, a)
#define memif_file_del_by_index(a) unix_file_del_by_index(&unix_main, a)
#endif

typedef struct
{
  u8 *filename;
  int fd;
  uword unix_file_index;
  uword *pending_file_indices;
  int ref_cnt;
  int is_listener;

  /* hash of all registered keys */
  mhash_t dev_instance_by_key;

  /* hash of all registered fds */
  uword *dev_instance_by_fd;
} memif_socket_file_t;

typedef struct
{
  void *shm;
  u32 region_size;
  int fd;
} memif_region_t;

typedef struct
{
  /* ring data */
  memif_ring_t *ring;
  u8 log2_ring_size;
  u8 region;
  u32 offset;

  u16 last_head;
  u16 last_tail;

  /* interrupts */
  int int_fd;
  uword int_unix_file_index;
  u64 int_count;
} memif_queue_t;

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
  u32 hw_if_index;
  u32 sw_if_index;
  uword dev_instance;

  u32 per_interface_next_index;

  /* socket connection */
  uword socket_file_index;
  int conn_fd;
  uword conn_unix_file_index;


  memif_region_t *regions;

  memif_queue_t *rx_queues;
  memif_queue_t *tx_queues;

  /* remote info */
  pid_t remote_pid;
  uid_t remote_uid;
  gid_t remote_gid;

  struct
  {
    u8 log2_ring_size;
    u8 num_s2m_rings;
    u8 num_m2s_rings;
    u16 buffer_size;
  } cfg;

  struct
  {
    u8 log2_ring_size;
    u8 num_s2m_rings;
    u8 num_m2s_rings;
    u16 buffer_size;
  } run;

} memif_if_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /** API message ID base */
  u16 msg_id_base;

  /* pool of all memory interfaces */
  memif_if_t *interfaces;

  /* pool of all unix socket files */
  memif_socket_file_t *socket_files;
  mhash_t socket_file_index_by_filename;

  /* rx buffer cache */
  u32 **rx_buffers;

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
  u8 rx_queues;
  u8 tx_queues;

  /* return */
  u32 sw_if_index;
} memif_create_if_args_t;

int memif_create_if (vlib_main_t * vm, memif_create_if_args_t * args);
int memif_delete_if (vlib_main_t * vm, memif_if_t * mif);
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

static_always_inline void *
memif_get_buffer (memif_if_t * mif, memif_ring_t * ring, u16 slot)
{
  u16 region = ring->desc[slot].region;
  return mif->regions[region].shm + ring->desc[slot].offset;
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

/* memif.c */
clib_error_t *memif_init_regions_and_queues (memif_if_t * mif);
clib_error_t *memif_connect (memif_if_t * mif);
void memif_disconnect (memif_if_t * mif);

/* socket.c */
clib_error_t *memif_conn_fd_accept_ready (unix_file_t * uf);
clib_error_t *memif_master_conn_fd_read_ready (unix_file_t * uf);
clib_error_t *memif_slave_conn_fd_read_ready (unix_file_t * uf);
clib_error_t *memif_master_conn_fd_error (unix_file_t * uf);
clib_error_t *memif_slave_conn_fd_error (unix_file_t * uf);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
