/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vlib/dma/dma.h>
#include <vlib/log.h>

#define MEMIF_DEFAULT_SOCKET_FILENAME  "memif.sock"
#define MEMIF_DEFAULT_RING_SIZE 1024
#define MEMIF_DEFAULT_RX_QUEUES 1
#define MEMIF_DEFAULT_TX_QUEUES 1
#define MEMIF_DEFAULT_BUFFER_SIZE 2048

#define MEMIF_MAX_M2S_RING		256
#define MEMIF_MAX_S2M_RING		256
#define MEMIF_MAX_REGION		256
#define MEMIF_MAX_LOG2_RING_SIZE	14


#define memif_log_debug(dev, f, ...) do {                               \
  memif_if_t *_dev = (memif_if_t *) dev;                                \
  if (_dev)                                                             \
    vlib_log(VLIB_LOG_LEVEL_DEBUG, memif_main.log_class, "%U: " f,      \
	     format_vnet_hw_if_index_name, vnet_get_main(),             \
	     _dev->hw_if_index, ##__VA_ARGS__);                         \
  else                                                                  \
    vlib_log(VLIB_LOG_LEVEL_DEBUG, memif_main.log_class, f,             \
             ##__VA_ARGS__);                                            \
} while (0)

#define memif_log_warn(dev, f, ...) do {                                \
  memif_if_t *_dev = (memif_if_t *) dev;                                \
  if (_dev)                                                             \
    vlib_log(VLIB_LOG_LEVEL_WARNING, memif_main.log_class, "%U: " f,    \
	     format_vnet_hw_if_index_name, vnet_get_main(),             \
	     _dev->hw_if_index, ##__VA_ARGS__);                         \
  else                                                                  \
    vlib_log(VLIB_LOG_LEVEL_WARNING, memif_main.log_class, f,           \
             ##__VA_ARGS__);                                            \
} while (0)

#define memif_log_err(dev, f, ...) do {                                 \
  memif_if_t *_dev = (memif_if_t *) dev;                                \
  if (_dev)                                                             \
    vlib_log(VLIB_LOG_LEVEL_ERR, memif_main.log_class, "%U: " f,        \
	     format_vnet_hw_if_index_name, vnet_get_main(),             \
	     _dev->hw_if_index, ##__VA_ARGS__);                         \
  else                                                                  \
    vlib_log(VLIB_LOG_LEVEL_ERR, memif_main.log_class, f,               \
             ##__VA_ARGS__);                                            \
} while (0)

#define memif_file_add(a, b)                                                  \
  do                                                                          \
    {                                                                         \
      *a = clib_file_add (&file_main, b);                                     \
      memif_log_debug (0, "clib_file_add fd %d private_data %u idx %u",       \
		       (b)->file_descriptor, (b)->private_data, *a);          \
    }                                                                         \
  while (0)

#define memif_file_del(a)                                                     \
  do                                                                          \
    {                                                                         \
      memif_log_debug (0, "clib_file_del idx %u", (a)->index);                \
      clib_file_del (&file_main, a);                                          \
    }                                                                         \
  while (0)

#define memif_file_del_by_index(a)                                            \
  do                                                                          \
    {                                                                         \
      memif_log_debug (0, "clib_file_del idx %u", a);                         \
      clib_file_del_by_index (&file_main, a);                                 \
    }                                                                         \
  while (0)

typedef struct
{
  u8 *filename;
  u32 socket_id;
  clib_socket_t *sock;
  clib_socket_t **pending_clients;
  int ref_cnt;
  int is_listener;

  /* hash of all registered id */
  mhash_t dev_instance_by_id;

  /* hash of all registered fds */
  uword *dev_instance_by_fd;
} memif_socket_file_t;

typedef struct
{
  /* Required for vec_validate_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  void *shm;
  memif_region_size_t region_size;
  int fd;
  u8 is_external;
} memif_region_t;

typedef struct
{
  memif_msg_t msg;
  int fd;
} memif_msg_fifo_elt_t;

#define MEMIF_RX_VECTOR_SZ  VLIB_FRAME_SIZE
#define MEMIF_DMA_INFO_SIZE VLIB_FRAME_SIZE

struct memif_dma_info;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_spinlock_t lockp;
  /* ring data */
  memif_ring_t *ring;
  memif_log2_ring_size_t log2_ring_size;
  memif_region_index_t region;
  memif_region_offset_t offset;

  u16 last_head;
  u16 last_tail;
  u32 *buffers;
  u8 buffer_pool_index;

  /* dma data */
  u16 dma_head;
  u16 dma_tail;
  struct memif_dma_info *dma_info;
  u16 dma_info_head;
  u16 dma_info_tail;
  u16 dma_info_size;
  u8 dma_info_full;

  /* packets received or sent */
  u64 n_packets;
  u64 no_free_tx;
  u32 max_no_free_tx;

  /* interrupts */
  int int_fd;
  uword int_clib_file_index;
  u64 int_count;

  /* queue type */
  memif_ring_type_t type;
  u32 queue_index;
} memif_queue_t;

#define foreach_memif_if_flag                                                 \
  _ (0, ADMIN_UP, "admin-up")                                                 \
  _ (1, IS_SLAVE, "slave")                                                    \
  _ (2, CONNECTING, "connecting")                                             \
  _ (3, CONNECTED, "connected")                                               \
  _ (4, DELETING, "deleting")                                                 \
  _ (5, ZERO_COPY, "zero-copy")                                               \
  _ (6, ERROR, "error")                                                       \
  _ (7, USE_DMA, "use_dma")

typedef enum
{
#define _(a, b, c) MEMIF_IF_FLAG_##b = (1 << a),
  foreach_memif_if_flag
#undef _
} memif_if_flag_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 flags;
  memif_interface_id_t id;
  u32 hw_if_index;
  u32 sw_if_index;
  uword dev_instance;
  memif_interface_mode_t mode:8;

  u32 per_interface_next_index;

  /* socket connection */
  clib_socket_t *sock;
  uword socket_file_index;
  memif_msg_fifo_elt_t *msg_queue;
  u8 *secret;

  memif_region_t *regions;

  memif_queue_t *rx_queues;
  memif_queue_t *tx_queues;

  /* remote info */
  u8 *remote_name;
  u8 *remote_if_name;

  struct
  {
    memif_log2_ring_size_t log2_ring_size;
    u8 num_s2m_rings;
    u8 num_m2s_rings;
    u16 buffer_size;
  } cfg;

  struct
  {
    memif_log2_ring_size_t log2_ring_size;
    u8 num_s2m_rings;
    u8 num_m2s_rings;
    u16 buffer_size;
  } run;

  /* disconnect strings */
  u8 *local_disc_string;
  u8 *remote_disc_string;

  /* dma config index */
  int dma_input_config;
  int dma_tx_config;
} memif_if_t;

typedef struct
{
  u16 packet_len;
  u16 first_buffer_vec_index;
} memif_packet_op_t;

typedef struct
{
  CLIB_ALIGN_MARK (pad, 16);	/* align up to 16 bytes for 32bit builds */
  void *data;
  u32 data_len;
  i16 buffer_offset;
  u16 buffer_vec_index;
} memif_copy_op_t;

typedef enum
{
  MEMIF_DESC_STATUS_OK = 0,
  MEMIF_DESC_STATUS_ERR_BAD_REGION,
  MEMIF_DESC_STATUS_ERR_REGION_OVERRUN,
  MEMIF_DESC_STATUS_ERR_DATA_TOO_BIG,
  MEMIF_DESC_STATUS_ERR_ZERO_LENGTH
} __clib_packed memif_desc_status_err_code_t;

typedef union
{
  struct
  {
    u8 next : 1;
    u8 err : 1;
    u8 reserved : 2;
    memif_desc_status_err_code_t err_code : 4;
  };
  u8 as_u8;
} memif_desc_status_t;

STATIC_ASSERT_SIZEOF (memif_desc_status_t, 1);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u16 n_packets;
  u16 max_desc_len;
  u32 n_rx_bytes;
  u8 xor_status;
  /* copy vector */
  memif_copy_op_t *copy_ops;
  u32 *buffers;
  memif_packet_op_t packet_ops[MEMIF_RX_VECTOR_SZ];

  /* temp storage for compressed descriptors */
  void **desc_data;
  u16 *desc_len;
  memif_desc_status_t *desc_status;

  /* buffer template */
  vlib_buffer_t buffer_template;
} memif_per_thread_data_t;

typedef struct memif_dma_info
{
  /* per thread data */
  memif_interface_mode_t mode;
  vlib_node_runtime_t *node;
  u32 dma_head;
  u32 dma_tail;
  u8 finished;
  memif_per_thread_data_t data;
} memif_dma_info_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /** API message ID base */
  u16 msg_id_base;

  /* pool of all memory interfaces */
  memif_if_t *interfaces;

  /* pool of all unix socket files */
  memif_socket_file_t *socket_files;
  uword *socket_file_index_by_sock_id;	/* map user socket id to pool idx */

  /* per thread data */
  memif_per_thread_data_t *per_thread_data;

  vlib_log_class_t log_class;

} memif_main_t;

extern memif_main_t memif_main;
extern vnet_device_class_t memif_device_class;
extern vlib_node_registration_t memif_input_node;

typedef enum
{
  MEMIF_PROCESS_EVENT_START = 1,
  MEMIF_PROCESS_EVENT_STOP = 2,
  MEMIF_PROCESS_EVENT_ADMIN_UP_DOWN = 3,
} memif_process_event_t;

typedef struct
{
  memif_interface_id_t id;
  u32 socket_id;
  u8 *secret;
  u8 is_master;
  u8 is_zero_copy;
  u8 use_dma;
  memif_interface_mode_t mode:8;
  memif_log2_ring_size_t log2_ring_size;
  u16 buffer_size;
  u8 hw_addr_set;
  u8 hw_addr[6];
  u8 rx_queues;
  u8 tx_queues;

  /* return */
  u32 sw_if_index;
} memif_create_if_args_t;

u32 memif_get_unused_socket_id ();
clib_error_t *memif_socket_filename_add_del (u8 is_add, u32 sock_id,
					     char *sock_filename);
clib_error_t *memif_create_if (vlib_main_t *vm, memif_create_if_args_t *args);
clib_error_t *memif_delete_if (vlib_main_t *vm, memif_if_t *mif);
clib_error_t *memif_plugin_api_hookup (vlib_main_t * vm);
clib_error_t *memif_interface_admin_up_down (vnet_main_t *vnm, u32 hw_if_index,
					     u32 flags);

static_always_inline void *
memif_get_buffer (memif_if_t * mif, memif_ring_t * ring, u16 slot)
{
  u16 region = ring->desc[slot].region;
  return mif->regions[region].shm + ring->desc[slot].offset;
}

/* memif.c */
clib_error_t *memif_init_regions_and_queues (memif_if_t * mif);
clib_error_t *memif_connect (memif_if_t * mif);
void memif_disconnect (memif_if_t * mif, clib_error_t * err);

/* socket.c */
void memif_socket_close (clib_socket_t ** sock);
clib_error_t *memif_conn_fd_accept_ready (clib_file_t * uf);
clib_error_t *memif_master_conn_fd_read_ready (clib_file_t * uf);
clib_error_t *memif_slave_conn_fd_read_ready (clib_file_t * uf);
clib_error_t *memif_master_conn_fd_write_ready (clib_file_t * uf);
clib_error_t *memif_slave_conn_fd_write_ready (clib_file_t * uf);
clib_error_t *memif_master_conn_fd_error (clib_file_t * uf);
clib_error_t *memif_slave_conn_fd_error (clib_file_t * uf);
clib_error_t *memif_msg_send_disconnect (memif_if_t * mif,
					 clib_error_t * err);
u8 *format_memif_device_name (u8 * s, va_list * args);
void memif_dma_completion_cb (vlib_main_t *vm, vlib_dma_batch_t *b);
void memif_tx_dma_completion_cb (vlib_main_t *vm, vlib_dma_batch_t *b);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
