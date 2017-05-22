#ifndef _MEMIF_LIB_PRIV_H_
#define _MEMIF_LIB_PRIV_H_

#include "memif_lib.h"
#include "memif_lib_vec.h"

/* TODO: define for different architectures */
#define CACHE_LINE_BYTES (1 << 6)

#define MEMIF_DEFAULT_SOCKET_DIR "/run/vpp"
#define MEMIF_DEFAULT_SOCKET_FILENAME  "memif.sock"
#define MEMIF_DEFAULT_RING_SIZE 1024
#define MEMIF_DEFAULT_RX_QUEUES 1
#define MEMIF_DEFAULT_TX_QUEUES 1
#define MEMIF_DEFAULT_BUFFER_SIZE 2048*1024

#define MEMIF_MAX_FDS 512

#define MEMIF_VERSION_MAJOR 0
#define MEMIF_VERSION_MINOR 1
#define MEMIF_VERSION ((MEMIF_VERSION_MAJOR << 8) | MEMIF_VERSION_MINOR)
#define MEMIF_COOKIE 0xdeadbeef

#define MEMIF_DEBUG 1

#if MEMIF_DEBUG == 1
#define DEBUG_LOG(...) printf("DEBUG_LOG: %s:%d: ", __func__, __LINE__); \
                       printf(__VA_ARGS__);                              \
                       printf("\n")
#define DEBUG_UNIX_LOG(...) printf("DEBUG_UNIX_LOG: %s:%d: ", __func__, __LINE__); \
                            printf(__VA_ARGS__);                                   \
                            printf("\n");
#endif

typedef struct
{
  uint8_t *filename;
  int fd;
  uint64_t memif_file_index;
  uint64_t *pending_file_indices;
  int ref_cnt;
  int is_listener;

  /* hash of all registered keys */
  /*ash_t dev_instance_by_key;*/

  /* hash of all registered fds */
  uint64_t *dev_instance_by_fd;
} memif_socket_file_t;

typedef struct
{
  void *shm;
  uint32_t region_size;
  int fd;
} memif_region_t;

typedef struct
{
  /* ring data */
  memif_ring_t *ring;
  uint8_t log2_ring_size;
  uint8_t region;
  uint32_t offset;

  uint16_t last_head;
  uint16_t last_tail;

  /* interrupts */
  uint8_t recv_mode;
  int int_fd;
  uint64_t int_memif_file_index;
} memif_queue_t;

struct memif_attributes
{
    uint8_t log2_ring_size;
    uint8_t num_s2m_rings;
    uint8_t num_m2s_rings;
    uint64_t buffer_size;
};

typedef struct
{
  /*CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_spinlock_t lockp;*/
  uint32_t flags;
#define MEMIF_IF_FLAG_ADMIN_UP   (1 << 0)
#define MEMIF_IF_FLAG_IS_SLAVE   (1 << 1)
#define MEMIF_IF_FLAG_CONNECTING (1 << 2)
#define MEMIF_IF_FLAG_CONNECTED  (1 << 3)
#define MEMIF_IF_FLAG_DELETING   (1 << 4)

  uint64_t key;
  /*u32 hw_if_index;*/
  /*u32 sw_if_index;*/
  uint64_t dev_instance;

  uint32_t per_interface_next_index;

  /* socket connection */
  uint64_t socket_file_index;
  int conn_fd;
  uint64_t conn_memif_file_index;


  memif_region_t *regions;

  memif_queue_t *rx_queues;
  memif_queue_t *tx_queues;

  /* remote info */
  pid_t remote_pid;
  uid_t remote_uid;
  gid_t remote_gid;

  struct memif_attributes cfg;
  struct memif_attributes run;

/*
  struct
  {
    uint8_t log2_ring_size;
    uint8_t num_s2m_rings;
    uint8_t num_m2s_rings;
    uint64_t buffer_size;
  } cfg;

  struct
  {
    uint8_t log2_ring_size;
    uint8_t num_s2m_rings;
    uint8_t num_m2s_rings;
    uint64_t buffer_size;
  } run;
*/

} memif_if_t;

typedef void *(memif_function_t) (memif_if_t *mif);

typedef void *(memif_function_data_t) (memif_if_t *mif, struct iovec **iov, uint32_t rx);

typedef struct
{
  /*CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);*/

  uint8_t recv_mode;
#define MEMIF_MM_RECV_MODE_POLL  (0)
#define MEMIF_MM_RECV_MODE_INT   (1)

  /** API message ID base */
  uint16_t msg_id_base;

  /* pool of all memory interfaces */
  memif_if_t *interfaces;

  /* pool of all unix socket files */
  memif_socket_file_t *socket_files;

  /*mhash_t socket_file_index_by_filename;*/

  /* rx buffer cache */
  uint32_t **rx_buffers;

  uint16_t *int_ifs;

  memif_function_t *on_connect, *on_disconnect, *on_interrupt;
  memif_function_data_t *on_incoming_data;

  memif_file_t *files;
} memif_main_t;

typedef struct
{
    uint64_t key;
    uint8_t *socket_filename;
    uint8_t is_master;
    uint8_t log2_ring_size;
    uint64_t buffer_size;
    uint8_t rx_queues;
    uint8_t tx_queues;
} memif_create_args_t;

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

memif_main_t * dump_memif_main ();

memif_if_t * memif_dump (uint64_t if_index);

memif_if_t * get_if_by_key (uint64_t key);

void memif_file_del (memif_file_t * mf);

void memif_file_del_by_index (uint64_t mf_index);

int memif_file_add (memif_file_t * mf);

void memif_bring_up (uint64_t if_index);

void memif_bring_down (uint64_t if_index);

void memif_disconnect (memif_if_t * mif);

int memif_connect (memif_if_t * mif);

int memif_init_regions_and_queues (memif_if_t * mif);

memif_main_t * memif_init (uint8_t recv_mode, memif_function_t *on_connect,
                            memif_function_t *on_disconnect,
                            memif_function_data_t *on_incoming_data,
                            memif_function_t *on_interrupt);

void epoll_init ();

int memif_delete (memif_if_t * mif);

uint64_t memif_create (memif_create_args_t *args);

int memif_send (uint64_t if_index);

int memif_recv (uint64_t if_index, struct iovec **iov, uint32_t iov_arr_len);

int memif_loop_run (int timeout);

void * memif_on_interrupt (memif_if_t * mif);

void memif_msg_send_recv_mode (memif_if_t * mif);

void memif_set_mode (uint8_t recv_mode);

static inline int
memfd_create (const char *name, unsigned int flags)
{
  return syscall (__NR_memfd_create, name, flags);
}

static inline void *
memif_get_buffer (memif_if_t * mif, memif_ring_t * ring, uint16_t slot)
{
  uint16_t region = ring->desc[slot].region;
  return mif->regions[region].shm + ring->desc[slot].offset;
}

static inline void *
memif_alloc_buffer (memif_if_t * mif, uint32_t buffer_size)
{
    /* mif->run | mif->cfg */
    uint8_t qid = 0;
    memif_queue_t *mq = (memif_queue_t *) vec_get_at_index (qid, mif->tx_queues);
    memif_ring_t *ring = mq->ring;
    uint16_t align_offset = CACHE_LINE_BYTES - (buffer_size % CACHE_LINE_BYTES);
    buffer_size += align_offset;
    uint16_t mask = (1 << mq->log2_ring_size) - 1;
    uint16_t h = (ring->head + ring->head_offset) & mask;
    if (ring->tail > ring->head)
    {
        if (ring->head_offset >= ring->tail - ring->head)
            return NULL;
    }
    else
    {
        if (ring->head_offset >= mask - ring->head + ring->tail)
            return NULL;
    }
 
    void *region = mif->regions[mq->region].shm;

    void *next_alloc = region + ring->desc[h].offset;


    if ((next_alloc + buffer_size) > (region + ring->buffer_offset + mif->run.buffer_size)){
        if ((region + ring->buffer_offset + buffer_size) >
            (region + ring->desc[ring->tail].offset)){
            return NULL;
        }
        ring->desc[h].offset = ring->buffer_offset;
    }
    else
    {
        if (next_alloc < (region + ring->desc[ring->tail].offset)){
            if ((next_alloc + buffer_size) > (region + ring->desc[ring->tail].offset)){
                return NULL;
            }
        }
    }
    ring->desc[h].buffer_length = buffer_size;
    ring->head_offset++;
    ring->desc[(h + 1) & mask].offset =
        ring->desc[h].offset + ring->desc[h].buffer_length;
    return region + ring->desc[h].offset;
}

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif
#define MFD_ALLOW_SEALING       0x0002U
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_SEAL_SEAL     0x0001  /* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002  /* prevent file from shrinking */
#define F_SEAL_GROW     0x0004  /* prevent file from growing */
#define F_SEAL_WRITE    0x0008  /* prevent writes */

/* memif.c */
int memif_init_regions_and_queues (memif_if_t * mif);
int memif_connect (memif_if_t * mif);
void memif_disconnect (memif_if_t * mif);

/* socket.c */
void *memif_conn_fd_accept_ready (memif_file_t * mf);
void *memif_master_conn_fd_read_ready (memif_file_t * mf);
void *memif_slave_conn_fd_read_ready (memif_file_t * mf);
void *memif_master_conn_fd_error (memif_file_t * mf);
void *memif_slave_conn_fd_error (memif_file_t * mf);

#endif
