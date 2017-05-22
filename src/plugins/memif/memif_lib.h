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

/* TODO: cleanup header file
         - sort deps
         - move vector to separate header
         - move function definitions to .c file
*/

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <stdint.h>
#include <net/if.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <limits.h>

#define CACHE_LINE_BYTES (1 << 6)
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
#if uword_bits == 64
typedef u64 uword;
#else
typedef u32 uword;
#endif

typedef struct
{
  uword *bitmap;
  u16 bitmap_len;
  ssize_t size;
  char data[0];
} vector_t;

static inline vector_t *
vec_get_hdr (void * pool)
{
    return (vector_t *) (pool - sizeof (vector_t));
}

static inline void
vec_free (void * pool)
{
    if (pool == NULL)
        return;
    vector_t *v = vec_get_hdr (pool);
    free (v);
    v = NULL;
}

static inline void *
vec_init (ssize_t size)
{
    vector_t *v = (vector_t *) malloc (sizeof (vector_t) +
                    (size * sizeof (uword) * CHAR_BIT));
    v->size = size;
    v->bitmap = (uword *) malloc (sizeof (uword));
    memset (v->bitmap, 0, sizeof (uword));
    v->bitmap_len = 1;
    return v->data;
}

static inline void *
vec_realloc (vector_t ** v)
{
    *v = (vector_t *) realloc (*v, sizeof (vector_t) +
                                ((*v)->size * sizeof (uword) * CHAR_BIT *
                                (*v)->bitmap_len + 1));
    (*v)->bitmap = (uword *) realloc ((*v)->bitmap, sizeof (uword) * 2);
    (*v)->bitmap[(*v)->bitmap_len] = 0;
    (*v)->bitmap_len++;
    
    /* TODO: error handling */
    
    return (void *) (*v)->data;
}

static inline void *
vec_get (void ** pool)
{
    vector_t *v = vec_get_hdr (*pool);
    uword i,e;
    for (e = 0; e < v->bitmap_len; e++)
    {
        if (v->bitmap[e] == ((1UL << ((sizeof (uword) * CHAR_BIT) + 1)) - 1))
        {
            *pool = vec_realloc (&v);
            continue;
        }
        for (i = 0; i < sizeof (uword) * CHAR_BIT; i++)
        {
            if (((1 << i) & v->bitmap[e]) == 0)
                {
                    v->bitmap[e] |= 1 << i;
                    return v->data + (v->size * i) +
                            (e * v->size * sizeof (uword) * CHAR_BIT);
                }
        }
    }
    return NULL;
}

static inline void *
vec_get_next (int *last_index, void * pool)
{
    vector_t *v = vec_get_hdr (pool);
    (*last_index)++;
    while (*last_index < (sizeof(uword) * CHAR_BIT))
    {
        if ((1 << *last_index) & v->bitmap[0])
            return v->data + (v->size * *last_index);
        (*last_index)++;
    }
    return NULL;
}

static inline void
vec_free_at_index (uword index, void * pool)
{
    vector_t *v = vec_get_hdr (pool);
    v->bitmap[0] &= ~(1 << index);
}

static inline void *
vec_get_at_index (uword index, void * pool)
{
    vector_t *v = vec_get_hdr (pool);
    if (index > sizeof (uword) * CHAR_BIT)
        return NULL;
    if (v->bitmap[0] & (1 << index))
        return v->data + (v->size * index);
    return NULL;
}

static inline int
vec_get_len (void * pool)
{
    return __builtin_popcount((vec_get_hdr (pool))->bitmap[0]);
}

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
#define MEMIF_MSG_TYPE_IF_MOD       3

  /* memif main flags */
  u16 flags;

  /* Connection-request parameters: */
  u64 key;
  u8 log2_ring_size;
#define MEMIF_DEFAULT_RING_SIZE 1024
  u16 num_s2m_rings;
  u16 num_m2s_rings;
  u64 buffer_size;
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
  u32 length;
  u8 reserved[4];
  u64 offset;
  u64 metadata;
} memif_desc_t;

/*STATIC_ASSERT_SIZEOF (memif_desc_t, 32);*/

typedef struct
{
  u16 head __attribute__ ((aligned (128)));
  u16 tail __attribute__ ((aligned (128)));
  u64 buffer_offset __attribute__ ((aligned (128)));
  u16 head_offset __attribute__ ((aligned (128)));
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

struct memif_file;

typedef void *(memif_file_function_t) (struct memif_file *mf);

typedef struct memif_file
{
  int fd;
  u32 index;

  uword data;
  memif_file_function_t *write_function, *read_function;
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
  /*CACHE_LINE_ALIGN_MARK (cacheline0);*/
/*  clib_spinlock_t lockp;*/
  u32 flags;
#define MEMIF_IF_FLAG_ADMIN_UP   (1 << 0)
#define MEMIF_IF_FLAG_IS_SLAVE   (1 << 1)
#define MEMIF_IF_FLAG_CONNECTING (1 << 2)
#define MEMIF_IF_FLAG_CONNECTED  (1 << 3)
#define MEMIF_IF_FLAG_DELETING   (1 << 4)
#define MEMIF_IF_FLAG_PEER_INT   (1 << 5)

  u64 key;
  uword if_index;

  u32 per_interface_next_index;

  uword listener_index;
  memif_file_t connection;
  memif_file_t interrupt_line;
  u8 *socket_filename;

  void **regions;

  u8 log2_ring_size;
  u8 num_s2m_rings;
  u8 num_m2s_rings;
  u64 buffer_size;

  memif_ring_data_t *ring_data;

  /* remote info */
  pid_t remote_pid;
  uid_t remote_uid;
} memif_if_t;

typedef void *(memif_function_t) (memif_if_t *mif);

typedef void *(memif_function_data_t) (memif_if_t *mif, struct iovec **iov, u32 rx);

typedef struct
{
/*  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);*/

  u16 flags;
#define MEMIF_MM_FLAG_IS_INT (1 << 0)

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

  /* first cpu index */
  u32 input_cpu_first_index;

  /* total cpu count */
  u32 input_cpu_count;

  /* pool of memif indexes with pending interrupts */
  u16 *int_if;

  /* configuration */
  u8 *default_socket_filename;
#define MEMIF_DEFAULT_SOCKET_FILENAME  "/var/vpp/memif.sock"

  memif_function_t *on_connect, *on_disconnect, *on_interrupt;
  memif_function_data_t *on_incoming_data;

  memif_file_t *files;
} memif_main_t;

typedef struct
{
    u64 key;
    u8 *socket_filename;
    u8 is_master;
    u8 log2_ring_size;
    u64 buffer_size;
} memif_create_args_t;

memif_main_t *dump_memif_main ();

int memif_send_conn_req (memif_if_t *mif);

void memif_close_if (memif_main_t *mm, memif_if_t *mif);

int memif_file_add (memif_file_t *mf);

void memif_file_del (memif_file_t *mf);

void poll_event (int timeout);

void epoll_init ();

void *memif_on_interrupt (memif_if_t *mif);

void *memif_int_fd_read_ready (memif_file_t *mf);

void *memif_conn_fd_read_ready (memif_file_t *mf);

void *memif_conn_fd_accept_ready (memif_file_t *mf);

void memif_connect (memif_if_t * mif);
void memif_disconnect (memif_if_t * mif);
void memif_connect_master (memif_if_t * mif);
/*allocate memory, init memif_if_t, create socket, MEMIF_PROCESS_EVENT_START*/
uword memif_create (memif_create_args_t * args);

/*free memory*/
int memif_delete (uword if_index);

void memif_bring_up (uword if_index);

void memif_bring_down (uword if_index);

void memif_set_mode (u16 flags);

memif_main_t *memif_init (u16 flags, memif_function_t *on_connect,
                 memif_function_t *on_disconnect, memif_function_data_t *on_incoming_data,
                 memif_function_t *on_interrupt);

memif_if_t * memif_dump (uword if_index);

int memif_loop_run (int timeout);

enum
{
  MEMIF_PROCESS_EVENT_START = 1,
  MEMIF_PROCESS_EVENT_STOP = 2,
} memif_process_event_t;

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

int memif_send (uword if_index);

int memif_recv (uword if_index, struct iovec **iov, u32 iov_arr_len);

static inline memif_ring_t *
memif_get_ring (memif_if_t * mif, memif_ring_type_t type, u16 ring_num)
{
  if (mif->regions == NULL)
    return NULL;
  void *p = mif->regions[0];
  int ring_size =
    sizeof (memif_ring_t) +
    sizeof (memif_desc_t) * (1 << mif->log2_ring_size);
  p += sizeof (memif_shm_t);
  p += (ring_num + type * mif->num_s2m_rings) * ring_size;

  return (memif_ring_t *) p;
}

static inline void *
memif_get_buffer (memif_if_t * mif, memif_ring_t * ring, u16 slot)
{
  u16 region = ring->desc[slot].region;
  return mif->regions[region] + ring->desc[slot].offset;
}

static inline void *
memif_alloc_buffer (memif_if_t * mif, memif_ring_t * ring, u32 buffer_size)
{
    u16 align_offset = CACHE_LINE_BYTES - (buffer_size % CACHE_LINE_BYTES);
    buffer_size += align_offset;
    u16 mask = (1 << mif->log2_ring_size) - 1;
    u16 h = (ring->head + ring->head_offset) & mask;
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
 
    void *region = mif->regions[ring->desc[h].region];

    void *next_alloc = region + ring->desc[h].offset;


    if ((next_alloc + buffer_size) > (region + ring->buffer_offset + mif->buffer_size)){
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
