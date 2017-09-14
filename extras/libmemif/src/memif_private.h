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


#ifndef _MEMIF_PRIVATE_H_
#define _MEMIF_PRIVATE_H_

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/timerfd.h>

#include <libmemif.h>

#define MEMIF_DEFAULT_SOCKET_DIR "/run/vpp"
#define MEMIF_DEFAULT_SOCKET_FILENAME  "memif.sock"
#define MEMIF_DEFAULT_RING_SIZE 1024
#define MEMIF_DEFAULT_LOG2_RING_SIZE 10
#define MEMIF_DEFAULT_RX_QUEUES 1
#define MEMIF_DEFAULT_TX_QUEUES 1
#define MEMIF_DEFAULT_BUFFER_SIZE 2048

#define MEMIF_MAX_M2S_RING		255
#define MEMIF_MAX_S2M_RING		255
#define MEMIF_MAX_REGION		255
#define MEMIF_MAX_LOG2_RING_SIZE	14

#define MEMIF_MAX_FDS 512

#define memif_min(a,b) (((a) < (b)) ? (a) : (b))

#ifdef MEMIF_DBG
#define DBG(...) do {                                                             \
                        printf("MEMIF_DEBUG:%s:%s:%d: ", __FILE__, __func__, __LINE__);  \
                        printf(__VA_ARGS__);                                            \
                        printf("\n");                                                   \
                        } while (0)

#define DBG_UNIX(...) do {                                                        \
                      printf("MEMIF_DEBUG_UNIX:%s:%s:%d: ", __FILE__, __func__, __LINE__);  \
                      printf(__VA_ARGS__);                                    \
                      printf("\n");                                           \
                      } while (0)

#define error_return_unix(...) do {                                             \
                                DBG_UNIX(__VA_ARGS__);                          \
                                return -1;                                      \
                                } while (0)
#define error_return(...) do {                                                  \
                            DBG(__VA_ARGS__);                                   \
                            return -1;                                          \
                            } while (0)
#else
#define DBG(...)
#define DBG_UNIX(...)
#define error_return_unix(...) do {                                             \
                                return -1;                                      \
                                } while (0)
#define error_return(...) do {                                                  \
                            return -1;                                          \
                            } while (0)

#endif /* MEMIF_DBG */

typedef struct
{
  void *shm;
  uint32_t region_size;
  int fd;
} memif_region_t;

typedef struct
{
  memif_ring_t *ring;
  uint8_t log2_ring_size;
  uint8_t region;
  uint32_t offset;

  uint16_t last_head;
  uint16_t last_tail;

  int int_fd;

  uint64_t int_count;
  uint32_t alloc_bufs;
} memif_queue_t;

typedef struct memif_msg_queue_elt
{
  memif_msg_t msg;
  int fd;
  struct memif_msg_queue_elt *next;
} memif_msg_queue_elt_t;

struct memif_connection;

typedef struct memif_connection memif_connection_t;

/* functions called by memif_control_fd_handler */
typedef int (memif_fn) (memif_connection_t * conn);

typedef struct
{
  uint8_t num_s2m_rings;
  uint8_t num_m2s_rings;
  uint16_t buffer_size;
  memif_log2_ring_size_t log2_ring_size;
} memif_conn_run_args_t;

typedef struct memif_connection
{
  uint16_t index;
  memif_conn_args_t args;
  memif_conn_run_args_t run_args;

  int fd;
  int listener_fd;

  memif_fn *write_fn, *read_fn, *error_fn;

  memif_connection_update_t *on_connect, *on_disconnect;
  memif_interrupt_t *on_interrupt;
  void *private_ctx;

  /* connection message queue */
  memif_msg_queue_elt_t *msg_queue;

  uint8_t remote_if_name[32];
  uint8_t remote_name[32];
  uint8_t remote_disconnect_string[96];

  memif_region_t *regions;

  memif_queue_t *rx_queues;
  memif_queue_t *tx_queues;

  uint16_t flags;
#define MEMIF_CONNECTION_FLAG_WRITE (1 << 0)
} memif_connection_t;

/*
 * WIP
 */
typedef struct
{
  int key;			/* fd or id */
  void *data_struct;
} memif_list_elt_t;

/*
 * WIP
 */
typedef struct
{
  int fd;
  uint16_t use_count;
  uint8_t *filename;
  uint16_t interface_list_len;
  memif_list_elt_t *interface_list;	/* memif master interfaces listening on this socket */
} memif_socket_t;

/*
 * WIP
 */
/* probably function like memif_cleanup () will need to be called to close timerfd */
typedef struct
{
  memif_control_fd_update_t *control_fd_update;
  int timerfd;
  struct itimerspec arm, disarm;
  uint16_t disconn_slaves;
  uint8_t *app_name;

  /* master implementation... */
  memif_socket_t ms;

  uint16_t control_list_len;
  uint16_t interrupt_list_len;
  uint16_t listener_list_len;
  uint16_t pending_list_len;
  memif_list_elt_t *control_list;
  memif_list_elt_t *interrupt_list;
  memif_list_elt_t *listener_list;
  memif_list_elt_t *pending_list;
} libmemif_main_t;

extern libmemif_main_t libmemif_main;
extern int memif_epfd;

/* main.c */

/* if region doesn't contain shared memory, mmap region, check ring cookie */
int memif_connect1 (memif_connection_t * c);

/* memory map region, initalize rings and queues */
int memif_init_regions_and_queues (memif_connection_t * c);

int memif_disconnect_internal (memif_connection_t * c);

/* map errno to memif error code */
int memif_syscall_error_handler (int err_code);

int add_list_elt (memif_list_elt_t * e, memif_list_elt_t ** list,
		  uint16_t * len);

int get_list_elt (memif_list_elt_t ** e, memif_list_elt_t * list,
		  uint16_t len, int key);

int free_list_elt (memif_list_elt_t * list, uint16_t len, int key);

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

static inline void *
memif_get_buffer (memif_connection_t * conn, memif_ring_t * ring,
		  uint16_t index)
{
  return (conn->regions[ring->desc[index].region].shm +
	  ring->desc[index].offset);
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

#endif /* _MEMIF_PRIVATE_H_ */
