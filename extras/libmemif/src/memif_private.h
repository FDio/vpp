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

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/timerfd.h>
#include <string.h>

#include <memif.h>
#include <libmemif.h>

#define MEMIF_NAME_LEN 32
_Static_assert (strlen (MEMIF_DEFAULT_APP_NAME) <= MEMIF_NAME_LEN,
		"MEMIF_DEFAULT_APP_NAME max length is 32");

#define MEMIF_DEFAULT_SOCKET_PATH "/run/vpp/memif.sock"
#define MEMIF_DEFAULT_RING_SIZE 1024
#define MEMIF_DEFAULT_LOG2_RING_SIZE 10
#define MEMIF_DEFAULT_RX_QUEUES 1
#define MEMIF_DEFAULT_TX_QUEUES 1
#define MEMIF_DEFAULT_BUFFER_SIZE 2048
#define MEMIF_DEFAULT_RECONNECT_PERIOD_SEC 2
#define MEMIF_DEFAULT_RECONNECT_PERIOD_NSEC 0

#define MEMIF_MAX_M2S_RING		255
#define MEMIF_MAX_S2M_RING		255
#define MEMIF_MAX_REGION		255
#define MEMIF_MAX_LOG2_RING_SIZE	14

#define MEMIF_MAX_FDS 512

#define memif_min(a,b) (((a) < (b)) ? (a) : (b))

#define EXPECT_TRUE(x) __builtin_expect((x),1)
#define EXPECT_FALSE(x) __builtin_expect((x),0)

#ifdef MEMIF_DBG
#define DBG(...) do {                                                             \
                        printf("MEMIF_DEBUG:%s:%s:%d: ", __FILE__, __func__, __LINE__);  \
                        printf(__VA_ARGS__);                                            \
                        printf("\n");                                                   \
                        } while (0)
#else
#define DBG(...)
#endif /* MEMIF_DBG */

typedef enum
{
  MEMIF_SOCKET_TYPE_NONE = 0,	/* unassigned, not used by any interface */
  MEMIF_SOCKET_TYPE_LISTENER,	/* listener socket, master interface assigned */
  MEMIF_SOCKET_TYPE_CLIENT	/* client socket, slave interface assigned */
} memif_socket_type_t;

typedef struct
{
  void *addr;
  uint32_t region_size;
  uint32_t buffer_offset;
  int fd;
  uint8_t is_external;
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

struct libmemif_main;

typedef struct memif_connection
{
  uint16_t index;
  memif_conn_args_t args;
  memif_conn_run_args_t run_args;

  int fd;

  memif_fn *write_fn, *read_fn, *error_fn;

  memif_connection_update_t *on_connect, *on_disconnect;
  memif_interrupt_t *on_interrupt;
  void *private_ctx;

  /* connection message queue */
  memif_msg_queue_elt_t *msg_queue;

  uint8_t remote_if_name[MEMIF_NAME_LEN];
  uint8_t remote_name[MEMIF_NAME_LEN];
  uint8_t remote_disconnect_string[96];

  uint8_t regions_num;
  memif_region_t *regions;

  uint8_t rx_queues_num;
  uint8_t tx_queues_num;
  memif_queue_t *rx_queues;
  memif_queue_t *tx_queues;

  uint16_t flags;
#define MEMIF_CONNECTION_FLAG_WRITE (1 << 0)
} memif_connection_t;

typedef struct
{
  int key;
  void *data_struct;
} memif_list_elt_t;

typedef struct
{
  int fd;
  uint16_t use_count;
  memif_socket_type_t type;
  uint8_t *filename;
  /* unique database */
  struct libmemif_main *lm;
  uint16_t interface_list_len;
  void *private_ctx;
  memif_list_elt_t *interface_list;	/* memif master interfaces listening on this socket */
} memif_socket_t;

typedef struct libmemif_main
{
  memif_control_fd_update_t *control_fd_update;
  int timerfd;
  int epfd;
  int poll_cancel_fd;
  struct itimerspec arm, disarm;
  uint16_t disconn_slaves;
  uint8_t app_name[MEMIF_NAME_LEN];

  void *private_ctx;

  memif_socket_handle_t default_socket;

  memif_add_external_region_t *add_external_region;
  memif_get_external_region_addr_t *get_external_region_addr;
  memif_del_external_region_t *del_external_region;
  memif_get_external_buffer_offset_t *get_external_buffer_offset;

  memif_alloc_t *alloc;
  memif_realloc_t *realloc;
  memif_free_t *free;

  uint16_t control_list_len;
  uint16_t interrupt_list_len;
  uint16_t socket_list_len;
  uint16_t pending_list_len;
  memif_list_elt_t *control_list;
  memif_list_elt_t *interrupt_list;
  memif_list_elt_t *socket_list;
  memif_list_elt_t *pending_list;
} libmemif_main_t;

extern libmemif_main_t libmemif_main;

/* main.c */

/* if region doesn't contain shared memory, mmap region, check ring cookie */
int memif_connect1 (memif_connection_t * c);

/* memory map region, initalize rings and queues */
int memif_init_regions_and_queues (memif_connection_t * c);

int memif_disconnect_internal (memif_connection_t * c);

/* map errno to memif error code */
int memif_syscall_error_handler (int err_code);

int add_list_elt (libmemif_main_t *lm, memif_list_elt_t * e, memif_list_elt_t ** list,
		  uint16_t * len);

int get_list_elt (memif_list_elt_t ** e, memif_list_elt_t * list,
		  uint16_t len, int key);

int free_list_elt (memif_list_elt_t * list, uint16_t len, int key);

libmemif_main_t *get_libmemif_main (memif_socket_t * ms);

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

#ifndef HAVE_MEMFD_CREATE
static inline int
memfd_create (const char *name, unsigned int flags)
{
  return syscall (__NR_memfd_create, name, flags);
}
#endif

static inline void *
memif_get_buffer (memif_connection_t * conn, memif_ring_t * ring,
		  uint16_t index)
{
  return (conn->regions[ring->desc[index].region].addr +
	  ring->desc[index].offset);
}

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING       0x0002U
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_SEAL_SEAL     0x0001	/* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002	/* prevent file from shrinking */
#define F_SEAL_GROW     0x0004	/* prevent file from growing */
#define F_SEAL_WRITE    0x0008	/* prevent writes */
#endif

#endif /* _MEMIF_PRIVATE_H_ */
