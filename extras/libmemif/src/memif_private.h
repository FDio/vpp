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
#include <string.h>
#include <sys/queue.h>

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

#ifndef HAS_LIB_BSD
static inline size_t
strlcpy (char *dest, const char *src, size_t len)
{
  const char *s = src;
  size_t n = len;

  while (--n > 0)
    {
      if ((*dest++ = *s++) == '\0')
	break;
    }

  if (n == 0)
    {
      if (len != 0)
	*dest = '\0';
      while (*s++)
	;
    }

  return (s - src - 1);
}
#else
#include <bsd/string.h>
#endif

typedef enum
{
  MEMIF_SOCKET_TYPE_NONE = 0,	/* unassigned, not used by any interface */
  MEMIF_SOCKET_TYPE_LISTENER,	/* listener socket, master interface assigned */
  MEMIF_SOCKET_TYPE_CLIENT	/* client socket, slave interface assigned */
} memif_socket_type_t;

typedef struct
{
  void *addr;
  memif_region_size_t region_size;
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
  uint32_t next_buf; /* points to next free buffer */
} memif_queue_t;

struct memif_connection;

typedef struct memif_connection memif_connection_t;

typedef struct
{
  uint8_t num_s2m_rings;
  uint8_t num_m2s_rings;
  uint16_t buffer_size;
  memif_log2_ring_size_t log2_ring_size;
} memif_conn_run_args_t;

struct memif_control_channel;

typedef struct memif_connection
{
  uint16_t index;
  memif_conn_args_t args;
  memif_conn_run_args_t run_args;

  struct memif_control_channel *control_channel;

  memif_connection_update_t *on_connect, *on_disconnect;
  memif_on_interrupt_t *on_interrupt;
  void *private_ctx;

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

  TAILQ_ENTRY (memif_connection) next;
} memif_connection_t;

/** \brief Memif message queue element
 * @param msg - memif control message (defined in memif.h)
 * @param nex - tailq entry
 * @param fd - File descriptor to be shared with peer endpoint
 */
typedef struct memif_msg_queue_elt
{
  memif_msg_t msg;
  TAILQ_ENTRY (memif_msg_queue_elt) next;
  int fd;
} memif_msg_queue_elt_t;

struct memif_socket;

/** \brief Memif control channel
 * @param fd - fd used for communbication
 * @param msg_queue - message queue
 * @param conn - memif connection using this control channel
 * @param sock - socket this control channel belongs to
 *
 * Memif controll channel represents one end of communication between two memif
 * endpoints. The controll channel is responsible for receiving and
 * transmitting memif control messages via UNIX domain socket.
 */
typedef struct memif_control_channel
{
  int fd;
  TAILQ_HEAD (, memif_msg_queue_elt) msg_queue;
  memif_connection_t *conn;
  struct memif_socket *sock;
} memif_control_channel_t;

/** \brief Memif socket
 * @param args - memif socket arguments (from libmemif.h)
 * @param epfd - epoll fd, used for internal fd polling
 * @param poll_cancel_fd - if event is received on this fd, interrupt polling
 * @param listener_fd - listener fd if this socket is listener else -1
 * @param private_ctx - private context
 * @param master_interfaces - master interface queue
 * @param slave_interfaces - slave interface queue
 * @param control_channels - controll channel queue
 */
typedef struct memif_socket
{
  memif_socket_args_t args;
  int epfd;
  int poll_cancel_fd;
  int listener_fd;
  int timer_fd;
  struct itimerspec timer;
  void *private_ctx;
  TAILQ_HEAD (, memif_connection) master_interfaces;
  TAILQ_HEAD (, memif_connection) slave_interfaces;

  /* External region callbacks */
  memif_add_external_region_t *add_external_region;
  memif_get_external_region_addr_t *get_external_region_addr;
  memif_del_external_region_t *del_external_region;
  memif_get_external_buffer_offset_t *get_external_buffer_offset;
} memif_socket_t;

typedef int (memif_fd_event_handler_t) (memif_fd_event_type_t type,
					void *private_ctx);

typedef struct memif_fd_event_data
{
  memif_fd_event_handler_t *event_handler;
  void *private_ctx;
} memif_fd_event_data_t;

typedef struct memif_interrupt
{
  memif_connection_t *c;
  uint16_t qid;
} memif_interrupt_t;

/* main.c */

/* if region doesn't contain shared memory, mmap region, check ring cookie */
int memif_connect1 (memif_connection_t * c);

/* memory map region, initialize rings and queues */
int memif_init_regions_and_queues (memif_connection_t * c);

int memif_disconnect_internal (memif_connection_t * c);

int memif_interrupt_handler (memif_fd_event_type_t type, void *private_ctx);

/* map errno to memif error code */
int memif_syscall_error_handler (int err_code);

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
