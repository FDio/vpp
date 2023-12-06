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

#define _GNU_SOURCE
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
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <asm/byteorder.h>
#include <byteswap.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <signal.h>
#include <linux/memfd.h>

/* memif protocol msg, ring and descriptor definitions */
#include <memif.h>
/* memif api */
#include <libmemif.h>
/* socket messaging functions */
#include <socket.h>
/* private structs and functions */
#include <memif_private.h>

#define ERRLIST_LEN 40
#define MAX_ERRBUF_LEN 256

#if __x86_x64__
#define MEMIF_MEMORY_BARRIER() __builtin_ia32_sfence ()
#else
#define MEMIF_MEMORY_BARRIER() __sync_synchronize ()
#endif /* __x86_x64__ */

static char memif_buf[MAX_ERRBUF_LEN];

const char *memif_errlist[ERRLIST_LEN] = {	/* MEMIF_ERR_SUCCESS */
  "Success.",
  /* MEMIF_ERR_SYSCALL */
  "Unspecified syscall error (build with -DMEMIF_DBG or make debug).",
  /* MEMIF_ERR_CONNREFUSED */
  "Connection refused",
  /* MEMIF_ERR_ACCES */
  "Permission to resource denied.",
  /* MEMIF_ERR_NO_FILE */
  "Socket file does not exist",
  /* MEMIF_ERR_FILE_LIMIT */
  "System limit on total numer of open files reached.",
  /* MEMIF_ERR_PROC_FILE_LIMIT */
  "Per-process limit on total number of open files reached.",
  /* MEMIF_ERR_ALREADY */
  "Connection already requested.",
  /* MEMIF_ERR_AGAIN */
  "File descriptor refers to file other than socket, or operation would block.",
  /* MEMIF_ERR_BAD_FD */
  "Bad file descriptor.",
  /* MEMIF_ERR_NOMEM */
  "Out of memory.",
  /* MEMIF_ERR_INVAL_ARG */
  "Invalid argument.",
  /* MEMIF_ERR_NOCONN */
  "Memif connection handle does not point to existing connection",
  /* MEMIF_ERR_CONN */
  "Memif connection handle points to existing connection",
  /* MEMIF_ERR_CB_FDUPDATE */
  "Callback memif_control_fd_update_t returned error",
  /* MEMIF_ERR_FILE_NOT_SOCK */
  "File specified by socket filename exists and is not socket.",
  /* MEMIF_ERR_NO_SHMFD */
  "Missing shared memory file descriptor. (internal error)",
  /* MEMIF_ERR_COOKIE */
  "Invalid cookie on ring. (internal error)",
  /* MEMIF_ERR_NOBUF_RING */
  "Ring buffer full.",
  /* MEMIF_ERR_NOBUF */
  "Not enough memif buffers. There are unreceived data in shared memory.",
  /* MEMIF_ERR_NOBUF_DET */
  "Not enough space for memif details in supplied buffer. String data might be malformed.",
  /* MEMIF_ERR_INT_WRITE */
  "Send interrupt error.",
  /* MEMIF_ERR_MFMSG */
  "Malformed message received on control channel.",
  /* MEMIF_ERR_QID */
  "Invalid queue id",
  /* MEMIF_ERR_PROTO */
  "Incompatible memory interface protocol version.",
  /* MEMIF_ERR_ID */
  "Unmatched interface id.",
  /* MEMIF_ERR_ACCSLAVE */
  "Slave cannot accept connection request.",
  /* MEMIF_ERR_ALRCONN */
  "Interface is already connected.",
  /* MEMIF_ERR_MODE */
  "Mode mismatch.",
  /* MEMIF_ERR_SECRET */
  "Secret mismatch.",
  /* MEMIF_ERR_NOSECRET */
  "Secret required.",
  /* MEMIF_ERR_MAXREG */
  "Limit on total number of regions reached.",
  /* MEMIF_ERR_MAXRING */
  "Limit on total number of ring reached.",
  /* MEMIF_ERR_NO_INTFD */
  "Missing interrupt file descriptor. (internal error)",
  /* MEMIF_ERR_DISCONNECT */
  "Interface received disconnect request.",
  /* MEMIF_ERR_DISCONNECTED */
  "Interface is disconnected.",
  /* MEMIF_ERR_UNKNOWN_MSG */
  "Unknown message type received on control channel. (internal error)",
  /* MEMIF_ERR_POLL_CANCEL */
  "Memif event polling was canceled.",
  /* MEMIF_ERR_MAX_RING */
  "Maximum log2 ring size is 15",
  /* MEMIF_ERR_PRIVHDR */
  "Private headers not supported."
};

#define MEMIF_ERR_UNDEFINED "undefined error"

char *
memif_strerror (int err_code)
{
  if (err_code >= ERRLIST_LEN)
    {
      strlcpy (memif_buf, MEMIF_ERR_UNDEFINED, sizeof (memif_buf));
    }
  else
    {
      strlcpy (memif_buf, memif_errlist[err_code], sizeof (memif_buf));
      memif_buf[strlen (memif_errlist[err_code])] = '\0';
    }
  return memif_buf;
}

uint16_t
memif_get_version ()
{
  return MEMIF_VERSION;
}

const char *
memif_get_version_str ()
{
#define __STR_HELPER(x) #x
#define __STR(x)	__STR_HELPER (x)
  return __STR (MEMIF_VERSION_MAJOR) "." __STR (MEMIF_VERSION_MINOR);
#undef __STR
#undef __STR_HELPER
}

#define DBG_TX_BUF (0)
#define DBG_RX_BUF (1)

#ifdef MEMIF_DBG_SHM
static void
print_bytes (void *data, uint16_t len, uint8_t q)
{
  if (q == DBG_TX_BUF)
    printf ("\nTX:\n\t");
  else
    printf ("\nRX:\n\t");
  int i;
  for (i = 0; i < len; i++)
    {
      if (i % 8 == 0)
	printf ("\n%d:\t", i);
      printf ("%02X ", ((uint8_t *) (data))[i]);
    }
  printf ("\n\n");
}
#endif /* MEMIF_DBG_SHM */

int
memif_syscall_error_handler (int err_code)
{
  DBG ("%s", strerror (err_code));

  if (err_code == 0)
    return MEMIF_ERR_SUCCESS;
  if (err_code == EACCES)
    return MEMIF_ERR_ACCES;
  if (err_code == ENFILE)
    return MEMIF_ERR_FILE_LIMIT;
  if (err_code == EMFILE)
    return MEMIF_ERR_PROC_FILE_LIMIT;
  if (err_code == ENOMEM)
    return MEMIF_ERR_NOMEM;
/* connection refused if master does not exist
    this error would spam the user until master was created */
/*
  if (err_code == ECONNREFUSED)
    return MEMIF_ERR_SUCCESS;
*/
  if (err_code == ECONNREFUSED)
    return MEMIF_ERR_CONNREFUSED;
  if (err_code == EALREADY)
    return MEMIF_ERR_ALREADY;
  if (err_code == EAGAIN)
    return MEMIF_ERR_AGAIN;
  if (err_code == EBADF)
    return MEMIF_ERR_BAD_FD;
  if (err_code == ENOENT)
    return MEMIF_ERR_NO_FILE;

  /* other syscall errors */
  return MEMIF_ERR_SYSCALL;
}

static int
memif_add_epoll_fd (memif_socket_t *ms, memif_fd_event_t fde, uint32_t events)
{
  if (fde.fd < 0)
    {
      DBG ("invalid fd %d", fde.fd);
      return -1;
    }
  struct epoll_event evt;
  memset (&evt, 0, sizeof (evt));
  evt.events = events;
  evt.data.ptr = fde.private_ctx;
  if (epoll_ctl (ms->epfd, EPOLL_CTL_ADD, fde.fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fde.fd);
      return -1;
    }
  DBG ("fd %d added to epoll", fde.fd);
  return 0;
}

static int
memif_mod_epoll_fd (memif_socket_t *ms, memif_fd_event_t fde, uint32_t events)
{
  if (fde.fd < 0)
    {
      DBG ("invalid fd %d", fde.fd);
      return -1;
    }
  struct epoll_event evt;
  memset (&evt, 0, sizeof (evt));
  evt.events = events;
  evt.data.ptr = fde.private_ctx;
  if (epoll_ctl (ms->epfd, EPOLL_CTL_MOD, fde.fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fde.fd);
      return -1;
    }
  DBG ("fd %d modified on epoll", fde.fd);
  return 0;
}

static int
memif_del_epoll_fd (memif_socket_t *ms, memif_fd_event_t fde)
{
  if (fde.fd < 0)
    {
      DBG ("invalid fd %d", fde.fd);
      return -1;
    }
  struct epoll_event evt;
  memset (&evt, 0, sizeof (evt));
  if (epoll_ctl (ms->epfd, EPOLL_CTL_DEL, fde.fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fde.fd);
      return -1;
    }
  DBG ("fd %d removed from epoll", fde.fd);
  return 0;
}

int
memif_control_fd_update (memif_fd_event_t fde, void *private_ctx)
{
  memif_socket_t *ms = (memif_socket_t *) private_ctx;
  int fd;

  if (ms == NULL)
    return MEMIF_ERR_INVAL_ARG;

  if (fde.type & MEMIF_FD_EVENT_DEL)
    return memif_del_epoll_fd (ms, fde);

  uint32_t evt = 0;
  if (fde.type & MEMIF_FD_EVENT_READ)
    evt |= EPOLLIN;
  if (fde.type & MEMIF_FD_EVENT_WRITE)
    evt |= EPOLLOUT;

  if (fde.type & MEMIF_FD_EVENT_MOD)
    return memif_mod_epoll_fd (ms, fde, evt);

  return memif_add_epoll_fd (ms, fde, evt);
}

static void
memif_control_fd_update_register (memif_socket_t *ms,
				  memif_control_fd_update_t *cb)
{
  ms->args.on_control_fd_update = cb;
}

void
memif_register_external_region (memif_socket_handle_t sock,
				memif_add_external_region_t *ar,
				memif_get_external_region_addr_t *gr,
				memif_del_external_region_t *dr,
				memif_get_external_buffer_offset_t *go)
{
  memif_socket_t *ms = (memif_socket_t *) sock;
  ms->add_external_region = ar;
  ms->get_external_region_addr = gr;
  ms->del_external_region = dr;
  ms->get_external_buffer_offset = go;
}

static void
memif_alloc_register (memif_socket_t *ms, memif_alloc_t *ma)
{
  ms->args.alloc = ma;
}

static void
memif_realloc_register (memif_socket_t *ms, memif_realloc_t *mr)
{
  ms->args.realloc = mr;
}

static void
memif_free_register (memif_socket_t *ms, memif_free_t *mf)
{
  ms->args.free = mf;
}

static inline memif_ring_t *
memif_get_ring (memif_connection_t * conn, memif_ring_type_t type,
		uint16_t ring_num)
{
  if (&conn->regions[0] == NULL)
    return NULL;
  void *p = conn->regions[0].addr;
  int ring_size =
    sizeof (memif_ring_t) +
    sizeof (memif_desc_t) * (1 << conn->run_args.log2_ring_size);
  p += (ring_num + type * conn->run_args.num_s2m_rings) * ring_size;

  return (memif_ring_t *) p;
}

int
memif_set_rx_mode (memif_conn_handle_t c, memif_rx_mode_t rx_mode,
		   uint16_t qid)
{
  memif_connection_t *conn = (memif_connection_t *) c;
  if (conn == NULL)
    return MEMIF_ERR_NOCONN;
  uint8_t num =
    (conn->args.is_master) ? conn->run_args.num_s2m_rings : conn->
    run_args.num_m2s_rings;
  if (qid >= num)
    return MEMIF_ERR_QID;

  conn->rx_queues[qid].ring->flags = rx_mode;
  DBG ("rx_mode flag: %u", conn->rx_queues[qid].ring->flags);
  return MEMIF_ERR_SUCCESS;
}

int
memif_poll_cancel_handler (memif_fd_event_type_t type, void *private_ctx)
{
  return MEMIF_ERR_POLL_CANCEL;
}

int
memif_connect_handler (memif_fd_event_type_t type, void *private_ctx)
{
  memif_socket_t *ms = (memif_socket_t *) private_ctx;
  memif_connection_t *c;

  if (ms->timer_fd >= 0)
    {
      uint64_t u64;
      /*
	Have to read the timer fd else it stays read-ready
	and makes epoll_pwait() return without sleeping
      */
      read (ms->timer_fd, &u64, sizeof (u64));
    }

  /* loop ms->slave_interfaces and request connection for disconnected ones */
  TAILQ_FOREACH (c, &ms->slave_interfaces, next)
  {
    /* connected or connecting */
    if (c->control_channel != NULL)
      continue;

    /* ignore errors */
    memif_request_connection (c);
  }

  return MEMIF_ERR_SUCCESS;
}

int
memif_set_connection_request_timer (memif_socket_handle_t sock,
				    struct itimerspec timer)
{
  memif_socket_t *ms = (memif_socket_t *) sock;
  memif_fd_event_t fde;
  memif_fd_event_data_t *fdata;
  void *ctx;

  if (ms == NULL)
    return MEMIF_ERR_INVAL_ARG;

  if (ms->timer_fd < 0)
    {
      /* only create new timer if there is a valid interval */
      if (timer.it_interval.tv_sec == 0 && timer.it_interval.tv_nsec == 0)
	return MEMIF_ERR_SUCCESS;

      /* create timerfd */
      ms->timer_fd = timerfd_create (CLOCK_REALTIME, TFD_NONBLOCK);
      if (ms->timer_fd < 0)
	return memif_syscall_error_handler (errno);

      /* start listening for events */
      fdata = ms->args.alloc (sizeof (*fdata));
      fdata->event_handler = memif_connect_handler;
      fdata->private_ctx = ms;

      fde.fd = ms->timer_fd;
      fde.type = MEMIF_FD_EVENT_READ;
      fde.private_ctx = fdata;

      ctx = ms->epfd != -1 ? ms : ms->private_ctx;
      ms->args.on_control_fd_update (fde, ctx);
    }

  ms->args.connection_request_timer = timer;

  /* arm the timer */
  if (timerfd_settime (ms->timer_fd, 0, &ms->args.connection_request_timer,
		       NULL) < 0)
    return memif_syscall_error_handler (errno);

  return MEMIF_ERR_SUCCESS;
}

int
memif_create_socket (memif_socket_handle_t *sock, memif_socket_args_t *args,
		     void *private_ctx)
{
  memif_socket_t *ms = (memif_socket_t *) * sock;
  memif_fd_event_t fde;
  memif_fd_event_data_t *fdata;
  int i, err = MEMIF_ERR_SUCCESS;
  void *ctx;

  /* allocate memif_socket_t */
  ms = NULL;
  if (args->alloc != NULL)
    ms = args->alloc (sizeof (memif_socket_t));
  else
    ms = malloc (sizeof (memif_socket_t));
  if (ms == NULL)
    {
      err = MEMIF_ERR_NOMEM;
      goto error;
    }

  /* default values */
  memset (ms, 0, sizeof (memif_socket_t));
  ms->epfd = -1;
  ms->listener_fd = -1;
  ms->poll_cancel_fd = -1;
  ms->timer_fd = -1;

  /* copy arguments to internal struct */
  memcpy (&ms->args, args, sizeof (*args));
  ms->private_ctx = private_ctx;

  if (ms->args.alloc == NULL)
    memif_alloc_register (ms, malloc);
  if (ms->args.realloc == NULL)
    memif_realloc_register (ms, realloc);
  if (ms->args.free == NULL)
    memif_free_register (ms, free);

  TAILQ_INIT (&ms->master_interfaces);
  TAILQ_INIT (&ms->slave_interfaces);

  /* FIXME: implement connection request timer */

  /* initialize internal epoll */
  if (ms->args.on_control_fd_update == NULL)
    {
      ms->epfd = epoll_create (1);
      /* register default fd update callback */
      memif_control_fd_update_register (ms, memif_control_fd_update);
      ms->poll_cancel_fd = eventfd (0, EFD_NONBLOCK);
      if (ms->poll_cancel_fd < 0)
	{
	  err = errno;
	  DBG ("eventfd: %s", strerror (err));
	  return memif_syscall_error_handler (err);
	}
      /* add interrupt fd to epfd */
      fdata = ms->args.alloc (sizeof (*fdata));
      fdata->event_handler = memif_poll_cancel_handler;
      fdata->private_ctx = ms;

      fde.fd = ms->poll_cancel_fd;
      fde.type = MEMIF_FD_EVENT_READ;
      fde.private_ctx = fdata;

      ctx = ms->epfd != -1 ? ms : ms->private_ctx;
      ms->args.on_control_fd_update (fde, ctx);
    }

  err =
    memif_set_connection_request_timer (ms, ms->args.connection_request_timer);
  if (err != MEMIF_ERR_SUCCESS)
    goto error;

  *sock = ms;

  return err;

error:
  if (ms != NULL)
    {
      ms->args.free (ms);
      if (ms->epfd != -1)
	close (ms->epfd);
      if (ms->poll_cancel_fd != -1)
	close (ms->poll_cancel_fd);
    }
  return err;
}

memif_socket_handle_t
memif_get_socket_handle (memif_conn_handle_t conn)
{
  memif_connection_t *c = (memif_connection_t *) conn;

  if (c == NULL)
    return NULL;

  return c->args.socket;
}

const char *
memif_get_socket_path (memif_socket_handle_t sock)
{
  memif_socket_t *ms = (memif_socket_t *) sock;

  if (ms == NULL)
    return NULL;

  return ms->args.path;
}

int
memif_get_listener_fd (memif_socket_handle_t sock)
{
  memif_socket_t *ms = (memif_socket_t *) sock;

  if (ms == NULL)
    return -1;

  return ms->listener_fd;
}

int
memif_set_listener_fd (memif_socket_handle_t sock, int fd)
{
  memif_socket_t *ms = (memif_socket_t *) sock;
  memif_fd_event_t fde;
  memif_fd_event_data_t *fdata;
  void *ctx;

  if ((ms == NULL) || (fd < 0))
    return MEMIF_ERR_INVAL_ARG;

  fdata = ms->args.alloc (sizeof (*fdata));
  if (fdata == NULL)
    return MEMIF_ERR_NOMEM;

  ms->listener_fd = fd;

  fdata->event_handler = memif_listener_handler;
  fdata->private_ctx = ms;
  ctx = ms->epfd != -1 ? ms : ms->private_ctx;
  /* send fd to epoll */
  fde.fd = ms->listener_fd;
  fde.type = MEMIF_FD_EVENT_READ;
  fde.private_ctx = fdata;
  ms->args.on_control_fd_update (fde, ctx);

  return MEMIF_ERR_SUCCESS;
}

int
memif_create (memif_conn_handle_t *c, memif_conn_args_t *args,
	      memif_connection_update_t *on_connect,
	      memif_connection_update_t *on_disconnect,
	      memif_on_interrupt_t *on_interrupt, void *private_ctx)
{
  int err, index = 0;
  memif_connection_t *conn = (memif_connection_t *) * c;
  memif_socket_t *ms = (memif_socket_t *) args->socket;

  if (conn != NULL)
    {
      DBG ("This handle already points to existing memif.");
      return MEMIF_ERR_CONN;
    }

  if (ms == NULL)
    {
      DBG ("Missing memif socket");
      return MEMIF_ERR_INVAL_ARG;
    }

  conn = (memif_connection_t *) ms->args.alloc (sizeof (*conn));
  if (conn == NULL)
    {
      err = MEMIF_ERR_NOMEM;
      goto error;
    }
  memset (conn, 0, sizeof (memif_connection_t));

  conn->args.interface_id = args->interface_id;

  if (args->log2_ring_size == 0)
    args->log2_ring_size = MEMIF_DEFAULT_LOG2_RING_SIZE;
  else if (args->log2_ring_size > MEMIF_MAX_LOG2_RING_SIZE)
    {
      err = MEMIF_ERR_MAX_RING;
      goto error;
    }
  if (args->buffer_size == 0)
    args->buffer_size = MEMIF_DEFAULT_BUFFER_SIZE;
  if (args->num_s2m_rings == 0)
    args->num_s2m_rings = MEMIF_DEFAULT_TX_QUEUES;
  if (args->num_m2s_rings == 0)
    args->num_m2s_rings = MEMIF_DEFAULT_RX_QUEUES;

  conn->args.num_s2m_rings = args->num_s2m_rings;
  conn->args.num_m2s_rings = args->num_m2s_rings;
  conn->args.buffer_size = args->buffer_size;
  conn->args.log2_ring_size = args->log2_ring_size;
  conn->args.is_master = args->is_master;
  conn->args.mode = args->mode;
  conn->args.socket = args->socket;
  conn->regions = NULL;
  conn->tx_queues = NULL;
  conn->rx_queues = NULL;
  conn->control_channel = NULL;
  conn->on_connect = on_connect;
  conn->on_disconnect = on_disconnect;
  conn->on_interrupt = on_interrupt;
  conn->private_ctx = private_ctx;
  memset (&conn->run_args, 0, sizeof (memif_conn_run_args_t));

  uint8_t l = sizeof (conn->args.interface_name);
  strlcpy ((char *) conn->args.interface_name, (char *) args->interface_name,
	   l);

  if ((l = strlen ((char *) args->secret)) > 0)
    strlcpy ((char *) conn->args.secret, (char *) args->secret,
	     sizeof (conn->args.secret));

  if (args->is_master)
    TAILQ_INSERT_TAIL (&ms->master_interfaces, conn, next);
  else
    TAILQ_INSERT_TAIL (&ms->slave_interfaces, conn, next);

  err = memif_request_connection (conn);
  if (err != MEMIF_ERR_SUCCESS && err != MEMIF_ERR_CONNREFUSED)
    {
      if (args->is_master)
	TAILQ_REMOVE (&ms->master_interfaces, conn, next);
      else
	TAILQ_REMOVE (&ms->slave_interfaces, conn, next);
      goto error;
    }

  *c = conn;

  return 0;

error:
  if (conn != NULL)
    ms->args.free (conn);
  *c = conn = NULL;
  return err;
}

static inline int
memif_path_is_abstract (const char *filename)
{
  return (filename[0] == '@');
}

int
memif_request_connection (memif_conn_handle_t c)
{
  memif_connection_t *conn = (memif_connection_t *) c;
  memif_socket_t *ms;
  int err = MEMIF_ERR_SUCCESS;
  int sockfd = -1;
  struct sockaddr_un un = { 0 };
  struct stat file_stat;
  int on = 1;
  memif_control_channel_t *cc = NULL;
  memif_fd_event_t fde;
  memif_fd_event_data_t *fdata = NULL;
  int sunlen = sizeof (un);
  void *ctx;

  if (conn == NULL)
    return MEMIF_ERR_NOCONN;

  ms = (memif_socket_t *) conn->args.socket;

  /* if control channel is assigned, the interface is either connected or
   * connecting */
  if (conn->control_channel != NULL)
    return MEMIF_ERR_ALRCONN;
  /* if interface is master and the socket is already listener we are done */
  if (conn->args.is_master && (ms->listener_fd != -1))
    return MEMIF_ERR_SUCCESS;

  sockfd = socket (AF_UNIX, SOCK_SEQPACKET, 0);
  if (sockfd < 0)
    {
      err = memif_syscall_error_handler (errno);
      goto error;
    }

  un.sun_family = AF_UNIX;

  /* use memcpy to support abstract socket
   * ms->args.path is already a valid socket path
   */
  memcpy (un.sun_path, ms->args.path, sizeof (un.sun_path) - 1);

  /* allocate fd event data */
  fdata = ms->args.alloc (sizeof (*fdata));
  if (fdata == NULL)
    {
      err = MEMIF_ERR_NOMEM;
      goto error;
    }

  if (memif_path_is_abstract (ms->args.path))
    {
      /* Ensure the string is NULL terminated */
      un.sun_path[sizeof (un.sun_path) - 1] = '\0';
      /* sunlen is strlen(un.sun_path) + sizeof(un.sun_family) */
      sunlen = strlen (un.sun_path) + (sizeof (un) - sizeof (un.sun_path));
      /* Handle abstract socket by converting '@' -> '\0' */
      un.sun_path[0] = '\0';
    }

  if (conn->args.is_master != 0)
    {
      /* Configure socket optins */
      if (setsockopt (sockfd, SOL_SOCKET, SO_PASSCRED, &on, sizeof (on)) < 0)
	{
	  err = memif_syscall_error_handler (errno);
	  goto error;
	}
      if (bind (sockfd, (struct sockaddr *) &un, sunlen) < 0)
	{
	  err = memif_syscall_error_handler (errno);
	  goto error;
	}
      if (listen (sockfd, 1) < 0)
	{
	  err = memif_syscall_error_handler (errno);
	  goto error;
	}
      if (!memif_path_is_abstract (ms->args.path))
	{
	  /* Verify that the socket was created */
	  if (stat ((char *) ms->args.path, &file_stat) < 0)
	    {
	      err = memif_syscall_error_handler (errno);
	      goto error;
	    }
	}

      /* assign listener fd */
      ms->listener_fd = sockfd;

      fdata->event_handler = memif_listener_handler;
      fdata->private_ctx = ms;
    }
  else
    {
      cc = ms->args.alloc (sizeof (*cc));
      if (cc == NULL)
	{
	  err = MEMIF_ERR_NOMEM;
	  goto error;
	}
      if (connect (sockfd, (struct sockaddr *) &un, sunlen) != 0)
	{
	  err = MEMIF_ERR_CONNREFUSED;
	  goto error;
	}

      /* Create control channel */
      cc->fd = sockfd;
      cc->sock = ms;
      cc->conn = conn;
      TAILQ_INIT (&cc->msg_queue);

      /* assign control channel to endpoint */
      conn->control_channel = cc;

      fdata->event_handler = memif_control_channel_handler;
      fdata->private_ctx = cc;
    }

  /* if event polling is done internally, send memif socket as context */
  ctx = ms->epfd != -1 ? ms : ms->private_ctx;
  /* send fd to epoll */
  fde.fd = sockfd;
  fde.type = MEMIF_FD_EVENT_READ;
  fde.private_ctx = fdata;
  ms->args.on_control_fd_update (fde, ctx);

  return err;

error:
  if (sockfd > 0)
    close (sockfd);
  sockfd = -1;
  if (fdata != NULL)
    ms->args.free (fdata);
  fdata = NULL;
  if (cc != NULL)
    ms->args.free (cc);
  conn->control_channel = cc = NULL;
  return err;
}

int
memif_control_fd_handler (void *ptr, memif_fd_event_type_t events)
{
  memif_fd_event_data_t *fdata = (memif_fd_event_data_t *) ptr;

  if (fdata == NULL)
    return MEMIF_ERR_INVAL_ARG;

  return fdata->event_handler (events, fdata->private_ctx);
}

int
memif_interrupt_handler (memif_fd_event_type_t type, void *private_ctx)
{
  memif_interrupt_t *idata = (memif_interrupt_t *) private_ctx;

  if (idata == NULL)
    return MEMIF_ERR_INVAL_ARG;

  return idata->c->on_interrupt (idata->c, idata->c->private_ctx, idata->qid);
}

int
memif_poll_event (memif_socket_handle_t sock, int timeout)
{
  memif_socket_t *ms = (memif_socket_t *) sock;
  struct epoll_event evt;
  int en = 0, err = MEMIF_ERR_SUCCESS;	/* 0 */
  memif_fd_event_type_t events = 0;
  uint64_t counter = 0;
  ssize_t r = 0;
  sigset_t sigset;

  if (ms == NULL)
    return MEMIF_ERR_INVAL_ARG;

  memset (&evt, 0, sizeof (evt));
  evt.events = EPOLLIN | EPOLLOUT;
  sigemptyset (&sigset);
  en = epoll_pwait (ms->epfd, &evt, 1, timeout, &sigset);
  if (en < 0)
    {
      err = errno;
      DBG ("epoll_pwait: %s", strerror (err));
      return memif_syscall_error_handler (err);
    }
  if (en > 0)
    {
      if (evt.events & EPOLLIN)
	events |= MEMIF_FD_EVENT_READ;
      if (evt.events & EPOLLOUT)
	events |= MEMIF_FD_EVENT_WRITE;
      if (evt.events & EPOLLERR)
	events |= MEMIF_FD_EVENT_ERROR;
      return memif_control_fd_handler (evt.data.ptr, events);
    }
  return MEMIF_ERR_SUCCESS;
}

int
memif_cancel_poll_event (memif_socket_handle_t sock)
{
  memif_socket_t *ms = (memif_socket_t *) sock;
  uint64_t counter = 1;
  ssize_t w = 0;

  if (ms->poll_cancel_fd == -1)
    return MEMIF_ERR_INVAL_ARG;
  w = write (ms->poll_cancel_fd, &counter, sizeof (counter));
  if (w < sizeof (counter))
    return MEMIF_ERR_INT_WRITE;

  return MEMIF_ERR_SUCCESS;
}

void
memif_close_queues (memif_socket_t *ms, memif_queue_t *queues, int nqueues)
{
  memif_fd_event_t fde;
  memif_queue_t *mq;
  void *ctx;

  int i;
  for (i = 0; i < nqueues; i++)
    {
      mq = &queues[i];
      if (mq != NULL)
	{
	  if (mq->int_fd > 0)
	    {
	      /* Stop listening for events */
	      fde.fd = mq->int_fd;
	      fde.type = MEMIF_FD_EVENT_DEL;
	      ctx = ms->epfd != -1 ? ms : ms->private_ctx;
	      ms->args.on_control_fd_update (fde, ctx);
	      close (mq->int_fd);
	    }
	  mq->int_fd = -1;
	}
    }
}

/* send disconnect msg and close interface */
int
memif_disconnect_internal (memif_connection_t * c)
{
  int err = MEMIF_ERR_SUCCESS, i;	/* 0 */
  memif_queue_t *mq;
  memif_socket_t *ms = (memif_socket_t *) c->args.socket;
  memif_fd_event_t fde;
  void *ctx;

  c->on_disconnect ((void *) c, c->private_ctx);

  /* Delete control channel */
  if (c->control_channel != NULL)
    memif_delete_control_channel (c->control_channel);

  if (c->tx_queues != NULL)
    {
      memif_close_queues (ms, c->tx_queues, c->tx_queues_num);
      ms->args.free (c->tx_queues);
      c->tx_queues = NULL;
    }
  c->tx_queues_num = 0;

  if (c->rx_queues != NULL)
    {
      memif_close_queues (ms, c->rx_queues, c->rx_queues_num);
      ms->args.free (c->rx_queues);
      c->rx_queues = NULL;
    }
  c->rx_queues_num = 0;

  /* TODO: Slave reuse regions */

  for (i = 0; i < c->regions_num; i++)
    {
      if (&c->regions[i] == NULL)
	continue;
      if (c->regions[i].is_external != 0)
	{
	  ms->del_external_region (c->regions[i].addr,
				   c->regions[i].region_size, c->regions[i].fd,
				   c->private_ctx);
	}
      else
	{
	  if (munmap (c->regions[i].addr, c->regions[i].region_size) < 0)
	    return memif_syscall_error_handler (errno);
	  if (c->regions[i].fd > 0)
	    close (c->regions[i].fd);
	  c->regions[i].fd = -1;
	}
    }
  ms->args.free (c->regions);
  c->regions = NULL;
  c->regions_num = 0;

  memset (&c->run_args, 0, sizeof (memif_conn_run_args_t));

  return err;
}

const char *
memif_get_socket_filename (memif_socket_handle_t sock)
{
  memif_socket_t *ms = (memif_socket_t *) sock;

  if (ms == NULL)
    return NULL;

  return (char *) ms->args.path;
}

int
memif_delete_socket (memif_socket_handle_t * sock)
{
  memif_socket_t *ms = (memif_socket_t *) * sock;
  memif_fd_event_t fde;
  void *ctx;

  /* check if socket is in use */
  if (ms == NULL || !TAILQ_EMPTY (&ms->master_interfaces) ||
      !TAILQ_EMPTY (&ms->slave_interfaces))
    return MEMIF_ERR_INVAL_ARG;

  if (ms->listener_fd > 0)
    {
      fde.fd = ms->listener_fd;
      fde.type = MEMIF_FD_EVENT_DEL;
      ctx = ms->epfd != -1 ? ms : ms->private_ctx;
      ms->args.on_control_fd_update (fde, ctx);
    }
  ms->listener_fd = -1;

  if (ms->poll_cancel_fd > 0)
    {
      fde.fd = ms->poll_cancel_fd;
      fde.type = MEMIF_FD_EVENT_DEL;
      ctx = ms->epfd != -1 ? ms : ms->private_ctx;
      ms->args.on_control_fd_update (fde, ctx);
    }
  ms->poll_cancel_fd = -1;

  if (ms->epfd > 0)
    close (ms->epfd);
  ms->epfd = -1;

  ms->args.free (ms);
  *sock = ms = NULL;

  return MEMIF_ERR_SUCCESS;
}

int
memif_delete (memif_conn_handle_t * conn)
{
  memif_connection_t *c = (memif_connection_t *) * conn;
  memif_socket_t *ms;
  int err = MEMIF_ERR_SUCCESS;

  if (c == NULL)
    {
      DBG ("no connection");
      return MEMIF_ERR_NOCONN;
    }

  err = memif_disconnect_internal (c);

  ms = (memif_socket_t *) c->args.socket;

  if (c->args.is_master)
    TAILQ_REMOVE (&ms->master_interfaces, c, next);
  else
    TAILQ_REMOVE (&ms->slave_interfaces, c, next);
  /* TODO: don't listen with empty interface queue */

  ms->args.free (c);
  c = NULL;

  *conn = c;
  return err;
}

int
memif_connect1 (memif_connection_t * c)
{
  memif_socket_t *ms;
  memif_region_t *mr;
  memif_queue_t *mq;
  int i;

  if (c == NULL)
    return MEMIF_ERR_INVAL_ARG;

  ms = (memif_socket_t *) c->args.socket;

  for (i = 0; i < c->regions_num; i++)
    {
      mr = &c->regions[i];
      if (mr != NULL)
	{
	  if (!mr->addr)
	    {
	      if (mr->is_external)
		{
		  if (ms->get_external_region_addr == NULL)
		    return MEMIF_ERR_INVAL_ARG;
		  mr->addr = ms->get_external_region_addr (
		    mr->region_size, mr->fd, c->private_ctx);
		}
	      else
		{
		  if (mr->fd < 0)
		    return MEMIF_ERR_NO_SHMFD;

		  if ((mr->addr =
			 mmap (NULL, mr->region_size, PROT_READ | PROT_WRITE,
			       MAP_SHARED, mr->fd, 0)) == MAP_FAILED)
		    {
		      return memif_syscall_error_handler (errno);
		    }
		}
	    }
	}
    }

  for (i = 0; i < c->rx_queues_num; i++)
    {
      mq = &c->rx_queues[i];
      if (mq != NULL)
	{
	  mq->ring = c->regions[mq->region].addr + mq->offset;
	  if (mq->ring->cookie != MEMIF_COOKIE)
	    {
	      DBG ("wrong cookie on rx ring %u", i);
	      return MEMIF_ERR_COOKIE;
	    }
	  mq->ring->head = mq->ring->tail = mq->last_head = mq->next_buf = 0;
	}
    }

  for (i = 0; i < c->tx_queues_num; i++)
    {
      mq = &c->tx_queues[i];
      if (mq != NULL)
	{
	  mq->ring = c->regions[mq->region].addr + mq->offset;
	  if (mq->ring->cookie != MEMIF_COOKIE)
	    {
	      DBG ("wrong cookie on tx ring %u", i);
	      return MEMIF_ERR_COOKIE;
	    }
	  mq->ring->head = mq->ring->tail = mq->last_head = mq->next_buf = 0;
	}
    }

  return 0;
}

static inline int
memif_add_region (memif_connection_t *conn, uint8_t has_buffers)
{
  memif_region_t *r;
  memif_socket_t *ms = (memif_socket_t *) conn->args.socket;

  r = ms->args.realloc (conn->regions,
			sizeof (memif_region_t) * ++conn->regions_num);
  if (r == NULL)
    return MEMIF_ERR_NOMEM;

  conn->regions = r;
  r = &conn->regions[conn->regions_num - 1];
  memset (r, 0, sizeof (memif_region_t));

  if (has_buffers != 0)
    {
      r->buffer_offset = 0;
    }
  else
    {
      r->buffer_offset =
	(conn->run_args.num_s2m_rings +
	 conn->run_args.num_m2s_rings) * (sizeof (memif_ring_t) +
					  sizeof (memif_desc_t) *
					  (1 << conn->
					   run_args.log2_ring_size));
    }

  r->region_size = (has_buffers == 0) ? r->buffer_offset : r->buffer_offset +
    conn->run_args.buffer_size * (1 << conn->run_args.log2_ring_size) *
    (conn->run_args.num_s2m_rings + conn->run_args.num_m2s_rings);

  if ((r->fd = memfd_create ("memif region 0", MFD_ALLOW_SEALING)) == -1)
    return memif_syscall_error_handler (errno);

  if ((fcntl (r->fd, F_ADD_SEALS, F_SEAL_SHRINK)) == -1)
    return memif_syscall_error_handler (errno);

  if ((ftruncate (r->fd, r->region_size)) == -1)
    return memif_syscall_error_handler (errno);

  if ((r->addr = mmap (NULL, r->region_size, PROT_READ | PROT_WRITE,
		       MAP_SHARED, r->fd, 0)) == MAP_FAILED)
    return memif_syscall_error_handler (errno);

  return MEMIF_ERR_SUCCESS;
}

static inline int
memif_init_queues (memif_connection_t *conn)
{
  int i, j;
  memif_ring_t *ring;
  memif_socket_t *ms = (memif_socket_t *) conn->args.socket;

  for (i = 0; i < conn->run_args.num_s2m_rings; i++)
    {
      ring = memif_get_ring (conn, MEMIF_RING_S2M, i);
      DBG ("RING: %p I: %d", ring, i);
      ring->head = ring->tail = 0;
      ring->cookie = MEMIF_COOKIE;
      ring->flags = 0;
      for (j = 0; j < (1 << conn->run_args.log2_ring_size); j++)
	{
	  uint32_t slot = i * (1 << conn->run_args.log2_ring_size) + j;
	  ring->desc[j].region = 1;
	  ring->desc[j].offset =
	    conn->regions[1].buffer_offset +
	    (uint32_t) (slot * conn->run_args.buffer_size);
	  ring->desc[j].length = conn->run_args.buffer_size;
	}
    }
  for (i = 0; i < conn->run_args.num_m2s_rings; i++)
    {
      ring = memif_get_ring (conn, MEMIF_RING_M2S, i);
      DBG ("RING: %p I: %d", ring, i);
      ring->head = ring->tail = 0;
      ring->cookie = MEMIF_COOKIE;
      ring->flags = 0;
      for (j = 0; j < (1 << conn->run_args.log2_ring_size); j++)
	{
	  uint32_t slot = (i + conn->run_args.num_s2m_rings) *
	    (1 << conn->run_args.log2_ring_size) + j;
	  ring->desc[j].region = 1;
	  ring->desc[j].offset =
	    conn->regions[1].buffer_offset +
	    (uint32_t) (slot * conn->run_args.buffer_size);
	  ring->desc[j].length = conn->run_args.buffer_size;
	}
    }
  memif_queue_t *mq;
  mq = (memif_queue_t *) ms->args.alloc (sizeof (memif_queue_t) *
					 conn->run_args.num_s2m_rings);
  if (mq == NULL)
    return MEMIF_ERR_NOMEM;

  int x;

  for (x = 0; x < conn->run_args.num_s2m_rings; x++)
    {
      if ((mq[x].int_fd = eventfd (0, EFD_NONBLOCK)) < 0)
	return memif_syscall_error_handler (errno);

      mq[x].ring = memif_get_ring (conn, MEMIF_RING_S2M, x);
      DBG ("RING: %p I: %d", mq[x].ring, x);
      mq[x].log2_ring_size = conn->run_args.log2_ring_size;
      mq[x].region = 0;
      mq[x].offset =
	(void *) mq[x].ring - (void *) conn->regions[mq->region].addr;
      mq[x].last_head = mq[x].last_tail = 0;
      mq[x].next_buf = 0;
    }
  conn->tx_queues = mq;
  conn->tx_queues_num = conn->run_args.num_s2m_rings;

  mq = (memif_queue_t *) ms->args.alloc (sizeof (memif_queue_t) *
					 conn->run_args.num_m2s_rings);
  if (mq == NULL)
    return MEMIF_ERR_NOMEM;

  for (x = 0; x < conn->run_args.num_m2s_rings; x++)
    {
      if ((mq[x].int_fd = eventfd (0, EFD_NONBLOCK)) < 0)
	return memif_syscall_error_handler (errno);

      mq[x].ring = memif_get_ring (conn, MEMIF_RING_M2S, x);
      DBG ("RING: %p I: %d", mq[x].ring, x);
      mq[x].log2_ring_size = conn->run_args.log2_ring_size;
      mq[x].region = 0;
      mq[x].offset =
	(void *) mq[x].ring - (void *) conn->regions[mq->region].addr;
      mq[x].last_head = mq[x].last_tail = 0;
      mq[x].next_buf = 0;
    }
  conn->rx_queues = mq;
  conn->rx_queues_num = conn->run_args.num_m2s_rings;

  return MEMIF_ERR_SUCCESS;
}

int
memif_init_regions_and_queues (memif_connection_t * conn)
{
  memif_region_t *r;
  memif_socket_t *ms = (memif_socket_t *) conn->args.socket;

  /* region 0. rings */
  memif_add_region (conn, /* has_buffers */ 0);

  /* region 1. buffers */
  if (ms->add_external_region)
    {
      r = (memif_region_t *) ms->args.realloc (
	conn->regions, sizeof (memif_region_t) * ++conn->regions_num);
      if (r == NULL)
	return MEMIF_ERR_NOMEM;
      conn->regions = r;

      conn->regions[1].region_size =
	conn->run_args.buffer_size * (1 << conn->run_args.log2_ring_size) *
	(conn->run_args.num_s2m_rings + conn->run_args.num_m2s_rings);
      conn->regions[1].buffer_offset = 0;
      ms->add_external_region (&conn->regions[1].addr,
			       conn->regions[1].region_size,
			       &conn->regions[1].fd, conn->private_ctx);
      conn->regions[1].is_external = 1;
    }
  else
    {
      memif_add_region (conn, 1);
    }

  memif_init_queues (conn);

  return 0;
}

int
memif_set_next_free_buffer (memif_conn_handle_t conn, uint16_t qid,
			    memif_buffer_t *buf)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (EXPECT_FALSE (c == NULL))
    return MEMIF_ERR_NOCONN;
  if (EXPECT_FALSE (qid >= c->tx_queues_num))
    return MEMIF_ERR_QID;
  if (EXPECT_FALSE (buf == NULL))
    return MEMIF_ERR_INVAL_ARG;

  uint16_t ring_size, ns;
  memif_queue_t *mq = &c->tx_queues[qid];
  memif_ring_t *ring = mq->ring;

  ring_size = (1 << mq->log2_ring_size);
  if (c->args.is_master)
    ns = ring->head - mq->next_buf;
  else
    ns = ring_size - mq->next_buf + ring->tail;

  if ((mq->next_buf - buf->desc_index) > ns)
    return MEMIF_ERR_INVAL_ARG;

  mq->next_buf = buf->desc_index;

  return MEMIF_ERR_SUCCESS;
}

static void
memif_buffer_enq_at_idx_internal (memif_queue_t *from_q, memif_queue_t *to_q,
				  memif_buffer_t *buf, uint16_t slot)
{
  uint16_t from_mask = (1 << from_q->log2_ring_size) - 1;
  uint16_t to_mask = (1 << to_q->log2_ring_size) - 1;
  memif_desc_t *from_d, *to_d, tmp_d;

  /* Get the descriptors */
  from_d = &from_q->ring->desc[buf->desc_index & from_mask];
  to_d = &to_q->ring->desc[slot & to_mask];

  /* Swap descriptors */
  tmp_d = *from_d;
  *from_d = *to_d;
  *to_d = tmp_d;

  /* Update descriptor index and queue for clients buffer */
  buf->desc_index = slot;
  buf->queue = to_q;
}

int
memif_buffer_requeue (memif_conn_handle_t conn, memif_buffer_t *buf_a,
		      memif_buffer_t *buf_b)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (EXPECT_FALSE (c == NULL))
    return MEMIF_ERR_NOCONN;
  if (EXPECT_FALSE (c->args.is_master))
    return MEMIF_ERR_INVAL_ARG;
  if ((buf_a == NULL) || (buf_b == NULL))
    return MEMIF_ERR_INVAL_ARG;

  int err;
  /* store buf_a information */
  uint16_t index_a = buf_a->desc_index;
  memif_queue_t *mq_a = buf_a->queue;

  /* swap buffers, buf_a was updated with new desc_index and queue */
  memif_buffer_enq_at_idx_internal ((memif_queue_t *) buf_a->queue,
				    (memif_queue_t *) buf_b->queue, buf_a,
				    buf_b->desc_index);

  /* update buf_b desc_index and queue */
  buf_b->desc_index = index_a;
  buf_b->queue = mq_a;

  return MEMIF_ERR_SUCCESS;
}

int
memif_buffer_enq_tx (memif_conn_handle_t conn, uint16_t qid,
		     memif_buffer_t * bufs, uint16_t count,
		     uint16_t * count_out)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (EXPECT_FALSE (c == NULL))
    return MEMIF_ERR_NOCONN;
  if (EXPECT_FALSE (c->control_channel == NULL))
    return MEMIF_ERR_DISCONNECTED;
  if (EXPECT_FALSE (qid >= c->tx_queues_num))
    return MEMIF_ERR_QID;
  if (EXPECT_FALSE (!count_out))
    return MEMIF_ERR_INVAL_ARG;
  if (EXPECT_FALSE (c->args.is_master))
    return MEMIF_ERR_INVAL_ARG;

  memif_queue_t *mq = &c->tx_queues[qid];
  memif_ring_t *ring = mq->ring;
  memif_buffer_t *b0;
  uint16_t mask = (1 << mq->log2_ring_size) - 1;
  uint16_t ring_size;
  uint16_t ns;
  memif_queue_t *bmq;
  int err = MEMIF_ERR_SUCCESS;	/* 0 */
  *count_out = 0;

  ring_size = (1 << mq->log2_ring_size);

  /* can only be called by slave */
  ns = ring_size - mq->next_buf + ring->tail;

  b0 = bufs;

  while (count && ns)
    {
      /* Swaps the descriptors, updates next_buf pointer and updates client
       * memif buffer */

      memif_buffer_enq_at_idx_internal ((memif_queue_t *) b0->queue, mq, b0,
					mq->next_buf);

      mq->next_buf++; /* mark the buffer as allocated */
      count--;
      ns--;
      b0++;
      *count_out += 1;
    }

  DBG ("allocated: %u/%u bufs. Next buffer pointer %d", *count_out, count,
       mq->next_buf);

  if (count)
    {
      DBG ("ring buffer full! qid: %u", qid);
      err = MEMIF_ERR_NOBUF_RING;
    }

  return err;
}

int
memif_buffer_alloc (memif_conn_handle_t conn, uint16_t qid,
		    memif_buffer_t * bufs, uint16_t count,
		    uint16_t * count_out, uint16_t size)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (EXPECT_FALSE (c == NULL))
    return MEMIF_ERR_NOCONN;
  if (EXPECT_FALSE (c->control_channel == NULL))
    return MEMIF_ERR_DISCONNECTED;
  uint8_t num =
    (c->args.is_master) ? c->run_args.num_m2s_rings : c->
    run_args.num_s2m_rings;
  if (EXPECT_FALSE (qid >= num))
    return MEMIF_ERR_QID;
  if (EXPECT_FALSE (!count_out))
    return MEMIF_ERR_INVAL_ARG;

  memif_socket_t *ms = (memif_socket_t *) c->args.socket;
  memif_queue_t *mq = &c->tx_queues[qid];
  memif_ring_t *ring = mq->ring;
  memif_buffer_t *b0;
  uint16_t mask = (1 << mq->log2_ring_size) - 1;
  uint16_t ring_size;
  uint16_t ns;
  int err = MEMIF_ERR_SUCCESS;	/* 0 */
  uint16_t dst_left, src_left;
  uint16_t saved_count;
  uint16_t saved_next_buf;
  uint16_t slot;
  memif_buffer_t *saved_b;
  *count_out = 0;

  ring_size = (1 << mq->log2_ring_size);

  if (c->args.is_master)
    ns = ring->head - mq->next_buf;
  else
    ns = ring_size - mq->next_buf + ring->tail;

  while (count && ns)
    {
      b0 = (bufs + *count_out);

      saved_b = b0;
      saved_count = count;
      saved_next_buf = mq->next_buf;

      b0->desc_index = mq->next_buf;
      ring->desc[mq->next_buf & mask].flags = 0;
      b0->flags = 0;

      /* slave can produce buffer with original length */
      dst_left = (c->args.is_master) ? ring->desc[mq->next_buf & mask].length :
				       c->run_args.buffer_size;
      src_left = size;

      while (src_left)
	{
	  if (EXPECT_FALSE (dst_left == 0))
	    {
	      if (count && ns)
		{
		  *count_out += 1;
		  mq->next_buf++;
		  ns--;

		  ring->desc[b0->desc_index & mask].flags |=
		    MEMIF_DESC_FLAG_NEXT;
		  b0->flags |= MEMIF_BUFFER_FLAG_NEXT;

		  b0 = (bufs + *count_out);
		  b0->desc_index = mq->next_buf;
		  dst_left = (c->args.is_master) ?
			       ring->desc[mq->next_buf & mask].length :
			       c->run_args.buffer_size;
		  ring->desc[mq->next_buf & mask].flags = 0;
		}
	      else
		{
		  /* rollback allocated chain buffers */
		  memset (saved_b, 0, sizeof (memif_buffer_t)
			  * (saved_count - count + 1));
		  *count_out -= saved_count - count;
		  mq->next_buf = saved_next_buf;
		  goto no_ns;
		}
	    }
	  b0->len = memif_min (dst_left, src_left);

	  /* slave resets buffer offset */
	  if (c->args.is_master == 0)
	    {
	      memif_desc_t *d = &ring->desc[slot & mask];
	      if (ms->get_external_buffer_offset)
		d->offset = ms->get_external_buffer_offset (c->private_ctx);
	      else
		d->offset = d->offset - (d->offset % c->run_args.buffer_size);
	    }
	  b0->data = memif_get_buffer (c, ring, mq->next_buf & mask);

	  src_left -= b0->len;
	  dst_left -= b0->len;
	}

      *count_out += 1;
      mq->next_buf++;
      ns--;
      count--;
    }

no_ns:

  DBG ("allocated: %u/%u bufs. Next buffer pointer %d", *count_out, count,
       mq->next_buf);

  if (count)
    {
      DBG ("ring buffer full! qid: %u", qid);
      err = MEMIF_ERR_NOBUF_RING;
    }

  return err;
}

int
memif_refill_queue (memif_conn_handle_t conn, uint16_t qid, uint16_t count,
		    uint16_t headroom)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (EXPECT_FALSE (c == NULL))
    return MEMIF_ERR_NOCONN;
  if (EXPECT_FALSE (c->control_channel == NULL))
    return MEMIF_ERR_DISCONNECTED;
  uint8_t num =
    (c->args.is_master) ? c->run_args.num_s2m_rings : c->
    run_args.num_m2s_rings;
  if (EXPECT_FALSE (qid >= num))
    return MEMIF_ERR_QID;
  memif_socket_t *ms = (memif_socket_t *) c->args.socket;
  memif_queue_t *mq = &c->rx_queues[qid];
  memif_ring_t *ring = mq->ring;
  uint16_t mask = (1 << mq->log2_ring_size) - 1;
  uint16_t slot, counter = 0;

  if (c->args.is_master)
    {
      MEMIF_MEMORY_BARRIER ();
      ring->tail =
	(ring->tail + count <=
	 mq->last_head) ? ring->tail + count : mq->last_head;
      return MEMIF_ERR_SUCCESS;
    }

  uint16_t head = ring->head;
  slot = head;
  uint16_t ns = (1 << mq->log2_ring_size) - head + mq->last_tail;
  count = (count < ns) ? count : ns;

  memif_desc_t *d;
  while (counter < count)
    {
      d = &ring->desc[slot & mask];
      d->region = 1;
      d->length = c->run_args.buffer_size - headroom;
      if (ms->get_external_buffer_offset)
	d->offset = ms->get_external_buffer_offset (c->private_ctx);
      else
	d->offset =
	  d->offset - (d->offset % c->run_args.buffer_size) + headroom;
      slot++;
      counter++;
    }

  MEMIF_MEMORY_BARRIER ();
  ring->head = slot;

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

int
memif_tx_burst (memif_conn_handle_t conn, uint16_t qid,
		memif_buffer_t * bufs, uint16_t count, uint16_t * tx)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (EXPECT_FALSE (c == NULL))
    return MEMIF_ERR_NOCONN;
  if (EXPECT_FALSE (c->control_channel == NULL))
    return MEMIF_ERR_DISCONNECTED;
  uint8_t num =
    (c->args.is_master) ? c->run_args.num_m2s_rings : c->
    run_args.num_s2m_rings;
  if (EXPECT_FALSE (qid >= num))
    return MEMIF_ERR_QID;
  if (EXPECT_FALSE (!tx))
    return MEMIF_ERR_INVAL_ARG;

  memif_queue_t *mq = &c->tx_queues[qid];
  memif_ring_t *ring = mq->ring;
  uint16_t mask = (1 << mq->log2_ring_size) - 1;
  memif_buffer_t *b0;
  memif_desc_t *d;
  int64_t data_offset;
  *tx = 0;
  int err = MEMIF_ERR_SUCCESS;

  if (EXPECT_FALSE (count == 0))
    return MEMIF_ERR_SUCCESS;

  uint16_t index;
  if (c->args.is_master)
    index = ring->tail;
  else
    index = ring->head;

  while (count)
    {
      b0 = (bufs + *tx);
      /* set error to MEMIF_ERR_INVAL_ARG and finish the sending process
       */
      if ((b0->desc_index & mask) != (index & mask))
	{
	  err = MEMIF_ERR_INVAL_ARG;
	  goto done;
	}
      d = &ring->desc[b0->desc_index & mask];
      d->length = b0->len;
      d->flags =
	((b0->flags & MEMIF_BUFFER_FLAG_NEXT) == 1) ? MEMIF_DESC_FLAG_NEXT : 0;
      if (!c->args.is_master)
	{
	  // reset headroom
	  d->offset = d->offset - (d->offset % c->run_args.buffer_size);
	  // calculate offset from user data
	  data_offset = b0->data - (d->offset + c->regions[d->region].addr);
	  if (data_offset != 0)
	    {
	      /* verify data offset and buffer length */
	      if ((data_offset < 0) ||
		  ((data_offset + b0->len) > c->run_args.buffer_size))
		{
		  DBG ("slot: %d, data_offset: %ld, length: %d",
		       b0->desc_index & mask, data_offset, b0->len);
		  err = MEMIF_ERR_INVAL_ARG;
		  goto done;
		}
	      d->offset += data_offset;
	    }
	}

#ifdef MEMIF_DBG_SHM
      printf ("offset: %-6d\n", ring->desc[b0->desc_index & mask].offset);
      printf ("data: %p\n",
	      memif_get_buffer (c, ring, b0->desc_index & mask));
      printf ("index: %u\n", b0->desc_index);
      print_bytes (memif_get_buffer (c, ring, b0->desc_index & mask),
		   ring->desc[b0->desc_index & mask].length, DBG_TX_BUF);
#endif /* MEMIF_DBG_SHM */

      *tx += 1;
      count--;
      index++;
    }

done:
  MEMIF_MEMORY_BARRIER ();
  if (c->args.is_master)
    ring->tail = b0->desc_index + 1;
  else
    ring->head = b0->desc_index + 1;

  if ((ring->flags & MEMIF_RING_FLAG_MASK_INT) == 0)
    {
      uint64_t a = 1;
      int r = write (mq->int_fd, &a, sizeof (a));
      if (r < 0)
	return MEMIF_ERR_INT_WRITE;
    }

  return err;
}

int
memif_rx_burst (memif_conn_handle_t conn, uint16_t qid,
		memif_buffer_t * bufs, uint16_t count, uint16_t * rx)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (EXPECT_FALSE (c == NULL))
    return MEMIF_ERR_NOCONN;
  if (EXPECT_FALSE (c->control_channel == NULL))
    return MEMIF_ERR_DISCONNECTED;
  uint8_t num =
    (c->args.is_master) ? c->run_args.num_s2m_rings : c->
    run_args.num_m2s_rings;
  if (EXPECT_FALSE (qid >= num))
    return MEMIF_ERR_QID;
  if (EXPECT_FALSE (!rx))
    return MEMIF_ERR_INVAL_ARG;

  memif_queue_t *mq = &c->rx_queues[qid];
  memif_ring_t *ring = mq->ring;
  uint16_t cur_slot, last_slot;
  uint16_t ns;
  uint16_t mask = (1 << mq->log2_ring_size) - 1;
  memif_buffer_t *b0;
  *rx = 0;

  uint64_t b;
  ssize_t r;

  cur_slot = (c->args.is_master) ? mq->last_head : mq->last_tail;
  last_slot = (c->args.is_master) ? ring->head : ring->tail;
  if (cur_slot == last_slot)
    {
      r = read (mq->int_fd, &b, sizeof (b));
      if (EXPECT_FALSE ((r == -1) && (errno != EAGAIN)))
			return memif_syscall_error_handler (errno);

      return MEMIF_ERR_SUCCESS;
    }

  ns = last_slot - cur_slot;

  while (ns && count)
    {
      b0 = (bufs + *rx);

      b0->desc_index = cur_slot;
      b0->data = memif_get_buffer (c, ring, cur_slot & mask);
      b0->len = ring->desc[cur_slot & mask].length;
      b0->flags = 0;
      /* slave resets buffer length */
      if (c->args.is_master == 0)
	{
	  ring->desc[cur_slot & mask].length = c->run_args.buffer_size;
	}

      if (ring->desc[cur_slot & mask].flags & MEMIF_DESC_FLAG_NEXT)
	{
	  b0->flags |= MEMIF_BUFFER_FLAG_NEXT;
	  ring->desc[cur_slot & mask].flags &= ~MEMIF_DESC_FLAG_NEXT;
	}

      b0->queue = mq;
#ifdef MEMIF_DBG_SHM
      printf ("data: %p\n", b0->data);
      printf ("index: %u\n", b0->desc_index);
      printf ("queue: %p\n", b0->queue);
      print_bytes (b0->data, b0->len, DBG_RX_BUF);
#endif /* MEMIF_DBG_SHM */
      ns--;
      *rx += 1;

      count--;
      cur_slot++;
    }

  if (c->args.is_master)
    mq->last_head = cur_slot;
  else
    mq->last_tail = cur_slot;

  if (ns)
    {
      DBG ("not enough buffers!");
      return MEMIF_ERR_NOBUF;
    }

  r = read (mq->int_fd, &b, sizeof (b));
  if (EXPECT_FALSE ((r == -1) && (errno != EAGAIN)))
    return memif_syscall_error_handler (errno);

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

int
memif_get_details (memif_conn_handle_t conn, memif_details_t * md,
		   char *buf, ssize_t buflen)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  memif_socket_t *ms;
  int err = MEMIF_ERR_SUCCESS, i;
  ssize_t l0 = 0, l1;

  if (c == NULL)
    return MEMIF_ERR_NOCONN;

  ms = (memif_socket_t *) c->args.socket;

  l1 = strlen ((char *) c->args.interface_name);
  if (l0 + l1 < buflen)
    {
      md->if_name =
	(uint8_t *) strcpy (buf + l0, (char *) c->args.interface_name);
      l0 += l1 + 1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  l1 = strlen ((char *) ms->args.app_name);
  if (l0 + l1 < buflen)
    {
      md->inst_name =
	(uint8_t *) strcpy (buf + l0, (char *) ms->args.app_name);
      l0 += l1 + 1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  l1 = strlen ((char *) c->remote_if_name);
  if (l0 + l1 < buflen)
    {
      md->remote_if_name =
	(uint8_t *) strcpy (buf + l0, (char *) c->remote_if_name);
      l0 += l1 + 1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  l1 = strlen ((char *) c->remote_name);
  if (l0 + l1 < buflen)
    {
      md->remote_inst_name =
	(uint8_t *) strcpy (buf + l0, (char *) c->remote_name);
      l0 += l1 + 1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  md->id = c->args.interface_id;

  if (strlen ((char *) c->args.secret) > 0)
    {
      l1 = strlen ((char *) c->args.secret);
      if (l0 + l1 < buflen)
	{
	  md->secret = (uint8_t *) strcpy (buf + l0, (char *) c->args.secret);
	  l0 += l1 + 1;
	}
      else
	err = MEMIF_ERR_NOBUF_DET;
    }

  md->role = (c->args.is_master) ? 0 : 1;
  md->mode = c->args.mode;

  l1 = 108;
  if (l0 + l1 < buflen)
    {
      md->socket_path = (uint8_t *) memcpy (buf + l0, ms->args.path, 108);
      l0 += l1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  l1 = strlen ((char *) c->remote_disconnect_string);
  if (l0 + l1 < buflen)
    {
      md->error =
	(uint8_t *) strcpy (buf + l0, (char *) c->remote_disconnect_string);
      l0 += l1 + 1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  md->regions_num = c->regions_num;
  l1 = sizeof (memif_region_details_t) * md->regions_num;
  if (l0 + l1 <= buflen)
    {
      md->regions = (memif_region_details_t *) (buf + l0);
      for (i = 0; i < md->regions_num; i++)
	{
	  md->regions[i].index = i;
	  md->regions[i].addr = c->regions[i].addr;
	  md->regions[i].size = c->regions[i].region_size;
	  md->regions[i].fd = c->regions[i].fd;
	  md->regions[i].is_external = c->regions[i].is_external;
	}
      l0 += l1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  md->rx_queues_num =
    (c->args.is_master) ? c->run_args.num_s2m_rings : c->
    run_args.num_m2s_rings;

  l1 = sizeof (memif_queue_details_t) * md->rx_queues_num;
  if (l0 + l1 <= buflen)
    {
      md->rx_queues = (memif_queue_details_t *) (buf + l0);
      for (i = 0; i < md->rx_queues_num; i++)
	{
	  md->rx_queues[i].region = c->rx_queues[i].region;
	  md->rx_queues[i].qid = i;
	  md->rx_queues[i].ring_size = (1 << c->rx_queues[i].log2_ring_size);
	  md->rx_queues[i].flags = c->rx_queues[i].ring->flags;
	  md->rx_queues[i].head = c->rx_queues[i].ring->head;
	  md->rx_queues[i].tail = c->rx_queues[i].ring->tail;
	  md->rx_queues[i].buffer_size = c->run_args.buffer_size;
	}
      l0 += l1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  md->tx_queues_num =
    (c->args.is_master) ? c->run_args.num_m2s_rings : c->
    run_args.num_s2m_rings;

  l1 = sizeof (memif_queue_details_t) * md->tx_queues_num;
  if (l0 + l1 <= buflen)
    {
      md->tx_queues = (memif_queue_details_t *) (buf + l0);
      for (i = 0; i < md->tx_queues_num; i++)
	{
	  md->tx_queues[i].region = c->tx_queues[i].region;
	  md->tx_queues[i].qid = i;
	  md->tx_queues[i].ring_size = (1 << c->tx_queues[i].log2_ring_size);
	  md->tx_queues[i].flags = c->tx_queues[i].ring->flags;
	  md->tx_queues[i].head = c->tx_queues[i].ring->head;
	  md->tx_queues[i].tail = c->tx_queues[i].ring->tail;
	  md->tx_queues[i].buffer_size = c->run_args.buffer_size;
	}
      l0 += l1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  /* This is not completely true, clients should relay on
   * on_connect/on_disconnect callbacks */
  md->link_up_down = (c->control_channel != NULL) ? 1 : 0;

  return err;			/* 0 */
}

int
memif_get_queue_efd (memif_conn_handle_t conn, uint16_t qid, int *efd)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  uint8_t num;

  *efd = -1;
  if (c == NULL)
    return MEMIF_ERR_NOCONN;
  if (c->control_channel == NULL)
    return MEMIF_ERR_DISCONNECTED;

  num =
    (c->args.is_master) ? c->run_args.num_s2m_rings : c->
    run_args.num_m2s_rings;
  if (qid >= num)
    return MEMIF_ERR_QID;

  *efd = c->rx_queues[qid].int_fd;

  return MEMIF_ERR_SUCCESS;
}
