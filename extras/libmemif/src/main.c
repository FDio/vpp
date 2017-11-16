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

/* memif protocol msg, ring and descriptor definitions */
#include <memif.h>
/* memif api */
#include <libmemif.h>
/* socket messaging functions */
#include <socket.h>
/* private structs and functions */
#include <memif_private.h>

#define ERRLIST_LEN 38
#define MAX_ERRBUF_LEN 256

#if __x86_x64__
#define MEMIF_MEMORY_BARRIER() __builtin_ia32_sfence ()
#else
#define MEMIF_MEMORY_BARRIER() __sync_synchronize ()
#endif /* __x86_x64__ */

libmemif_main_t libmemif_main;
int memif_epfd;
int poll_cancel_fd = -1;

static char memif_buf[MAX_ERRBUF_LEN];

const char *memif_errlist[ERRLIST_LEN] = {	/* MEMIF_ERR_SUCCESS */
  "Success.",
  /* MEMIF_ERR_SYSCALL */
  "Unspecified syscall error (build with -DMEMIF_DBG or make debug).",
  /* MEMIF_ERR_ACCES */
  "Permission to resoure denied.",
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
  "Memif connection handle does not point to existing conenction",
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
  "Not enough space for memif details in suplied buffer. String data might be malformed.",
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
  "Slave cannot accept connection reqest.",
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
  "Maximum log2 ring size is 15"
};

#define MEMIF_ERR_UNDEFINED "undefined error"

char *
memif_strerror (int err_code)
{
  if (err_code >= ERRLIST_LEN)
    {
      strncpy (memif_buf, MEMIF_ERR_UNDEFINED, strlen (MEMIF_ERR_UNDEFINED));
      memif_buf[strlen (MEMIF_ERR_UNDEFINED)] = '\0';
    }
  else
    {
      strncpy (memif_buf, memif_errlist[err_code],
	       strlen (memif_errlist[err_code]));
      memif_buf[strlen (memif_errlist[err_code])] = '\0';
    }
  return memif_buf;
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
  DBG_UNIX ("%s", strerror (err_code));

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
  if (err_code == ECONNREFUSED)
    return MEMIF_ERR_SUCCESS;
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
memif_add_epoll_fd (int fd, uint32_t events)
{
  if (fd < 0)
    {
      DBG ("invalid fd %d", fd);
      return -1;
    }
  struct epoll_event evt;
  memset (&evt, 0, sizeof (evt));
  evt.events = events;
  evt.data.fd = fd;
  if (epoll_ctl (memif_epfd, EPOLL_CTL_ADD, fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG ("fd %d added to epoll", fd);
  return 0;
}

static int
memif_mod_epoll_fd (int fd, uint32_t events)
{
  if (fd < 0)
    {
      DBG ("invalid fd %d", fd);
      return -1;
    }
  struct epoll_event evt;
  memset (&evt, 0, sizeof (evt));
  evt.events = events;
  evt.data.fd = fd;
  if (epoll_ctl (memif_epfd, EPOLL_CTL_MOD, fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG ("fd %d moddified on epoll", fd);
  return 0;
}

static int
memif_del_epoll_fd (int fd)
{
  if (fd < 0)
    {
      DBG ("invalid fd %d", fd);
      return -1;
    }
  struct epoll_event evt;
  memset (&evt, 0, sizeof (evt));
  if (epoll_ctl (memif_epfd, EPOLL_CTL_DEL, fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG ("fd %d removed from epoll", fd);
  return 0;
}

int
memif_control_fd_update (int fd, uint8_t events)
{
  if (events & MEMIF_FD_EVENT_DEL)
    return memif_del_epoll_fd (fd);

  uint32_t evt = 0;
  if (events & MEMIF_FD_EVENT_READ)
    evt |= EPOLLIN;
  if (events & MEMIF_FD_EVENT_WRITE)
    evt |= EPOLLOUT;

  if (events & MEMIF_FD_EVENT_MOD)
    return memif_mod_epoll_fd (fd, evt);

  return memif_add_epoll_fd (fd, evt);
}

int
add_list_elt (memif_list_elt_t * e, memif_list_elt_t ** list, uint16_t * len)
{
  libmemif_main_t *lm = &libmemif_main;

  int i;
  for (i = 0; i < *len; i++)
    {
      if ((*list)[i].data_struct == NULL)
	{
	  (*list)[i].key = e->key;
	  (*list)[i].data_struct = e->data_struct;
	  return i;
	}
    }
  memif_list_elt_t *tmp;
  tmp = realloc (*list, sizeof (memif_list_elt_t) * *len * 2);
  if (tmp == NULL)
    return -1;

  for (i = *len; i < *len * 2; i++)
    {
      tmp[i].key = -1;
      tmp[i].data_struct = NULL;
    }

  tmp[*len].key = e->key;
  tmp[*len].data_struct = e->data_struct;
  i = *len;
  *len = *len * 2;
  *list = tmp;

  return i;
}

int
get_list_elt (memif_list_elt_t ** e, memif_list_elt_t * list, uint16_t len,
	      int key)
{
  if (key == -1)
    {
      *e = NULL;
      return -1;
    }
  int i;
  for (i = 0; i < len; i++)
    {
      if (list[i].key == key)
	{
	  *e = &list[i];
	  return 0;
	}
    }
  *e = NULL;
  return -1;
}

/* does not free memory, only marks element as free */
int
free_list_elt (memif_list_elt_t * list, uint16_t len, int key)
{
  int i;
  for (i = 0; i < len; i++)
    {
      if (list[i].key == key)
	{
	  list[i].key = -1;
	  list[i].data_struct = NULL;
	  return 0;
	}
    }

  return -1;
}

int
free_list_elt_ctx (memif_list_elt_t * list, uint16_t len,
		   memif_connection_t * ctx)
{
  int i;
  for (i = 0; i < len; i++)
    {
      if (list[i].key == -1)
	{
	  if (list[i].data_struct == ctx)
	    {
	      list[i].data_struct = NULL;
	      return 0;
	    }
	}
    }

  return -1;
}

static void
memif_control_fd_update_register (memif_control_fd_update_t * cb)
{
  libmemif_main_t *lm = &libmemif_main;
  lm->control_fd_update = cb;
}

int
memif_init (memif_control_fd_update_t * on_control_fd_update, char *app_name)
{
  int err = MEMIF_ERR_SUCCESS;	/* 0 */
  libmemif_main_t *lm = &libmemif_main;

  if (app_name)
    {
      lm->app_name = malloc (strlen (app_name) + sizeof (char));
      memset (lm->app_name, 0, strlen (app_name) + sizeof (char));
      strncpy ((char *) lm->app_name, app_name, strlen (app_name));
    }
  else
    {
      lm->app_name = malloc (strlen (MEMIF_DEFAULT_APP_NAME) + sizeof (char));
      memset (lm->app_name, 0, strlen (app_name) + sizeof (char));
      strncpy ((char *) lm->app_name, MEMIF_DEFAULT_APP_NAME,
	       strlen (MEMIF_DEFAULT_APP_NAME));
    }

  /* register control fd update callback */
  if (on_control_fd_update != NULL)
    memif_control_fd_update_register (on_control_fd_update);
  else
    {
      memif_epfd = epoll_create (1);
      memif_control_fd_update_register (memif_control_fd_update);
      if ((poll_cancel_fd = eventfd (0, EFD_NONBLOCK)) < 0)
	{
	  err = errno;
	  DBG ("eventfd: %s", strerror (err));
	  return memif_syscall_error_handler (err);
	}
      lm->control_fd_update (poll_cancel_fd, MEMIF_FD_EVENT_READ);
      DBG ("libmemif event polling initialized");
    }

  memset (&lm->ms, 0, sizeof (memif_socket_t));

  lm->control_list_len = 2;
  lm->interrupt_list_len = 2;
  lm->listener_list_len = 1;
  lm->pending_list_len = 1;

  lm->control_list =
    malloc (sizeof (memif_list_elt_t) * lm->control_list_len);
  lm->interrupt_list =
    malloc (sizeof (memif_list_elt_t) * lm->interrupt_list_len);
  lm->listener_list =
    malloc (sizeof (memif_list_elt_t) * lm->listener_list_len);
  lm->pending_list =
    malloc (sizeof (memif_list_elt_t) * lm->pending_list_len);

  int i;
  for (i = 0; i < lm->control_list_len; i++)
    {
      lm->control_list[i].key = -1;
      lm->control_list[i].data_struct = NULL;
    }
  for (i = 0; i < lm->interrupt_list_len; i++)
    {
      lm->interrupt_list[i].key = -1;
      lm->interrupt_list[i].data_struct = NULL;
    }
  for (i = 0; i < lm->listener_list_len; i++)
    {
      lm->listener_list[i].key = -1;
      lm->listener_list[i].data_struct = NULL;
    }
  for (i = 0; i < lm->pending_list_len; i++)
    {
      lm->pending_list[i].key = -1;
      lm->pending_list[i].data_struct = NULL;
    }

  lm->disconn_slaves = 0;

  lm->timerfd = timerfd_create (CLOCK_REALTIME, TFD_NONBLOCK);
  if (lm->timerfd < 0)
    {
      err = errno;
      DBG ("timerfd: %s", strerror (err));
      return memif_syscall_error_handler (err);
    }

  lm->arm.it_value.tv_sec = 2;
  lm->arm.it_value.tv_nsec = 0;
  lm->arm.it_interval.tv_sec = 2;
  lm->arm.it_interval.tv_nsec = 0;
  memset (&lm->disarm, 0, sizeof (lm->disarm));

  if (lm->control_fd_update (lm->timerfd, MEMIF_FD_EVENT_READ) < 0)
    {
      DBG ("callback type memif_control_fd_update_t error!");
      return MEMIF_ERR_CB_FDUPDATE;
    }

  return 0;
}

static inline memif_ring_t *
memif_get_ring (memif_connection_t * conn, memif_ring_type_t type,
		uint16_t ring_num)
{
  if (&conn->regions[0] == NULL)
    return NULL;
  void *p = conn->regions[0].shm;
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
memif_create (memif_conn_handle_t * c, memif_conn_args_t * args,
	      memif_connection_update_t * on_connect,
	      memif_connection_update_t * on_disconnect,
	      memif_interrupt_t * on_interrupt, void *private_ctx)
{
  int err, i, index, sockfd = -1;
  memif_list_elt_t list_elt;
  memif_connection_t *conn = (memif_connection_t *) * c;
  if (conn != NULL)
    {
      DBG ("This handle already points to existing memif.");
      return MEMIF_ERR_CONN;
    }
  conn = (memif_connection_t *) malloc (sizeof (memif_connection_t));
  if (conn == NULL)
    {
      err = memif_syscall_error_handler (errno);
      goto error;
    }
  memset (conn, 0, sizeof (memif_connection_t));

  libmemif_main_t *lm = &libmemif_main;

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
  conn->msg_queue = NULL;
  conn->regions = NULL;
  conn->tx_queues = NULL;
  conn->rx_queues = NULL;
  conn->fd = -1;
  conn->on_connect = on_connect;
  conn->on_disconnect = on_disconnect;
  conn->on_interrupt = on_interrupt;
  conn->private_ctx = private_ctx;
  memset (&conn->run_args, 0, sizeof (memif_conn_run_args_t));

  uint8_t l = strlen ((char *) args->interface_name);
  strncpy ((char *) conn->args.interface_name, (char *) args->interface_name,
	   l);

  l = strlen ((char *) args->instance_name);
  strncpy ((char *) conn->args.instance_name, (char *) args->instance_name,
	   l);

  /* allocate and initialize socket_filename so it can be copyed to sun_path
     without memory leaks */
  conn->args.socket_filename = malloc (sizeof (char *) * 108);
  memset (conn->args.socket_filename, 0, 108 * sizeof (char *));

  if (args->socket_filename)
    {
      if (conn->args.socket_filename == NULL)
	{
	  err = memif_syscall_error_handler (errno);
	  goto error;
	}
      strncpy ((char *) conn->args.socket_filename,
	       (char *) args->socket_filename,
	       strlen ((char *) args->socket_filename));
    }
  else
    {
      uint16_t sdl = strlen (MEMIF_DEFAULT_SOCKET_DIR);
      uint16_t sfl = strlen (MEMIF_DEFAULT_SOCKET_FILENAME);
      if (conn->args.socket_filename == NULL)
	{
	  err = memif_syscall_error_handler (errno);
	  goto error;
	}
      strncpy ((char *) conn->args.socket_filename,
	       MEMIF_DEFAULT_SOCKET_DIR, sdl);
      conn->args.socket_filename[sdl] = '/';
      strncpy ((char *) (conn->args.socket_filename + 1 + sdl),
	       MEMIF_DEFAULT_SOCKET_FILENAME, sfl);
    }

  if (args->secret)
    {
      l = strlen ((char *) args->secret);
      strncpy ((char *) conn->args.secret, (char *) args->secret, l);
    }

  if (conn->args.is_master)
    {
      conn->run_args.buffer_size = conn->args.buffer_size;
      memif_socket_t *ms;
      memif_list_elt_t elt;
      for (i = 0; i < lm->listener_list_len; i++)
	{
	  if ((ms =
	       (memif_socket_t *) lm->listener_list[i].data_struct) != NULL)
	    {
	      if (strncmp
		  ((char *) ms->filename, (char *) conn->args.socket_filename,
		   strlen ((char *) ms->filename)) == 0)
		{
		  /* add interface to listener socket */
		  elt.key = conn->args.interface_id;
		  *c = elt.data_struct = conn;
		  add_list_elt (&elt, &ms->interface_list,
				&ms->interface_list_len);
		  ms->use_count++;
		  conn->listener_fd = ms->fd;
		  break;
		}
	    }
	  else
	    {
	      struct stat file_stat;
	      if (stat ((char *) conn->args.socket_filename, &file_stat) == 0)
		{
		  if (S_ISSOCK (file_stat.st_mode))
		    unlink ((char *) conn->args.socket_filename);
		  else
		    return memif_syscall_error_handler (errno);
		}
	      DBG ("creating socket file");
	      ms = malloc (sizeof (memif_socket_t));
	      ms->filename =
		malloc (strlen ((char *) conn->args.socket_filename) +
			sizeof (char));
	      memset (ms->filename, 0,
		      strlen ((char *) conn->args.socket_filename) +
		      sizeof (char));
	      strncpy ((char *) ms->filename,
		       (char *) conn->args.socket_filename,
		       strlen ((char *) conn->args.socket_filename));
	      ms->interface_list_len = 1;
	      ms->interface_list =
		malloc (sizeof (memif_list_elt_t) * ms->interface_list_len);
	      ms->interface_list[0].key = -1;
	      ms->interface_list[0].data_struct = NULL;
	      struct sockaddr_un un = { 0 };
	      int on = 1;

	      ms->fd = socket (AF_UNIX, SOCK_SEQPACKET, 0);
	      if (ms->fd < 0)
		{
		  err = memif_syscall_error_handler (errno);
		  goto error;
		}
	      DBG ("socket %d created", ms->fd);
	      un.sun_family = AF_UNIX;
	      strncpy ((char *) un.sun_path, (char *) ms->filename,
		       sizeof (un.sun_path) - 1);
	      DBG ("sockopt");
	      if (setsockopt
		  (ms->fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof (on)) < 0)
		{
		  err = memif_syscall_error_handler (errno);
		  goto error;
		}
	      DBG ("bind");
	      if (bind (ms->fd, (struct sockaddr *) &un, sizeof (un)) < 0)
		{
		  err = memif_syscall_error_handler (errno);
		  goto error;
		}
	      DBG ("listen");
	      if (listen (ms->fd, 1) < 0)
		{
		  err = memif_syscall_error_handler (errno);
		  goto error;
		}
	      DBG ("stat");
	      if (stat ((char *) ms->filename, &file_stat) < 0)
		{
		  err = memif_syscall_error_handler (errno);
		  goto error;
		}

	      /* add interface to listener socket */
	      elt.key = conn->args.interface_id;
	      *c = elt.data_struct = conn;
	      add_list_elt (&elt, &ms->interface_list,
			    &ms->interface_list_len);
	      ms->use_count = 1;
	      conn->listener_fd = ms->fd;

	      /* add listener socket to libmemif main */
	      elt.key = ms->fd;
	      elt.data_struct = ms;
	      add_list_elt (&elt, &lm->listener_list, &lm->listener_list_len);
	      lm->control_fd_update (ms->fd, MEMIF_FD_EVENT_READ);
	      break;
	    }
	}
    }
  else
    {
      if (lm->disconn_slaves == 0)
	{
	  if (timerfd_settime (lm->timerfd, 0, &lm->arm, NULL) < 0)
	    {
	      err = memif_syscall_error_handler (errno);
	      goto error;
	    }
	}

      lm->disconn_slaves++;

      list_elt.key = -1;
      *c = list_elt.data_struct = conn;
      if ((index =
	   add_list_elt (&list_elt, &lm->control_list,
			 &lm->control_list_len)) < 0)
	{
	  err = MEMIF_ERR_NOMEM;
	  goto error;
	}
    }

  conn->index = index;

  return 0;

error:
  if (sockfd > 0)
    close (sockfd);
  sockfd = -1;
  if (conn->args.socket_filename)
    free (conn->args.socket_filename);
  if (conn != NULL)
    free (conn);
  *c = conn = NULL;
  return err;
}

int
memif_control_fd_handler (int fd, uint8_t events)
{
  int i, rv, sockfd = -1, err = MEMIF_ERR_SUCCESS;	/* 0 */
  uint16_t num;
  memif_list_elt_t *e = NULL;
  memif_connection_t *conn;
  libmemif_main_t *lm = &libmemif_main;
  if (fd == lm->timerfd)
    {
      uint64_t b;
      ssize_t size;
      size = read (fd, &b, sizeof (b));
      for (i = 0; i < lm->control_list_len; i++)
	{
	  if ((lm->control_list[i].key < 0)
	      && (lm->control_list[i].data_struct != NULL))
	    {
	      conn = lm->control_list[i].data_struct;
	      if (conn->args.is_master)
		continue;

	      struct sockaddr_un sun;
	      sockfd = socket (AF_UNIX, SOCK_SEQPACKET, 0);
	      if (sockfd < 0)
		{
		  err = memif_syscall_error_handler (errno);
		  goto error;
		}

	      sun.sun_family = AF_UNIX;

	      strncpy (sun.sun_path, conn->args.socket_filename,
		       sizeof (sun.sun_path) - 1);

	      if (connect (sockfd, (struct sockaddr *) &sun,
			   sizeof (struct sockaddr_un)) == 0)
		{
		  conn->fd = sockfd;
		  conn->read_fn = memif_conn_fd_read_ready;
		  conn->write_fn = memif_conn_fd_write_ready;
		  conn->error_fn = memif_conn_fd_error;

		  lm->control_list[conn->index].key = conn->fd;

		  lm->control_fd_update (sockfd,
					 MEMIF_FD_EVENT_READ |
					 MEMIF_FD_EVENT_WRITE);

		  lm->disconn_slaves--;
		  if (lm->disconn_slaves == 0)
		    {
		      if (timerfd_settime (lm->timerfd, 0, &lm->disarm, NULL)
			  < 0)
			{
			  err = memif_syscall_error_handler (errno);
			  goto error;
			}
		    }
		}
	      else
		{
		  err = memif_syscall_error_handler (errno);
		  goto error;
		}
	    }
	}
    }
  else
    {
      get_list_elt (&e, lm->interrupt_list, lm->interrupt_list_len, fd);
      if (e != NULL)
	{
	  if (((memif_connection_t *) e->data_struct)->on_interrupt != NULL)
	    {
	      num =
		(((memif_connection_t *) e->data_struct)->
		 args.is_master) ? ((memif_connection_t *) e->
				    data_struct)->run_args.
		num_s2m_rings : ((memif_connection_t *) e->data_struct)->
		run_args.num_m2s_rings;
	      for (i = 0; i < num; i++)
		{
		  if (((memif_connection_t *) e->data_struct)->
		      rx_queues[i].int_fd == fd)
		    {
		      ((memif_connection_t *) e->data_struct)->
			on_interrupt ((void *) e->data_struct,
				      ((memif_connection_t *) e->
				       data_struct)->private_ctx, i);
		      return MEMIF_ERR_SUCCESS;
		    }
		}
	    }
	  return MEMIF_ERR_SUCCESS;
	}
      get_list_elt (&e, lm->listener_list, lm->listener_list_len, fd);
      if (e != NULL)
	{
	  memif_conn_fd_accept_ready ((memif_socket_t *) e->data_struct);
	  return MEMIF_ERR_SUCCESS;
	}

      get_list_elt (&e, lm->pending_list, lm->pending_list_len, fd);
      if (e != NULL)
	{
	  memif_read_ready (fd);
	  return MEMIF_ERR_SUCCESS;
	}

      get_list_elt (&e, lm->control_list, lm->control_list_len, fd);
      if (e != NULL)
	{
	  if (events & MEMIF_FD_EVENT_READ)
	    {
	      err =
		((memif_connection_t *) e->data_struct)->
		read_fn (e->data_struct);
	      if (err != MEMIF_ERR_SUCCESS)
		return err;
	    }
	  if (events & MEMIF_FD_EVENT_WRITE)
	    {
	      err =
		((memif_connection_t *) e->data_struct)->
		write_fn (e->data_struct);
	      if (err != MEMIF_ERR_SUCCESS)
		return err;
	    }
	  if (events & MEMIF_FD_EVENT_ERROR)
	    {
	      err =
		((memif_connection_t *) e->data_struct)->
		error_fn (e->data_struct);
	      if (err != MEMIF_ERR_SUCCESS)
		return err;
	    }
	}
    }

  return MEMIF_ERR_SUCCESS;	/* 0 */

error:
  if (sockfd > 0)
    close (sockfd);
  sockfd = -1;
  return err;
}

int
memif_poll_event (int timeout)
{
  libmemif_main_t *lm = &libmemif_main;
  memif_list_elt_t *elt;
  struct epoll_event evt, *e;
  int en = 0, err = MEMIF_ERR_SUCCESS, i = 0;	/* 0 */
  uint16_t num;
  uint32_t events = 0;
  uint64_t counter = 0;
  ssize_t r = 0;
  memset (&evt, 0, sizeof (evt));
  evt.events = EPOLLIN | EPOLLOUT;
  sigset_t sigset;
  sigemptyset (&sigset);
  en = epoll_pwait (memif_epfd, &evt, 1, timeout, &sigset);
  if (en < 0)
    {
      err = errno;
      DBG ("epoll_pwait: %s", strerror (err));
      return memif_syscall_error_handler (err);
    }
  if (en > 0)
    {
      if (evt.data.fd == poll_cancel_fd)
	{
	  r = read (evt.data.fd, &counter, sizeof (counter));
	  return MEMIF_ERR_POLL_CANCEL;
	}
      if (evt.events & EPOLLIN)
	events |= MEMIF_FD_EVENT_READ;
      if (evt.events & EPOLLOUT)
	events |= MEMIF_FD_EVENT_WRITE;
      if (evt.events & EPOLLERR)
	events |= MEMIF_FD_EVENT_ERROR;
      err = memif_control_fd_handler (evt.data.fd, events);
      return err;
    }
  return 0;
}

int
memif_cancel_poll_event ()
{
  uint64_t counter = 1;
  ssize_t w = 0;

  if (poll_cancel_fd == -1)
    return 0;
  w = write (poll_cancel_fd, &counter, sizeof (counter));
  if (w < sizeof (counter))
    return MEMIF_ERR_INT_WRITE;

  return 0;
}

static void
memif_msg_queue_free (memif_msg_queue_elt_t ** e)
{
  if (*e == NULL)
    return;
  memif_msg_queue_free (&(*e)->next);
  free (*e);
  *e = NULL;
  return;
}

/* send disconnect msg and close interface */
int
memif_disconnect_internal (memif_connection_t * c)
{
  if (c == NULL)
    {
      DBG ("no connection");
      return MEMIF_ERR_NOCONN;
    }
  uint16_t num;
  int err = MEMIF_ERR_SUCCESS, i;	/* 0 */
  memif_queue_t *mq;
  libmemif_main_t *lm = &libmemif_main;
  memif_list_elt_t *e;

  c->on_disconnect ((void *) c, c->private_ctx);

  if (c->fd > 0)
    {
      memif_msg_send_disconnect (c->fd, "interface deleted", 0);
      lm->control_fd_update (c->fd, MEMIF_FD_EVENT_DEL);
      close (c->fd);
    }
  get_list_elt (&e, lm->control_list, lm->control_list_len, c->fd);
  if (e != NULL)
    {
      if (c->args.is_master)
	free_list_elt (lm->control_list, lm->control_list_len, c->fd);
      e->key = c->fd = -1;
    }

  if (c->tx_queues != NULL)
    {
      num =
	(c->args.is_master) ? c->run_args.num_m2s_rings : c->
	run_args.num_s2m_rings;
      for (i = 0; i < num; i++)
	{
	  mq = &c->tx_queues[i];
	  if (mq != NULL)
	    {
	      if (mq->int_fd > 0)
		close (mq->int_fd);
	      free_list_elt (lm->interrupt_list, lm->interrupt_list_len,
			     mq->int_fd);
	      mq->int_fd = -1;
	    }
	}
      free (c->tx_queues);
      c->tx_queues = NULL;
    }

  if (c->rx_queues != NULL)
    {
      num =
	(c->args.is_master) ? c->run_args.num_s2m_rings : c->
	run_args.num_m2s_rings;
      for (i = 0; i < num; i++)
	{
	  mq = &c->rx_queues[i];
	  if (mq != NULL)
	    {
	      if (mq->int_fd > 0)
		{
		  if (c->on_interrupt != NULL)
		    lm->control_fd_update (mq->int_fd, MEMIF_FD_EVENT_DEL);
		  close (mq->int_fd);
		}
	      free_list_elt (lm->interrupt_list, lm->interrupt_list_len,
			     mq->int_fd);
	      mq->int_fd = -1;
	    }
	}
      free (c->rx_queues);
      c->rx_queues = NULL;
    }

  if (c->regions != NULL)
    {
      if (munmap (c->regions[0].shm, c->regions[0].region_size) < 0)
	return memif_syscall_error_handler (errno);
      if (c->regions[0].fd > 0)
	close (c->regions[0].fd);
      c->regions[0].fd = -1;
      free (c->regions);
      c->regions = NULL;
    }

  memset (&c->run_args, 0, sizeof (memif_conn_run_args_t));

  memif_msg_queue_free (&c->msg_queue);

  if (!(c->args.is_master))
    {
      if (lm->disconn_slaves == 0)
	{
	  if (timerfd_settime (lm->timerfd, 0, &lm->arm, NULL) < 0)
	    {
	      err = memif_syscall_error_handler (errno);
	      DBG_UNIX ("timerfd_settime: arm");
	    }
	}
      lm->disconn_slaves++;
    }

  return err;
}

int
memif_delete (memif_conn_handle_t * conn)
{
  memif_connection_t *c = (memif_connection_t *) * conn;
  if (c == NULL)
    {
      DBG ("no connection");
      return MEMIF_ERR_NOCONN;
    }
  libmemif_main_t *lm = &libmemif_main;
  memif_list_elt_t *e = NULL;
  memif_socket_t *ms = NULL;

  int err = MEMIF_ERR_SUCCESS;

  if (c->fd > 0)
    {
      DBG ("DISCONNECTING");
      err = memif_disconnect_internal (c);
      if (err == MEMIF_ERR_NOCONN)
	return err;
    }

  free_list_elt_ctx (lm->control_list, lm->control_list_len, c);

  if (c->args.is_master)
    {
      get_list_elt (&e, lm->listener_list, lm->listener_list_len,
		    c->listener_fd);
      if (e != NULL)
	{
	  ms = (memif_socket_t *) e->data_struct;
	  ms->use_count--;
	  free_list_elt (ms->interface_list, ms->interface_list_len,
			 c->args.interface_id);
	  if (ms->use_count <= 0)
	    {
	      lm->control_fd_update (c->listener_fd, MEMIF_FD_EVENT_DEL);
	      free_list_elt (lm->listener_list, lm->listener_list_len,
			     c->listener_fd);
	      close (c->listener_fd);
	      c->listener_fd = ms->fd = -1;
	      free (ms->interface_list);
	      ms->interface_list = NULL;
	      free (ms->filename);
	      ms->filename = NULL;
	      free (ms);
	      ms = NULL;
	    }
	}
    }
  else
    {
      lm->disconn_slaves--;
      if (lm->disconn_slaves <= 0)
	{
	  if (timerfd_settime (lm->timerfd, 0, &lm->disarm, NULL) < 0)
	    {
	      err = memif_syscall_error_handler (errno);
	      DBG ("timerfd_settime: disarm");
	    }
	}
    }

  if (c->args.socket_filename)
    free (c->args.socket_filename);
  c->args.socket_filename = NULL;

  free (c);
  c = NULL;

  *conn = c;
  return err;
}

int
memif_connect1 (memif_connection_t * c)
{
  libmemif_main_t *lm = &libmemif_main;
  memif_region_t *mr = c->regions;
  memif_queue_t *mq;
  int i;
  uint16_t num;

  if (mr != NULL)
    {
      if (!mr->shm)
	{
	  if (mr->fd < 0)
	    return MEMIF_ERR_NO_SHMFD;

	  if ((mr->shm = mmap (NULL, mr->region_size, PROT_READ | PROT_WRITE,
			       MAP_SHARED, mr->fd, 0)) == MAP_FAILED)
	    {
	      return memif_syscall_error_handler (errno);
	    }
	}
    }

  num =
    (c->args.is_master) ? c->run_args.num_m2s_rings : c->
    run_args.num_s2m_rings;
  for (i = 0; i < num; i++)
    {
      mq = &c->tx_queues[i];
      if (mq != NULL)
	{
	  mq->ring = c->regions[mq->region].shm + mq->offset;
	  if (mq->ring->cookie != MEMIF_COOKIE)
	    {
	      DBG ("wrong cookie on tx ring %u", i);
	      return MEMIF_ERR_COOKIE;
	    }
	  mq->ring->head = mq->ring->tail = mq->last_head = mq->alloc_bufs =
	    0;
	}
    }
  num =
    (c->args.is_master) ? c->run_args.num_s2m_rings : c->
    run_args.num_m2s_rings;
  for (i = 0; i < num; i++)
    {
      mq = &c->rx_queues[i];
      if (mq != NULL)
	{
	  mq->ring = c->regions[mq->region].shm + mq->offset;
	  if (mq->ring->cookie != MEMIF_COOKIE)
	    {
	      DBG ("wrong cookie on rx ring %u", i);
	      return MEMIF_ERR_COOKIE;
	    }
	  mq->ring->head = mq->ring->tail = mq->last_head = mq->alloc_bufs =
	    0;
	}
    }

  lm->control_fd_update (c->fd, MEMIF_FD_EVENT_READ | MEMIF_FD_EVENT_MOD);

  return 0;
}

int
memif_init_regions_and_queues (memif_connection_t * conn)
{
  memif_ring_t *ring = NULL;
  uint64_t buffer_offset;
  memif_region_t *r;
  int i, j;
  libmemif_main_t *lm = &libmemif_main;
  memif_list_elt_t e;

  conn->regions = (memif_region_t *) malloc (sizeof (memif_region_t));
  if (conn->regions == NULL)
    return memif_syscall_error_handler (errno);
  r = conn->regions;

  buffer_offset =
    (conn->run_args.num_s2m_rings +
     conn->run_args.num_m2s_rings) * (sizeof (memif_ring_t) +
				      sizeof (memif_desc_t) *
				      (1 << conn->run_args.log2_ring_size));

  r->region_size = buffer_offset +
    conn->run_args.buffer_size * (1 << conn->run_args.log2_ring_size) *
    (conn->run_args.num_s2m_rings + conn->run_args.num_m2s_rings);

  if ((r->fd = memfd_create ("memif region 0", MFD_ALLOW_SEALING)) == -1)
    return memif_syscall_error_handler (errno);
/*
    if ((fcntl (r->fd, F_ADD_SEALS, F_SEAL_SHRINK)) == -1)
        return memif_syscall_error_handler (errno);
*/
  if ((ftruncate (r->fd, r->region_size)) == -1)
    return memif_syscall_error_handler (errno);

  if ((r->shm = mmap (NULL, r->region_size, PROT_READ | PROT_WRITE,
		      MAP_SHARED, r->fd, 0)) == MAP_FAILED)
    return memif_syscall_error_handler (errno);

  for (i = 0; i < conn->run_args.num_s2m_rings; i++)
    {
      ring = memif_get_ring (conn, MEMIF_RING_S2M, i);
      DBG ("RING: %p I: %d", ring, i);
      ring->head = ring->tail = 0;
      ring->cookie = MEMIF_COOKIE;
      ring->flags = 0;
      for (j = 0; j < (1 << conn->run_args.log2_ring_size); j++)
	{
	  uint16_t slot = i * (1 << conn->run_args.log2_ring_size) + j;
	  ring->desc[j].region = 0;
	  ring->desc[j].offset = buffer_offset +
	    (uint32_t) (slot * conn->run_args.buffer_size);
	  ring->desc[j].buffer_length = conn->run_args.buffer_size;
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
	  uint16_t slot =
	    (i +
	     conn->run_args.num_s2m_rings) *
	    (1 << conn->run_args.log2_ring_size) + j;
	  ring->desc[j].region = 0;
	  ring->desc[j].offset = buffer_offset +
	    (uint32_t) (slot * conn->run_args.buffer_size);
	  ring->desc[j].buffer_length = conn->run_args.buffer_size;
	}
    }
  memif_queue_t *mq;
  mq =
    (memif_queue_t *) malloc (sizeof (memif_queue_t) *
			      conn->run_args.num_s2m_rings);
  if (mq == NULL)
    return memif_syscall_error_handler (errno);
  int x;
  for (x = 0; x < conn->run_args.num_s2m_rings; x++)
    {
      if ((mq[x].int_fd = eventfd (0, EFD_NONBLOCK)) < 0)
	return memif_syscall_error_handler (errno);
      /* add int fd to interrupt fd list */
      e.key = mq[x].int_fd;
      e.data_struct = conn;
      add_list_elt (&e, &lm->interrupt_list, &lm->interrupt_list_len);

      mq[x].ring = memif_get_ring (conn, MEMIF_RING_S2M, x);
      DBG ("RING: %p I: %d", mq[x].ring, x);
      mq[x].log2_ring_size = conn->run_args.log2_ring_size;
      mq[x].region = 0;
      mq[x].offset =
	(void *) mq[x].ring - (void *) conn->regions[mq->region].shm;
      mq[x].last_head = 0;
      mq[x].alloc_bufs = 0;
    }
  conn->tx_queues = mq;

  mq =
    (memif_queue_t *) malloc (sizeof (memif_queue_t) *
			      conn->run_args.num_m2s_rings);
  if (mq == NULL)
    return memif_syscall_error_handler (errno);
  for (x = 0; x < conn->run_args.num_m2s_rings; x++)
    {
      if ((mq[x].int_fd = eventfd (0, EFD_NONBLOCK)) < 0)
	return memif_syscall_error_handler (errno);
      /* add int fd to interrupt fd list */
      e.key = mq[x].int_fd;
      e.data_struct = conn;
      add_list_elt (&e, &lm->interrupt_list, &lm->interrupt_list_len);

      mq[x].ring = memif_get_ring (conn, MEMIF_RING_M2S, x);
      DBG ("RING: %p I: %d", mq[x].ring, x);
      mq[x].log2_ring_size = conn->run_args.log2_ring_size;
      mq[x].region = 0;
      mq[x].offset =
	(void *) mq[x].ring - (void *) conn->regions[mq->region].shm;
      mq[x].last_head = 0;
      mq[x].alloc_bufs = 0;
    }
  conn->rx_queues = mq;

  return 0;
}

int
memif_buffer_alloc (memif_conn_handle_t conn, uint16_t qid,
		    memif_buffer_t * bufs, uint16_t count,
		    uint16_t * count_out, uint16_t size)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (c == NULL)
    return MEMIF_ERR_NOCONN;
  if (c->fd < 0)
    return MEMIF_ERR_DISCONNECTED;
  uint8_t num =
    (c->args.is_master) ? c->run_args.num_m2s_rings : c->
    run_args.num_s2m_rings;
  if (qid >= num)
    return MEMIF_ERR_QID;
  memif_queue_t *mq = &c->tx_queues[qid];
  memif_ring_t *ring = mq->ring;
  memif_buffer_t *b0, *b1;
  uint8_t chain_buf = 1;
  uint16_t mask = (1 << mq->log2_ring_size) - 1;
  uint16_t head = ring->head;
  uint16_t tail = ring->tail;
  uint16_t s0, s1, ns;
  *count_out = 0;
  int i, err = MEMIF_ERR_SUCCESS;	/* 0 */

  ns = (1 << mq->log2_ring_size) - head + tail;

  /* calculate number of chain buffers */
  if (size > ring->desc[0].buffer_length)
    {
      chain_buf = size / ring->desc[0].buffer_length;
      if (((size % ring->desc[0].buffer_length) != 0) || (size == 0))
	chain_buf++;
    }

  while (count && ns)
    {
      while ((count > 2) && (ns > 2))
	{
	  s0 = (ring->head + mq->alloc_bufs) & mask;
	  s1 = (ring->head + mq->alloc_bufs + chain_buf) & mask;

	  if ((2 * chain_buf) > ns)
	    break;

	  b0 = (bufs + *count_out);
	  b1 = (bufs + *count_out + 1);

	  b0->desc_index = head + mq->alloc_bufs;
	  b1->desc_index = head + mq->alloc_bufs + chain_buf;
	  ring->desc[s0].flags = 0;
	  ring->desc[s1].flags = 0;
	  b0->buffer_len = ring->desc[s0].buffer_length * chain_buf;
	  b1->buffer_len = ring->desc[s1].buffer_length * chain_buf;
	  /* TODO: support multiple regions -> ring descriptor contains region index */
	  b0->data = c->regions->shm + ring->desc[s0].offset;
	  b1->data = c->regions->shm + ring->desc[s1].offset;

	  for (i = 0; i < (chain_buf - 1); i++)
	    {
	      ring->desc[(s0 + i) & mask].flags |= MEMIF_DESC_FLAG_NEXT;
	      ring->desc[(s1 + i) & mask].flags |= MEMIF_DESC_FLAG_NEXT;
	      DBG ("allocating chained buffers");
	    }

	  mq->alloc_bufs += 2 * chain_buf;

	  DBG ("allocated ring slots %u, %u", s0, s1);
	  count -= 2;
	  ns -= (2 * chain_buf);
	  *count_out += 2;
	}
      s0 = (ring->head + mq->alloc_bufs) & mask;

      b0 = (bufs + *count_out);

      if (chain_buf > ns)
	break;

      b0->desc_index = head + mq->alloc_bufs;
      ring->desc[s0].flags = 0;
      b0->buffer_len = ring->desc[s0].buffer_length * chain_buf;
      b0->data = c->regions->shm + ring->desc[s0].offset;

      for (i = 0; i < (chain_buf - 1); i++)
	{
	  ring->desc[(s0 + i) & mask].flags |= MEMIF_DESC_FLAG_NEXT;
	  DBG ("allocating chained buffers");
	}

      mq->alloc_bufs += chain_buf;

      DBG ("allocated ring slot %u", s0);
      count--;
      ns -= chain_buf;
      *count_out += 1;
    }

  DBG ("allocated: %u/%u bufs. Total %u allocated bufs", *count_out, count,
       mq->alloc_bufs);

  if (count)
    {
      DBG ("ring buffer full! qid: %u", qid);
      err = MEMIF_ERR_NOBUF_RING;
    }

  return err;
}

int
memif_buffer_free (memif_conn_handle_t conn, uint16_t qid,
		   memif_buffer_t * bufs, uint16_t count,
		   uint16_t * count_out)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (c == NULL)
    return MEMIF_ERR_NOCONN;
  if (c->fd < 0)
    return MEMIF_ERR_DISCONNECTED;
  uint8_t num =
    (c->args.is_master) ? c->run_args.num_s2m_rings : c->
    run_args.num_m2s_rings;
  if (qid >= num)
    return MEMIF_ERR_QID;
  libmemif_main_t *lm = &libmemif_main;
  memif_queue_t *mq = &c->rx_queues[qid];
  memif_ring_t *ring = mq->ring;
  uint16_t tail = ring->tail;
  uint16_t mask = (1 << mq->log2_ring_size) - 1;
  uint8_t chain_buf0, chain_buf1;
  memif_buffer_t *b0, *b1;
  *count_out = 0;

  if (mq->alloc_bufs < count)
    count = mq->alloc_bufs;

  while (count)
    {
      while (count > 2)
	{
	  b0 = (bufs + *count_out);
	  b1 = (bufs + *count_out + 1);
	  chain_buf0 =
	    b0->buffer_len / ring->desc[b0->desc_index & mask].buffer_length;
	  if ((b0->buffer_len %
	       ring->desc[b0->desc_index & mask].buffer_length) != 0)
	    chain_buf0++;
	  chain_buf1 =
	    b1->buffer_len / ring->desc[b1->desc_index & mask].buffer_length;
	  if ((b1->buffer_len %
	       ring->desc[b1->desc_index & mask].buffer_length) != 0)
	    chain_buf1++;
	  tail = b1->desc_index + chain_buf1;
	  b0->data = NULL;
	  b1->data = NULL;

	  count -= 2;
	  *count_out += 2;
	  mq->alloc_bufs -= chain_buf0 + chain_buf1;
	}
      b0 = (bufs + *count_out);
      chain_buf0 =
	b0->buffer_len / ring->desc[b0->desc_index & mask].buffer_length;
      if ((b0->buffer_len %
	   ring->desc[b0->desc_index & mask].buffer_length) != 0)
	chain_buf0++;
      tail = b0->desc_index + chain_buf0;
      b0->data = NULL;

      count--;
      *count_out += 1;
      mq->alloc_bufs -= chain_buf0;
    }
  MEMIF_MEMORY_BARRIER ();
  ring->tail = tail;
  DBG ("tail: %u", ring->tail);

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

int
memif_tx_burst (memif_conn_handle_t conn, uint16_t qid,
		memif_buffer_t * bufs, uint16_t count, uint16_t * tx)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (c == NULL)
    return MEMIF_ERR_NOCONN;
  if (c->fd < 0)
    return MEMIF_ERR_DISCONNECTED;
  uint8_t num =
    (c->args.is_master) ? c->run_args.num_m2s_rings : c->
    run_args.num_s2m_rings;
  if (qid >= num)
    return MEMIF_ERR_QID;
  memif_queue_t *mq = &c->tx_queues[qid];
  memif_ring_t *ring = mq->ring;
  uint16_t head = ring->head;
  uint16_t mask = (1 << mq->log2_ring_size) - 1;
  uint8_t chain_buf0, chain_buf1;
  *tx = 0;
  uint16_t curr_buf = 0;
  memif_buffer_t *b0, *b1;
  int i;

  while (count)
    {
      while (count > 2)
	{
	  b0 = (bufs + curr_buf);
	  b1 = (bufs + curr_buf + 1);
	  chain_buf0 =
	    b0->buffer_len / ring->desc[b0->desc_index & mask].buffer_length;
	  if ((b0->buffer_len %
	       ring->desc[b0->desc_index & mask].buffer_length) != 0)
	    chain_buf0++;

	  chain_buf1 =
	    b1->buffer_len / ring->desc[b1->desc_index & mask].buffer_length;
	  if ((b1->buffer_len %
	       ring->desc[b1->desc_index & mask].buffer_length) != 0)
	    chain_buf1++;

	  for (i = 0; i < memif_min (chain_buf0, chain_buf1); i++)
	    {
	      /* b0 */
	      if (b0->data_len >
		  ring->desc[(b0->desc_index + i) & mask].buffer_length)
		{
		  b0->data_len -=
		    ring->desc[(b0->desc_index + i) & mask].length =
		    ring->desc[(b0->desc_index + i) & mask].buffer_length;
		}
	      else
		{
		  ring->desc[(b0->desc_index + i) & mask].length =
		    b0->data_len;
		  b0->data_len = 0;
		}
	      /* b1 */
	      if (b1->data_len >
		  ring->desc[(b1->desc_index + i) & mask].buffer_length)
		{
		  b1->data_len -=
		    ring->desc[(b1->desc_index + i) & mask].length =
		    ring->desc[(b1->desc_index + i) & mask].buffer_length;
		}
	      else
		{
		  ring->desc[(b1->desc_index + i) & mask].length =
		    b1->data_len;
		  b1->data_len = 0;
		}
#ifdef MEMIF_DBG_SHM
	      print_bytes (b0->data +
			   ring->desc[(b0->desc_index +
				       i) & mask].buffer_length *
			   (chain_buf0 - 1),
			   ring->desc[(b0->desc_index +
				       i) & mask].buffer_length, DBG_TX_BUF);
	      print_bytes (b1->data +
			   ring->desc[(b1->desc_index +
				       i) & mask].buffer_length *
			   (chain_buf1 - 1),
			   ring->desc[(b1->desc_index +
				       i) & mask].buffer_length, DBG_TX_BUF);
#endif /* MEMIF_DBG_SHM */
	    }

	  if (chain_buf0 > chain_buf1)
	    {
	      for (; i < chain_buf0; i++)
		{
		  if (b0->data_len >
		      ring->desc[(b0->desc_index + i) & mask].buffer_length)
		    {
		      b0->data_len -=
			ring->desc[(b0->desc_index + i) & mask].length =
			ring->desc[(b0->desc_index + i) & mask].buffer_length;
		    }
		  else
		    {
		      ring->desc[(b0->desc_index + i) & mask].length =
			b0->data_len;
		      b0->data_len = 0;
		    }
#ifdef MEMIF_DBG_SHM
		  print_bytes (b0->data +
			       ring->desc[(b0->desc_index +
					   i) & mask].buffer_length *
			       (chain_buf0 - 1),
			       ring->desc[(b0->desc_index +
					   i) & mask].buffer_length,
			       DBG_TX_BUF);
#endif /* MEMIF_DBG_SHM */
		}
	    }
	  else
	    {
	      for (; i < chain_buf1; i++)
		{
		  if (b1->data_len >
		      ring->desc[(b1->desc_index + i) & mask].buffer_length)
		    {
		      b1->data_len -=
			ring->desc[(b1->desc_index + i) & mask].length =
			ring->desc[(b1->desc_index + i) & mask].buffer_length;
		    }
		  else
		    {
		      ring->desc[(b1->desc_index + i) & mask].length =
			b1->data_len;
		      b1->data_len = 0;
		    }
#ifdef MEMIF_DBG_SHM
		  print_bytes (b1->data +
			       ring->desc[(b1->desc_index +
					   i) & mask].buffer_length *
			       (chain_buf1 - 1),
			       ring->desc[(b1->desc_index +
					   i) & mask].buffer_length,
			       DBG_TX_BUF);
#endif /* MEMIF_DBG_SHM */
		}
	    }

	  head = b1->desc_index + chain_buf1;

	  b0->data = NULL;
#ifdef MEMIF_DBG
	  if (b0->data_len != 0)
	    DBG ("invalid b0 data length!");
#endif /* MEMIF_DBG */
	  b1->data = NULL;
#ifdef MEMIF_DBG
	  if (b1->data_len != 0)
	    DBG ("invalid b1 data length!");
#endif /* MEMIF_DBG */

	  count -= 2;
	  *tx += chain_buf0 + chain_buf1;
	  curr_buf += 2;
	}

      b0 = (bufs + curr_buf);
      chain_buf0 =
	b0->buffer_len / ring->desc[b0->desc_index & mask].buffer_length;
      if ((b0->buffer_len %
	   ring->desc[b0->desc_index & mask].buffer_length) != 0)
	chain_buf0++;

      for (i = 0; i < chain_buf0; i++)
	{
	  if (b0->data_len >
	      ring->desc[(b0->desc_index + i) & mask].buffer_length)
	    {
	      b0->data_len -= ring->desc[(b0->desc_index + i) & mask].length =
		ring->desc[(b0->desc_index + i) & mask].buffer_length;
	    }
	  else
	    {
	      ring->desc[(b0->desc_index + i) & mask].length = b0->data_len;
	      b0->data_len = 0;
	    }
#ifdef MEMIF_DBG_SHM
	  print_bytes (b0->data +
		       ring->desc[(b0->desc_index + i) & mask].buffer_length *
		       (chain_buf0 - 1),
		       ring->desc[(b0->desc_index + i) & mask].buffer_length,
		       DBG_TX_BUF);
#endif /* MEMIF_DBG_SHM */
	}

      head = b0->desc_index + chain_buf0;

      b0->data = NULL;
#ifdef MEMIF_DBG
      if (b0->data_len != 0)
	DBG ("invalid b0 data length!");
#endif /* MEMIF_DBG */

      count--;
      *tx += chain_buf0;
      curr_buf++;
    }
  MEMIF_MEMORY_BARRIER ();
  ring->head = head;

  mq->alloc_bufs -= *tx;

  /* TODO: return num of buffers and packets */
  *tx = curr_buf;

  if ((ring->flags & MEMIF_RING_FLAG_MASK_INT) == 0)
    {
      uint64_t a = 1;
      int r = write (mq->int_fd, &a, sizeof (a));
      if (r < 0)
	return MEMIF_ERR_INT_WRITE;
    }

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

int
memif_rx_burst (memif_conn_handle_t conn, uint16_t qid,
		memif_buffer_t * bufs, uint16_t count, uint16_t * rx)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (c == NULL)
    return MEMIF_ERR_NOCONN;
  if (c->fd < 0)
    return MEMIF_ERR_DISCONNECTED;
  uint8_t num =
    (c->args.is_master) ? c->run_args.num_s2m_rings : c->
    run_args.num_m2s_rings;
  if (qid >= num)
    return MEMIF_ERR_QID;
  memif_queue_t *mq = &c->rx_queues[qid];
  memif_ring_t *ring = mq->ring;
  uint16_t head = ring->head;
  uint16_t ns;
  uint16_t mask = (1 << mq->log2_ring_size) - 1;
  memif_buffer_t *b0, *b1;
  uint16_t curr_buf = 0;
  *rx = 0;
#ifdef MEMIF_DBG_SHM
  int i;
#endif /* MEMIF_DBG_SHM */

  uint64_t b;
  ssize_t r = read (mq->int_fd, &b, sizeof (b));
  if ((r == -1) && (errno != EAGAIN))
    return memif_syscall_error_handler (errno);

  if (head == mq->last_head)
    return 0;

  ns = head - mq->last_head;

  while (ns && count)
    {
      while ((ns > 2) && (count > 2))
	{
	  b0 = (bufs + curr_buf);
	  b1 = (bufs + curr_buf + 1);

	  b0->desc_index = mq->last_head;
	  b0->data = memif_get_buffer (conn, ring, mq->last_head & mask);
	  b0->data_len = ring->desc[mq->last_head & mask].length;
	  b0->buffer_len = ring->desc[mq->last_head & mask].buffer_length;
#ifdef MEMIF_DBG_SHM
	  i = 0;
	  print_bytes (b0->data +
		       ring->desc[b0->desc_index & mask].buffer_length * i++,
		       ring->desc[b0->desc_index & mask].buffer_length,
		       DBG_TX_BUF);
#endif /* MEMIF_DBG_SHM */
	  ns--;
	  *rx += 1;
	  while (ring->desc[mq->last_head & mask].
		 flags & MEMIF_DESC_FLAG_NEXT)
	    {
	      ring->desc[mq->last_head & mask].flags &= ~MEMIF_DESC_FLAG_NEXT;
	      mq->last_head++;
	      b0->data_len += ring->desc[mq->last_head & mask].length;
	      b0->buffer_len +=
		ring->desc[mq->last_head & mask].buffer_length;
#ifdef MEMIF_DBG_SHM
	      print_bytes (b0->data +
			   ring->desc[b0->desc_index & mask].buffer_length *
			   i++,
			   ring->desc[b0->desc_index & mask].buffer_length,
			   DBG_TX_BUF);
#endif /* MEMIF_DBG_SHM */
	      ns--;
	      *rx += 1;
	    }
	  mq->last_head++;

	  b1->desc_index = mq->last_head;
	  b1->data = memif_get_buffer (conn, ring, mq->last_head & mask);
	  b1->data_len = ring->desc[mq->last_head & mask].length;
	  b1->buffer_len = ring->desc[mq->last_head & mask].buffer_length;
#ifdef MEMIF_DBG_SHM
	  i = 0;
	  print_bytes (b1->data +
		       ring->desc[b1->desc_index & mask].buffer_length * i++,
		       ring->desc[b1->desc_index & mask].buffer_length,
		       DBG_TX_BUF);
#endif /* MEMIF_DBG_SHM */
	  ns--;
	  *rx += 1;
	  while (ring->desc[mq->last_head & mask].
		 flags & MEMIF_DESC_FLAG_NEXT)
	    {
	      ring->desc[mq->last_head & mask].flags &= ~MEMIF_DESC_FLAG_NEXT;
	      mq->last_head++;
	      b1->data_len += ring->desc[mq->last_head & mask].length;
	      b1->buffer_len +=
		ring->desc[mq->last_head & mask].buffer_length;
#ifdef MEMIF_DBG_SHM
	      print_bytes (b1->data +
			   ring->desc[b1->desc_index & mask].buffer_length *
			   i++,
			   ring->desc[b1->desc_index & mask].buffer_length,
			   DBG_TX_BUF);
#endif /* MEMIF_DBG_SHM */
	      ns--;
	      *rx += 1;
	    }
	  mq->last_head++;

	  count -= 2;
	  curr_buf += 2;
	}
      b0 = (bufs + curr_buf);

      b0->desc_index = mq->last_head;
      b0->data = memif_get_buffer (conn, ring, mq->last_head & mask);
      b0->data_len = ring->desc[mq->last_head & mask].length;
      b0->buffer_len = ring->desc[mq->last_head & mask].buffer_length;
#ifdef MEMIF_DBG_SHM
      i = 0;
      print_bytes (b0->data +
		   ring->desc[b0->desc_index & mask].buffer_length * i++,
		   ring->desc[b0->desc_index & mask].buffer_length,
		   DBG_TX_BUF);
#endif /* MEMIF_DBG_SHM */
      ns--;
      *rx += 1;

      while (ring->desc[mq->last_head & mask].flags & MEMIF_DESC_FLAG_NEXT)
	{
	  ring->desc[mq->last_head & mask].flags &= ~MEMIF_DESC_FLAG_NEXT;
	  mq->last_head++;
	  b0->data_len += ring->desc[mq->last_head & mask].length;
	  b0->buffer_len += ring->desc[mq->last_head & mask].buffer_length;
#ifdef MEMIF_DBG_SHM
	  print_bytes (b0->data +
		       ring->desc[b0->desc_index & mask].buffer_length * i++,
		       ring->desc[b0->desc_index & mask].buffer_length,
		       DBG_TX_BUF);
#endif /* MEMIF_DBG_SHM */
	  ns--;
	  *rx += 1;
	}
      mq->last_head++;

      count--;
      curr_buf++;
    }

  mq->alloc_bufs += *rx;

  /* TODO: return num of buffers and packets */
  *rx = curr_buf;

  if (ns)
    {
      DBG ("not enough buffers!");
      return MEMIF_ERR_NOBUF;
    }

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

int
memif_get_details (memif_conn_handle_t conn, memif_details_t * md,
		   char *buf, ssize_t buflen)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (c == NULL)
    return MEMIF_ERR_NOCONN;

  int err = MEMIF_ERR_SUCCESS, i;
  ssize_t l0, l1, total_l;
  l0 = 0;

  l1 = strlen ((char *) c->args.interface_name);
  if (l0 + l1 < buflen)
    {
      md->if_name = strcpy (buf + l0, (char *) c->args.interface_name);
      l0 += l1 + 1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  l1 = strlen ((char *) c->args.instance_name);
  if (l0 + l1 < buflen)
    {
      md->inst_name = strcpy (buf + l0, (char *) c->args.instance_name);
      l0 += l1 + 1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  l1 = strlen ((char *) c->remote_if_name);
  if (l0 + l1 < buflen)
    {
      md->remote_if_name = strcpy (buf + l0, (char *) c->remote_if_name);
      l0 += l1 + 1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  l1 = strlen ((char *) c->remote_name);
  if (l0 + l1 < buflen)
    {
      md->remote_inst_name = strcpy (buf + l0, (char *) c->remote_name);
      l0 += l1 + 1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  md->id = c->args.interface_id;

  if (c->args.secret)
    {
      l1 = strlen ((char *) c->args.secret);
      if (l0 + l1 < buflen)
	{
	  md->secret = strcpy (buf + l0, (char *) c->args.secret);
	  l0 += l1 + 1;
	}
      else
	err = MEMIF_ERR_NOBUF_DET;
    }

  md->role = (c->args.is_master) ? 0 : 1;
  md->mode = c->args.mode;

  l1 = strlen ((char *) c->args.socket_filename);
  if (l0 + l1 < buflen)
    {
      md->socket_filename =
	strcpy (buf + l0, (char *) c->args.socket_filename);
      l0 += l1 + 1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  md->rx_queues_num =
    (c->args.is_master) ? c->run_args.num_s2m_rings : c->
    run_args.num_m2s_rings;

  l1 = sizeof (memif_queue_details_t) * md->rx_queues_num;
  if (l0 + l1 <= buflen)
    {
      md->rx_queues = (memif_queue_details_t *) buf + l0;
      l0 += l1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  for (i = 0; i < md->rx_queues_num; i++)
    {
      md->rx_queues[i].qid = i;
      md->rx_queues[i].ring_size = (1 << c->rx_queues[i].log2_ring_size);
      md->rx_queues[i].flags = c->rx_queues[i].ring->flags;
      md->rx_queues[i].head = c->rx_queues[i].ring->head;
      md->rx_queues[i].tail = c->rx_queues[i].ring->tail;
      md->rx_queues[i].buffer_size = c->run_args.buffer_size;
    }

  md->tx_queues_num =
    (c->args.is_master) ? c->run_args.num_m2s_rings : c->
    run_args.num_s2m_rings;

  l1 = sizeof (memif_queue_details_t) * md->tx_queues_num;
  if (l0 + l1 <= buflen)
    {
      md->tx_queues = (memif_queue_details_t *) buf + l0;
      l0 += l1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  for (i = 0; i < md->tx_queues_num; i++)
    {
      md->tx_queues[i].qid = i;
      md->tx_queues[i].ring_size = (1 << c->tx_queues[i].log2_ring_size);
      md->tx_queues[i].flags = c->tx_queues[i].ring->flags;
      md->tx_queues[i].head = c->tx_queues[i].ring->head;
      md->tx_queues[i].tail = c->tx_queues[i].ring->tail;
      md->tx_queues[i].buffer_size = c->run_args.buffer_size;
    }

  md->link_up_down = (c->fd > 0) ? 1 : 0;

  return err;			/* 0 */
}

int
memif_get_queue_efd (memif_conn_handle_t conn, uint16_t qid, int *efd)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  *efd = -1;
  if (c == NULL)
    return MEMIF_ERR_NOCONN;
  if (c->fd < 0)
    return MEMIF_ERR_DISCONNECTED;
  uint8_t num =
    (c->args.is_master) ? c->run_args.num_s2m_rings : c->
    run_args.num_m2s_rings;
  if (qid >= num)
    return MEMIF_ERR_QID;

  *efd = c->rx_queues[qid].int_fd;

  return MEMIF_ERR_SUCCESS;
}

int
memif_cleanup ()
{
  libmemif_main_t *lm = &libmemif_main;
  if (lm->app_name)
    free (lm->app_name);
  lm->app_name = NULL;
  if (lm->control_list)
    free (lm->control_list);
  lm->control_list = NULL;
  if (lm->interrupt_list)
    free (lm->interrupt_list);
  lm->interrupt_list = NULL;
  if (lm->listener_list)
    free (lm->listener_list);
  lm->listener_list = NULL;
  if (lm->pending_list)
    free (lm->pending_list);
  lm->pending_list = NULL;
  if (poll_cancel_fd != -1)
    close (poll_cancel_fd);

  return MEMIF_ERR_SUCCESS;	/* 0 */
}
