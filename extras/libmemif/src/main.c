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

libmemif_main_t libmemif_main;
int memif_epfd;
int poll_cancel_fd = -1;

static char memif_buf[MAX_ERRBUF_LEN];

const char *memif_errlist[ERRLIST_LEN] = {	/* MEMIF_ERR_SUCCESS */
  "Success.",
  /* MEMIF_ERR_SYSCALL */
  "Unspecified syscall error (build with -DMEMIF_DBG or make debug).",
  /* MEMIF_ERR_CONNREFUSED */
  "Connection refused",
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

uint16_t
memif_get_version ()
{
  return MEMIF_VERSION;
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
  tmp = lm->realloc (*list, sizeof (memif_list_elt_t) * *len * 2);
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

void
memif_register_external_region (memif_add_external_region_t * ar,
				memif_get_external_region_addr_t * gr,
				memif_del_external_region_t * dr,
				memif_get_external_buffer_offset_t * go)
{
  libmemif_main_t *lm = &libmemif_main;
  lm->add_external_region = ar;
  lm->get_external_region_addr = gr;
  lm->del_external_region = dr;
  lm->get_external_buffer_offset = go;
}

static void
memif_alloc_register (memif_alloc_t * ma)
{
  libmemif_main_t *lm = &libmemif_main;
  lm->alloc = ma;
}

static void
memif_realloc_register (memif_realloc_t * mr)
{
  libmemif_main_t *lm = &libmemif_main;
  lm->realloc = mr;
}

static void
memif_free_register (memif_free_t * mf)
{
  libmemif_main_t *lm = &libmemif_main;
  lm->free = mf;
}

int
memif_init (memif_control_fd_update_t * on_control_fd_update, char *app_name,
	    memif_alloc_t * memif_alloc, memif_realloc_t * memif_realloc,
	    memif_free_t * memif_free)
{
  int err = MEMIF_ERR_SUCCESS;	/* 0 */
  libmemif_main_t *lm = &libmemif_main;
  memset (lm, 0, sizeof (libmemif_main_t));

  if (memif_alloc != NULL)
    {
      memif_alloc_register (memif_alloc);
    }
  else
    memif_alloc_register (malloc);

  if (memif_realloc != NULL)
    {
      memif_realloc_register (memif_realloc);
    }
  else
    memif_realloc_register (realloc);

  if (memif_free != NULL)
    memif_free_register (memif_free);
  else
    memif_free_register (free);

  if (app_name != NULL)
    {
      uint8_t len = (strlen (app_name) > MEMIF_NAME_LEN)
	? strlen (app_name) : MEMIF_NAME_LEN;
      strncpy ((char *) lm->app_name, app_name, len);
    }
  else
    {
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

  lm->control_list_len = 2;
  lm->interrupt_list_len = 2;
  lm->listener_list_len = 1;
  lm->pending_list_len = 1;

  lm->control_list =
    lm->alloc (sizeof (memif_list_elt_t) * lm->control_list_len);
  if (lm->control_list == NULL)
    {
      err = MEMIF_ERR_NOMEM;
      goto error;
    }
  lm->interrupt_list =
    lm->alloc (sizeof (memif_list_elt_t) * lm->interrupt_list_len);
  if (lm->interrupt_list == NULL)
    {
      err = MEMIF_ERR_NOMEM;
      goto error;
    }
  lm->listener_list =
    lm->alloc (sizeof (memif_list_elt_t) * lm->listener_list_len);
  if (lm->listener_list == NULL)
    {
      err = MEMIF_ERR_NOMEM;
      goto error;
    }
  lm->pending_list =
    lm->alloc (sizeof (memif_list_elt_t) * lm->pending_list_len);
  if (lm->pending_list == NULL)
    {
      err = MEMIF_ERR_NOMEM;
      goto error;
    }

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
      err = memif_syscall_error_handler (errno);
      goto error;
    }

  lm->arm.it_value.tv_sec = 2;
  lm->arm.it_value.tv_nsec = 0;
  lm->arm.it_interval.tv_sec = 2;
  lm->arm.it_interval.tv_nsec = 0;

  if (lm->control_fd_update (lm->timerfd, MEMIF_FD_EVENT_READ) < 0)
    {
      DBG ("callback type memif_control_fd_update_t error!");
      err = MEMIF_ERR_CB_FDUPDATE;
      goto error;
    }

  return err;

error:
  memif_cleanup ();
  return err;
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
memif_create (memif_conn_handle_t * c, memif_conn_args_t * args,
	      memif_connection_update_t * on_connect,
	      memif_connection_update_t * on_disconnect,
	      memif_interrupt_t * on_interrupt, void *private_ctx)
{
  libmemif_main_t *lm = &libmemif_main;
  int err, i, index = 0, sockfd = -1;
  memif_list_elt_t list_elt;
  memif_connection_t *conn = (memif_connection_t *) * c;
  if (conn != NULL)
    {
      DBG ("This handle already points to existing memif.");
      return MEMIF_ERR_CONN;
    }
  conn = (memif_connection_t *) lm->alloc (sizeof (memif_connection_t));
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

  /* allocate and initialize socket_filename so it can be copyed to sun_path
     without memory leaks */
  conn->args.socket_filename = lm->alloc (sizeof (char *) * 108);
  if (conn->args.socket_filename == NULL)
    {
      err = MEMIF_ERR_NOMEM;
      goto error;
    }
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

  if ((l = strlen ((char *) args->secret)) > 0)
    {
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
	      ms = lm->alloc (sizeof (memif_socket_t));
	      if (ms == NULL)
		{
		  err = MEMIF_ERR_NOMEM;
		  goto error;
		}
	      ms->filename =
		lm->alloc (strlen ((char *) conn->args.socket_filename) +
			   sizeof (char));
	      if (ms->filename == NULL)
		{
		  err = MEMIF_ERR_NOMEM;
		  goto error;
		}
	      memset (ms->filename, 0,
		      strlen ((char *) conn->args.socket_filename) +
		      sizeof (char));
	      strncpy ((char *) ms->filename,
		       (char *) conn->args.socket_filename,
		       strlen ((char *) conn->args.socket_filename));
	      ms->interface_list_len = 1;
	      ms->interface_list =
		lm->alloc (sizeof (memif_list_elt_t) *
			   ms->interface_list_len);
	      if (ms->interface_list == NULL)
		{
		  err = MEMIF_ERR_NOMEM;
		  goto error;
		}
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
    lm->free (conn->args.socket_filename);
  if (conn != NULL)
    lm->free (conn);
  *c = conn = NULL;
  return err;
}

int
memif_control_fd_handler (int fd, uint8_t events)
{
  int i, sockfd = -1, err = MEMIF_ERR_SUCCESS;	/* 0 */
  uint16_t num;
  memif_list_elt_t *e = NULL;
  memif_connection_t *conn;
  libmemif_main_t *lm = &libmemif_main;
  if (fd == lm->timerfd)
    {
      uint64_t b;
      ssize_t size;
      size = read (fd, &b, sizeof (b));

      if (size == -1)
        goto error;

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

	      strncpy (sun.sun_path, (char *) conn->args.socket_filename,
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
		  strcpy ((char *) conn->remote_disconnect_string,
			  memif_strerror (memif_syscall_error_handler
					  (errno)));
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
  struct epoll_event evt;
  int en = 0, err = MEMIF_ERR_SUCCESS;	/* 0 */
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
	  if (r == -1)
	    return MEMIF_ERR_DISCONNECTED;

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
memif_msg_queue_free (libmemif_main_t * lm, memif_msg_queue_elt_t ** e)
{
  if (*e == NULL)
    return;
  memif_msg_queue_free (lm, &(*e)->next);
  lm->free (*e);
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
      memif_msg_send_disconnect (c->fd, (uint8_t *) "interface deleted", 0);
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
      lm->free (c->tx_queues);
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
      lm->free (c->rx_queues);
      c->rx_queues = NULL;
    }

  for (i = 0; i < c->regions_num; i++)
    {
      if (&c->regions[i] == NULL)
	continue;
      if (c->regions[i].is_external != 0)
	{
	  lm->del_external_region (c->regions[i].addr,
				   c->regions[i].region_size,
				   c->regions[i].fd, c->private_ctx);
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
  lm->free (c->regions);
  c->regions = NULL;
  c->regions_num = 0;

  memset (&c->run_args, 0, sizeof (memif_conn_run_args_t));

  memif_msg_queue_free (lm, &c->msg_queue);

  if (!(c->args.is_master))
    {
      if (lm->disconn_slaves == 0)
	{
	  if (timerfd_settime (lm->timerfd, 0, &lm->arm, NULL) < 0)
	    {
	      err = memif_syscall_error_handler (errno);
	      DBG ("timerfd_settime: arm");
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
	      lm->free (ms->interface_list);
	      ms->interface_list = NULL;
	      lm->free (ms->filename);
	      ms->filename = NULL;
	      lm->free (ms);
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
    lm->free (c->args.socket_filename);
  c->args.socket_filename = NULL;

  lm->free (c);
  c = NULL;

  *conn = c;
  return err;
}

int
memif_connect1 (memif_connection_t * c)
{
  libmemif_main_t *lm = &libmemif_main;
  memif_region_t *mr;
  memif_queue_t *mq;
  int i;

  for (i = 0; i < c->regions_num; i++)
    {
      mr = &c->regions[i];
      if (mr != NULL)
	{
	  if (!mr->addr)
	    {
	      if (mr->is_external)
		{
		  if (lm->get_external_region_addr == NULL)
		    return 99;	/* FIXME: proper error report */
		  mr->addr =
		    lm->get_external_region_addr (mr->region_size, mr->fd,
						  c->private_ctx);
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
	  mq->ring->head = mq->ring->tail = mq->last_head = mq->alloc_bufs =
	    0;
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
	  mq->ring->head = mq->ring->tail = mq->last_head = mq->alloc_bufs =
	    0;
	}
    }

  lm->control_fd_update (c->fd, MEMIF_FD_EVENT_READ | MEMIF_FD_EVENT_MOD);

  return 0;
}

static inline int
memif_add_region (libmemif_main_t * lm, memif_connection_t * conn,
		  uint8_t has_buffers)
{
  memif_region_t *r;

  r =
    lm->realloc (conn->regions,
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
memif_init_queues (libmemif_main_t * lm, memif_connection_t * conn)
{
  int i, j;
  memif_ring_t *ring;

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
	  uint16_t slot = (i + conn->run_args.num_s2m_rings) *
	    (1 << conn->run_args.log2_ring_size) + j;
	  ring->desc[j].region = 1;
	  ring->desc[j].offset =
	    conn->regions[1].buffer_offset +
	    (uint32_t) (slot * conn->run_args.buffer_size);
	  ring->desc[j].length = conn->run_args.buffer_size;
	}
    }
  memif_queue_t *mq;
  DBG ("alloc: %p", lm->alloc);
  DBG ("size: %lu", sizeof (memif_queue_t) * conn->run_args.num_s2m_rings);
  mq =
    (memif_queue_t *) lm->alloc (sizeof (memif_queue_t) *
				 conn->run_args.num_s2m_rings);
  if (mq == NULL)
    return MEMIF_ERR_NOMEM;

  int x;
  memif_list_elt_t e;
  for (x = 0; x < conn->run_args.num_s2m_rings; x++)
    {
      if ((mq[x].int_fd = eventfd (0, EFD_NONBLOCK)) < 0)
	return memif_syscall_error_handler (errno);
      e.key = mq[x].int_fd;
      e.data_struct = conn;
      add_list_elt (&e, &lm->interrupt_list, &lm->interrupt_list_len);

      mq[x].ring = memif_get_ring (conn, MEMIF_RING_S2M, x);
      DBG ("RING: %p I: %d", mq[x].ring, x);
      mq[x].log2_ring_size = conn->run_args.log2_ring_size;
      mq[x].region = 0;
      mq[x].offset =
	(void *) mq[x].ring - (void *) conn->regions[mq->region].addr;
      mq[x].last_head = mq[x].last_tail = 0;
      mq[x].alloc_bufs = 0;
    }
  conn->tx_queues = mq;

  mq =
    (memif_queue_t *) lm->alloc (sizeof (memif_queue_t) *
				 conn->run_args.num_m2s_rings);
  if (mq == NULL)
    return MEMIF_ERR_NOMEM;

  for (x = 0; x < conn->run_args.num_m2s_rings; x++)
    {
      if ((mq[x].int_fd = eventfd (0, EFD_NONBLOCK)) < 0)
	return memif_syscall_error_handler (errno);
      e.key = mq[x].int_fd;
      e.data_struct = conn;
      add_list_elt (&e, &lm->interrupt_list, &lm->interrupt_list_len);

      mq[x].ring = memif_get_ring (conn, MEMIF_RING_M2S, x);
      DBG ("RING: %p I: %d", mq[x].ring, x);
      mq[x].log2_ring_size = conn->run_args.log2_ring_size;
      mq[x].region = 0;
      mq[x].offset =
	(void *) mq[x].ring - (void *) conn->regions[mq->region].addr;
      mq[x].last_head = mq[x].last_tail = 0;
      mq[x].alloc_bufs = 0;
    }
  conn->rx_queues = mq;

  return MEMIF_ERR_SUCCESS;
}

int
memif_init_regions_and_queues (memif_connection_t * conn)
{
  memif_region_t *r;
  libmemif_main_t *lm = &libmemif_main;

  /* region 0. rings */
  memif_add_region (lm, conn, /* has_buffers */ 0);

  /* region 1. buffers */
  if (lm->add_external_region)
    {
      r =
	(memif_region_t *) lm->realloc (conn->regions,
					sizeof (memif_region_t) *
					++conn->regions_num);
      if (r == NULL)
	return MEMIF_ERR_NOMEM;
      conn->regions = r;

      conn->regions[1].region_size =
	conn->run_args.buffer_size * (1 << conn->run_args.log2_ring_size) *
	(conn->run_args.num_s2m_rings + conn->run_args.num_m2s_rings);
      conn->regions[1].buffer_offset = 0;
      lm->add_external_region (&conn->regions[1].addr,
			       conn->regions[1].region_size,
			       &conn->regions[1].fd, conn->private_ctx);
      conn->regions[1].is_external = 1;
    }
  else
    {
      memif_add_region (lm, conn, 1);
    }

  memif_init_queues (lm, conn);

  return 0;
}

int
memif_buffer_enq_tx (memif_conn_handle_t conn, uint16_t qid,
		     memif_buffer_t * bufs, uint16_t count,
		     uint16_t * count_out)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (EXPECT_FALSE (c == NULL))
    return MEMIF_ERR_NOCONN;
  if (EXPECT_FALSE (c->fd < 0))
    return MEMIF_ERR_DISCONNECTED;
  uint8_t num =
    (c->args.is_master) ? c->run_args.num_m2s_rings : c->
    run_args.num_s2m_rings;
  if (EXPECT_FALSE (qid >= num))
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
  uint16_t slot, ns;
  int err = MEMIF_ERR_SUCCESS;	/* 0 */
  *count_out = 0;

  ring_size = (1 << mq->log2_ring_size);
  slot = (c->args.is_master) ? ring->tail : ring->head;
  slot += mq->alloc_bufs;

  /* can only be called by slave */
  ns = ring_size - (ring->head + mq->alloc_bufs) + ring->tail;

  b0 = bufs;

  while (count && ns)
    {
      if (EXPECT_FALSE ((b0->flags & MEMIF_BUFFER_FLAG_RX) == 0))
	{
	  /* not a valid buffer */
	  count--;
	  continue;
	}
      b0->flags &= ~MEMIF_BUFFER_FLAG_RX;

      ((memif_ring_t *) b0->ring)->desc[b0->desc_index & mask].offset = ring->desc[slot & mask].offset;	/* put free buffer on rx ring */

      ring->desc[slot & mask].offset =
	(uint32_t) (b0->data -
		    c->regions[ring->desc[slot & mask].region].addr);
      ring->desc[slot & mask].flags |=
	(b0->flags & MEMIF_BUFFER_FLAG_NEXT) ? MEMIF_DESC_FLAG_NEXT : 0;

      b0->desc_index = slot;

      mq->alloc_bufs++;
      slot++;

      count--;
      ns--;
      b0++;
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
memif_buffer_alloc (memif_conn_handle_t conn, uint16_t qid,
		    memif_buffer_t * bufs, uint16_t count,
		    uint16_t * count_out, uint16_t size)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (EXPECT_FALSE (c == NULL))
    return MEMIF_ERR_NOCONN;
  if (EXPECT_FALSE (c->fd < 0))
    return MEMIF_ERR_DISCONNECTED;
  uint8_t num =
    (c->args.is_master) ? c->run_args.num_m2s_rings : c->
    run_args.num_s2m_rings;
  if (EXPECT_FALSE (qid >= num))
    return MEMIF_ERR_QID;
  if (EXPECT_FALSE (!count_out))
    return MEMIF_ERR_INVAL_ARG;

  libmemif_main_t *lm = &libmemif_main;
  memif_queue_t *mq = &c->tx_queues[qid];
  memif_ring_t *ring = mq->ring;
  memif_buffer_t *b0;
  uint16_t mask = (1 << mq->log2_ring_size) - 1;
  uint32_t offset_mask = c->run_args.buffer_size - 1;
  uint16_t ring_size;
  uint16_t slot, ns;
  int err = MEMIF_ERR_SUCCESS;	/* 0 */
  uint16_t dst_left, src_left;
  uint16_t saved_count;
  memif_buffer_t *saved_b;
  *count_out = 0;

  ring_size = (1 << mq->log2_ring_size);
  slot = (c->args.is_master) ? ring->tail : ring->head;
  slot += mq->alloc_bufs;

  if (c->args.is_master)
    ns = ring->head - (ring->tail + mq->alloc_bufs);
  else
    ns = ring_size - (ring->head + mq->alloc_bufs) + ring->tail;

  while (count && ns)
    {
      b0 = (bufs + *count_out);

      saved_b = b0;
      saved_count = count;

      b0->desc_index = slot;
      ring->desc[slot & mask].flags = 0;

      /* slave can produce buffer with original length */
      dst_left = (c->args.is_master) ? ring->desc[slot & mask].length :
	c->run_args.buffer_size;
      src_left = size;

      while (src_left)
	{
	  if (EXPECT_FALSE (dst_left == 0))
	    {
	      if (count && ns)
		{
		  slot++;
		  *count_out += 1;
		  mq->alloc_bufs++;
		  ns--;

		  ring->desc[b0->desc_index & mask].flags |=
		    MEMIF_DESC_FLAG_NEXT;
		  b0->flags |= MEMIF_BUFFER_FLAG_NEXT;

		  b0 = (bufs + *count_out);
		  b0->desc_index = slot;
		  dst_left =
		    (c->args.is_master) ? ring->desc[slot & mask].
		    length : c->run_args.buffer_size;
		  ring->desc[slot & mask].flags = 0;
		}
	      else
		{
		  /* rollback allocated chain buffers */
		  memset (saved_b, 0, sizeof (memif_buffer_t)
			  * (saved_count - count + 1));
		  *count_out -= saved_count - count;
		  mq->alloc_bufs = saved_count - count;
		  goto no_ns;
		}
	    }
	  b0->len = memif_min (dst_left, src_left);

	  /* slave resets buffer offset */
	  if (c->args.is_master == 0)
	    {
	      memif_desc_t *d = &ring->desc[slot & mask];
	      if (lm->get_external_buffer_offset)
		d->offset = lm->get_external_buffer_offset (c->private_ctx);
	      else
		d->offset = d->offset - (d->offset & offset_mask);
	    }
	  b0->data = memif_get_buffer (c, ring, slot & mask);

	  src_left -= b0->len;
	  dst_left -= b0->len;
	}

      slot++;
      *count_out += 1;
      mq->alloc_bufs++;
      ns--;
      count--;
    }

no_ns:

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
memif_refill_queue (memif_conn_handle_t conn, uint16_t qid, uint16_t count,
		    uint16_t headroom)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (EXPECT_FALSE (c == NULL))
    return MEMIF_ERR_NOCONN;
  if (EXPECT_FALSE (c->fd < 0))
    return MEMIF_ERR_DISCONNECTED;
  uint8_t num =
    (c->args.is_master) ? c->run_args.num_s2m_rings : c->
    run_args.num_m2s_rings;
  if (EXPECT_FALSE (qid >= num))
    return MEMIF_ERR_QID;
  libmemif_main_t *lm = &libmemif_main;
  memif_queue_t *mq = &c->rx_queues[qid];
  memif_ring_t *ring = mq->ring;
  uint16_t mask = (1 << mq->log2_ring_size) - 1;
  uint32_t offset_mask = c->run_args.buffer_size - 1;
  uint16_t slot;

  if (c->args.is_master)
    {
      MEMIF_MEMORY_BARRIER ();
      ring->tail =
	(ring->tail + count <=
	 mq->last_head) ? ring->tail + count : mq->last_head;
      return MEMIF_ERR_SUCCESS;
    }

  uint16_t head = ring->head;
  uint16_t ns = (1 << mq->log2_ring_size) - head + mq->last_tail;
  head += (count < ns) ? count : ns;

  slot = ring->head;
  memif_desc_t *d;
  while (slot < head)
    {
      d = &ring->desc[slot & mask];
      d->region = 1;
      d->length = c->run_args.buffer_size - headroom;
      if (lm->get_external_buffer_offset)
	d->offset = lm->get_external_buffer_offset (c->private_ctx);
      else
	d->offset = d->offset - (d->offset & offset_mask) + headroom;
      slot++;
    }

  MEMIF_MEMORY_BARRIER ();
  ring->head = head;

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

int
memif_tx_burst (memif_conn_handle_t conn, uint16_t qid,
		memif_buffer_t * bufs, uint16_t count, uint16_t * tx)
{
  memif_connection_t *c = (memif_connection_t *) conn;
  if (EXPECT_FALSE (c == NULL))
    return MEMIF_ERR_NOCONN;
  if (EXPECT_FALSE (c->fd < 0))
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
  *tx = 0;

  if (count > mq->alloc_bufs)
    count = mq->alloc_bufs;

  if (EXPECT_FALSE (count == 0))
    return MEMIF_ERR_SUCCESS;

  while (count)
    {
      b0 = (bufs + *tx);
      ring->desc[b0->desc_index & mask].length = b0->len;

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
    }


  MEMIF_MEMORY_BARRIER ();
  if (c->args.is_master)
    ring->tail = b0->desc_index + 1;
  else
    ring->head = b0->desc_index + 1;

  mq->alloc_bufs -= *tx;

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
  if (EXPECT_FALSE (c == NULL))
    return MEMIF_ERR_NOCONN;
  if (EXPECT_FALSE (c->fd < 0))
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
  ssize_t r = read (mq->int_fd, &b, sizeof (b));
  if (EXPECT_FALSE ((r == -1) && (errno != EAGAIN)))
    return memif_syscall_error_handler (errno);

  cur_slot = (c->args.is_master) ? mq->last_head : mq->last_tail;
  last_slot = (c->args.is_master) ? ring->head : ring->tail;
  if (cur_slot == last_slot)
    return MEMIF_ERR_SUCCESS;

  ns = last_slot - cur_slot;

  while (ns && count)
    {
      b0 = (bufs + *rx);

      b0->desc_index = cur_slot;
      b0->data = memif_get_buffer (c, ring, cur_slot & mask);
      b0->len = ring->desc[cur_slot & mask].length;
      /* slave resets buffer length */
      if (c->args.is_master == 0)
	{
	  ring->desc[cur_slot & mask].length = c->run_args.buffer_size;
	}

      b0->flags = MEMIF_BUFFER_FLAG_RX;
      if (ring->desc[cur_slot & mask].flags & MEMIF_DESC_FLAG_NEXT)
	{
	  b0->flags |= MEMIF_BUFFER_FLAG_NEXT;
	  ring->desc[cur_slot & mask].flags &= ~MEMIF_DESC_FLAG_NEXT;
	}
/*      b0->offset = ring->desc[cur_slot & mask].offset;*/
      b0->ring = ring;
#ifdef MEMIF_DBG_SHM
      printf ("data: %p\n", b0->data);
      printf ("index: %u\n", b0->desc_index);
      printf ("ring: %p\n", b0->ring);
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

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

int
memif_get_details (memif_conn_handle_t conn, memif_details_t * md,
		   char *buf, ssize_t buflen)
{
  libmemif_main_t *lm = &libmemif_main;
  memif_connection_t *c = (memif_connection_t *) conn;
  if (c == NULL)
    return MEMIF_ERR_NOCONN;

  int err = MEMIF_ERR_SUCCESS, i;
  ssize_t l0, l1;
  l0 = 0;

  l1 = strlen ((char *) c->args.interface_name);
  if (l0 + l1 < buflen)
    {
      md->if_name =
	(uint8_t *) strcpy (buf + l0, (char *) c->args.interface_name);
      l0 += l1 + 1;
    }
  else
    err = MEMIF_ERR_NOBUF_DET;

  l1 = strlen ((char *) lm->app_name);
  if (l0 + l1 < buflen)
    {
      md->inst_name = (uint8_t *) strcpy (buf + l0, (char *) lm->app_name);
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

  l1 = strlen ((char *) c->args.socket_filename);
  if (l0 + l1 < buflen)
    {
      md->socket_filename =
	(uint8_t *) strcpy (buf + l0, (char *) c->args.socket_filename);
      l0 += l1 + 1;
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
  if (lm->control_list)
    lm->free (lm->control_list);
  lm->control_list = NULL;
  if (lm->interrupt_list)
    lm->free (lm->interrupt_list);
  lm->interrupt_list = NULL;
  if (lm->listener_list)
    lm->free (lm->listener_list);
  lm->listener_list = NULL;
  if (lm->pending_list)
    lm->free (lm->pending_list);
  lm->pending_list = NULL;
  if (poll_cancel_fd != -1)
    close (poll_cancel_fd);

  return MEMIF_ERR_SUCCESS;	/* 0 */
}
