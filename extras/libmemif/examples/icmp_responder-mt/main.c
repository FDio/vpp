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

#include <stdlib.h>
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
#include <sys/epoll.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include <libmemif.h>
#include <icmp_proto.h>

#define APP_NAME "ICMP_Responder"
#define IF_NAME  "memif_connection"


#ifdef ICMP_DBG
#define DBG(...) do {                                               \
                    printf (APP_NAME":%s:%d: ", __func__, __LINE__);         \
                    printf (__VA_ARGS__);                           \
                    printf ("\n");                                  \
                } while (0)
#else
#define DBG(...)
#endif

#define INFO(...) do {                                              \
                    printf ("INFO: "__VA_ARGS__);                   \
                    printf ("\n");                                  \
                } while (0)

/* maximum tx/rx memif buffers */
#define MAX_MEMIF_BUFS  256
#define MAX_CONNS       50
#define MAX_QUEUES      2
#define MAX_THREADS     ((MAX_CONNS) * (MAX_QUEUES))

int main_epfd;

typedef struct
{
  /* thread id */
  uint8_t id;
  /* memif connection index */
  uint16_t index;
  /* id of queue to be handled by thread */
  uint8_t qid;
  uint8_t isRunning;

  uint16_t rx_buf_num;
  uint16_t tx_buf_num;
  memif_buffer_t *rx_bufs;
  memif_buffer_t *tx_bufs;
} memif_thread_data_t;

typedef struct
{
  uint16_t index;
  /* memif connection handle */
  memif_conn_handle_t conn;
  /* interface ip address */
  uint8_t ip_addr[4];
  /* inform pthread about connection termination */
  uint8_t pending_del;
} memif_connection_t;

memif_connection_t memif_connection[MAX_CONNS];
long ctx[MAX_CONNS];

/* thread data specific for each thread */
memif_thread_data_t thread_data[MAX_THREADS];
pthread_t thread[MAX_THREADS];

void
user_signal_handler (int sig)
{
}

static void
print_memif_details ()
{
  memif_details_t md;
  ssize_t buflen;
  char *buf;
  int err, i, e, ti;
  buflen = 2048;
  buf = malloc (buflen);
  printf ("MEMIF DETAILS\n");
  printf ("==============================\n");
  for (i = 0; i < MAX_CONNS; i++)
    {
      memif_connection_t *c = &memif_connection[i];

      memset (&md, 0, sizeof (md));
      memset (buf, 0, buflen);

      err = memif_get_details (c->conn, &md, buf, buflen);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  if (err != MEMIF_ERR_NOCONN)
	    INFO ("%s", memif_strerror (err));
	  continue;
	}

      printf ("interface index: %d\n", i);

      printf ("\tinterface ip: %u.%u.%u.%u\n",
	      c->ip_addr[0], c->ip_addr[1], c->ip_addr[2], c->ip_addr[3]);
      printf ("\tinterface name: %s\n", (char *) md.if_name);
      printf ("\tapp name: %s\n", (char *) md.inst_name);
      printf ("\tremote interface name: %s\n", (char *) md.remote_if_name);
      printf ("\tremote app name: %s\n", (char *) md.remote_inst_name);
      printf ("\tid: %u\n", md.id);
      printf ("\tsecret: %s\n", (char *) md.secret);
      printf ("\trole: ");
      if (md.role)
	printf ("slave\n");
      else
	printf ("master\n");
      printf ("\tmode: ");
      switch (md.mode)
	{
	case 0:
	  printf ("ethernet\n");
	  break;
	case 1:
	  printf ("ip\n");
	  break;
	case 2:
	  printf ("punt/inject\n");
	  break;
	default:
	  printf ("unknown\n");
	  break;
	}
      printf ("\tsocket filename: %s\n", (char *) md.socket_filename);
      printf ("\trx queues:\n");
      for (e = 0; e < md.rx_queues_num; e++)
	{
	  ti = (i * MAX_QUEUES) + e;
	  printf ("\tqueue id: %u\n", md.rx_queues[e].qid);
	  printf ("\t\tring size: %u\n", md.rx_queues[e].ring_size);
	  printf ("\t\tbuffer size: %u\n", md.rx_queues[e].buffer_size);
	  printf ("\t\tthread id: %u\n", thread_data[ti].id);
	  printf ("\t\tthread connection index: %u\n", thread_data[ti].index);
	  printf ("\t\tthread running: ");
	  if (thread_data[ti].isRunning)
	    printf ("yes\n");
	  else
	    printf ("no");
	}
      printf ("\ttx queues:\n");
      for (e = 0; e < md.tx_queues_num; e++)
	{
	  printf ("\tqueue id: %u\n", md.tx_queues[e].qid);
	  printf ("\t\tring size: %u\n", md.tx_queues[e].ring_size);
	  printf ("\t\tbuffer size: %u\n", md.tx_queues[e].buffer_size);
	}
      printf ("\tlink: ");
      if (md.link_up_down)
	printf ("up\n");
      else
	printf ("down\n");
    }
  free (buf);
}

int
add_epoll_fd (int epfd, int fd, uint32_t events)
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
  if (epoll_ctl (epfd, EPOLL_CTL_ADD, fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG ("fd %d added to epoll", fd);
  return 0;
}

int
mod_epoll_fd (int epfd, int fd, uint32_t events)
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
  if (epoll_ctl (epfd, EPOLL_CTL_MOD, fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG ("fd %d modified on epoll", fd);
  return 0;
}

int
del_epoll_fd (int epfd, int fd)
{
  if (fd < 0)
    {
      DBG ("invalid fd %d", fd);
      return -1;
    }
  struct epoll_event evt;
  memset (&evt, 0, sizeof (evt));
  if (epoll_ctl (epfd, EPOLL_CTL_DEL, fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG ("fd %d removed from epoll", fd);
  return 0;
}

void *
memif_rx_poll (void *ptr)
{
  memif_thread_data_t *data = (memif_thread_data_t *) ptr;
  memif_connection_t *c = &memif_connection[data->index];
  int err;
  uint16_t rx = 0, tx = 0, fb = 0;

  data->rx_bufs = malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);
  data->tx_bufs = malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);
  data->rx_buf_num = 0;
  data->tx_buf_num = 0;

  data->isRunning = 1;
  INFO ("pthread id %u starts in polling mode", data->id);

  while (1)
    {
      if (c->pending_del)
	goto close;

      /* receive data from shared memory buffers */
      err =
	memif_rx_burst (c->conn, data->qid, data->rx_bufs, MAX_MEMIF_BUFS,
			&rx);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_rx_burst: %s", memif_strerror (err));
	  data->rx_buf_num += rx;
	  goto error;
	}
      data->rx_buf_num += rx;
      if (rx == 0)
	{
	  continue;
	}

      DBG ("thread id: %u", data->id);

      DBG ("received %d buffers. %u/%u alloc/free buffers",
	   rx, data->rx_buf_num, MAX_MEMIF_BUFS - data->rx_buf_num);

      err =
	memif_buffer_alloc (c->conn, data->qid, data->tx_bufs,
			    data->rx_buf_num, &tx, 0);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_buffer_alloc: %s", memif_strerror (err));
	  data->tx_buf_num += tx;
	  goto error;
	}
      data->tx_buf_num += tx;
      DBG ("allocated %d/%d buffers, %u free buffers",
	   tx, data->rx_buf_num, MAX_MEMIF_BUFS - data->tx_buf_num);

      int i;
      for (i = 0; i < rx; i++)
	{
	  resolve_packet ((void *) (data->rx_bufs + i)->data,
			  (data->rx_bufs + i)->len,
			  (void *) (data->tx_bufs + i)->data,
			  &(data->tx_bufs + i)->len, c->ip_addr);
	}

      /* mark memif buffers and shared memory buffers as free */
      err = memif_refill_queue (c->conn, data->qid, rx, 0);
      if (err != MEMIF_ERR_SUCCESS)
	INFO ("memif_buffer_free: %s", memif_strerror (err));
      data->rx_buf_num -= fb;

      DBG ("freed %d buffers. %u/%u alloc/free buffers",
	   fb, data->rx_buf_num, MAX_MEMIF_BUFS - data->rx_buf_num);

      err =
	memif_tx_burst (c->conn, data->qid, data->tx_bufs, data->tx_buf_num,
			&tx);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_tx_burst: %s", memif_strerror (err));
	  goto error;
	}
      DBG ("tx: %d/%u", tx, data->tx_buf_num);
      data->tx_buf_num -= tx;
    }

error:
  INFO ("thread %u error!", data->id);
  goto close;

close:
  err = memif_refill_queue (c->conn, data->qid, rx, 0);
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_buffer_free: %s", memif_strerror (err));
  data->rx_buf_num -= fb;
  DBG ("freed %d buffers. %u/%u alloc/free buffers",
       fb, data->rx_buf_num, MAX_MEMIF_BUFS - data->rx_buf_num);
  free (data->rx_bufs);
  free (data->tx_bufs);
  data->isRunning = 0;
  INFO ("pthread id %u exit", data->id);
  pthread_exit (NULL);
}

void *
memif_rx_interrupt (void *ptr)
{
  memif_thread_data_t *data = (memif_thread_data_t *) ptr;
  memif_connection_t *c = &memif_connection[data->index];
  int err;
  uint16_t rx = 0, tx = 0, fb = 0;
  struct epoll_event evt;
  int en = 0;
  sigset_t sigset;

  signal (SIGUSR1, user_signal_handler);

  data->rx_bufs = malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);
  data->tx_bufs = malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);
  data->rx_buf_num = 0;
  data->tx_buf_num = 0;

  data->isRunning = 1;
  INFO ("pthread id %u starts in interrupt mode", data->id);
  int thread_epfd = epoll_create (1);

  /* get interrupt queue id */
  int fd = -1;
  err = memif_get_queue_efd (c->conn, data->qid, &fd);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_get_queue_efd: %s", memif_strerror (err));
      goto error;
    }
  add_epoll_fd (thread_epfd, fd, EPOLLIN);

  while (1)
    {
      memset (&evt, 0, sizeof (evt));
      evt.events = EPOLLIN | EPOLLOUT;
      sigemptyset (&sigset);
      en = epoll_pwait (thread_epfd, &evt, 1, -1, &sigset);
      if (en < 0)
	{
	  if (errno == EINTR)
	    goto close;
	  DBG ("epoll_pwait: %s", strerror (errno));
	  goto error;
	}
      else if (en > 0)
	{
	  /* receive data from shared memory buffers */
	  err =
	    memif_rx_burst (c->conn, data->qid, data->rx_bufs, MAX_MEMIF_BUFS,
			    &rx);
	  if (err != MEMIF_ERR_SUCCESS)
	    {
	      INFO ("memif_rx_burst: %s", memif_strerror (err));
	      data->rx_buf_num += rx;
	      goto error;
	    }
	  data->rx_buf_num += rx;
	  if (rx == 0)
	    {
	      continue;
	    }

	  DBG ("thread id: %u", data->id);

	  DBG ("received %d buffers. %u/%u alloc/free buffers",
	       rx, data->rx_buf_num, MAX_MEMIF_BUFS - data->rx_buf_num);

	  err =
	    memif_buffer_alloc (c->conn, data->qid, data->tx_bufs,
				data->rx_buf_num, &tx, 0);
	  if (err != MEMIF_ERR_SUCCESS)
	    {
	      INFO ("memif_buffer_alloc: %s", memif_strerror (err));
	      data->tx_buf_num += tx;
	      goto error;
	    }
	  data->tx_buf_num += tx;
	  DBG ("allocated %d/%d buffers, %u free buffers",
	       tx, data->rx_buf_num, MAX_MEMIF_BUFS - data->tx_buf_num);

	  int i;
	  for (i = 0; i < rx; i++)
	    {
	      resolve_packet ((void *) (data->rx_bufs + i)->data,
			      (data->rx_bufs + i)->len,
			      (void *) (data->tx_bufs + i)->data,
			      &(data->tx_bufs + i)->len, c->ip_addr);
	    }

	  /* mark memif buffers and shared memory buffers as free */
	  err = memif_refill_queue (c->conn, data->qid, rx, 0);
	  if (err != MEMIF_ERR_SUCCESS)
	    INFO ("memif_buffer_free: %s", memif_strerror (err));
	  data->rx_buf_num -= fb;

	  DBG ("freed %d buffers. %u/%u alloc/free buffers",
	       fb, data->rx_buf_num, MAX_MEMIF_BUFS - data->rx_buf_num);

	  err =
	    memif_tx_burst (c->conn, data->qid, data->tx_bufs,
			    data->tx_buf_num, &tx);
	  if (err != MEMIF_ERR_SUCCESS)
	    {
	      INFO ("memif_tx_burst: %s", memif_strerror (err));
	      goto error;
	    }
	  DBG ("tx: %d/%u", tx, data->tx_buf_num);
	  data->tx_buf_num -= tx;
	}
    }

error:
  INFO ("thread %u error!", data->id);
  goto close;

close:
  err = memif_refill_queue (c->conn, data->qid, rx, 0);
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_buffer_free: %s", memif_strerror (err));
  data->rx_buf_num -= fb;
  DBG ("freed %d buffers. %u/%u alloc/free buffers",
       fb, data->rx_buf_num, MAX_MEMIF_BUFS - data->rx_buf_num);
  free (data->rx_bufs);
  free (data->tx_bufs);
  data->isRunning = 0;
  INFO ("pthread id %u exit", data->id);
  pthread_exit (NULL);

}

/* informs user about connected status. private_ctx is used by user to identify connection
    (multiple connections WIP) */
int
on_connect (memif_conn_handle_t conn, void *private_ctx)
{
  long index = (*(long *) private_ctx);
  int err, i, ti;
  INFO ("memif connected! index %ld", index);
  memif_connection_t *c = &memif_connection[index];
  c->pending_del = 0;

  for (i = 0; i < MAX_QUEUES; i++)
    {
      err = memif_set_rx_mode (c->conn, MEMIF_RX_MODE_POLLING, i);
      if (err != MEMIF_ERR_SUCCESS)
	INFO ("memif_set_rx_mode: %s qid: %u", memif_strerror (err), i);
      else
	{
	  ti = (index * MAX_QUEUES) + i;
	  if (thread_data[ti].isRunning)
	    {
	      INFO ("thread id: %d already running!", ti);
	      continue;
	    }
	  thread_data[ti].index = index;
	  thread_data[ti].qid = i;
	  thread_data[ti].id = ti;
	  if ((i % 2) == 0)
	    pthread_create (&thread[ti],
			    NULL, memif_rx_poll, (void *) &thread_data[ti]);
	  else
	    pthread_create (&thread[ti],
			    NULL, memif_rx_interrupt,
			    (void *) &thread_data[ti]);
	}

    }
  return 0;
}

/* informs user about disconnected status. private_ctx is used by user to identify connection
    (multiple connections WIP) */
int
on_disconnect (memif_conn_handle_t conn, void *private_ctx)
{
  void *ptr;
  long index = (*(long *) private_ctx);
  memif_connection_t *c = &memif_connection[index];
  int i, ti;
  INFO ("memif disconnected!");
  /* inform thread in polling mode about memif disconnection */
  c->pending_del = 1;
  for (i = 0; i < MAX_QUEUES; i++)
    {
      ti = (index * MAX_QUEUES) + i;
      if (!thread_data[ti].isRunning)
	continue;
      if ((i % 2) != 0)
	pthread_kill (thread[ti], SIGUSR1);	/* interrupt thread in interrupt mode */
      pthread_join (thread[ti], &ptr);
    }
  return 0;
}

/* user needs to watch new fd or stop watching fd that is about to be closed.
    control fd will be modified during connection establishment to minimize CPU usage */
int
control_fd_update (int fd, uint8_t events, void *ctx)
{
  /* convert memif event definitions to epoll events */
  if (events & MEMIF_FD_EVENT_DEL)
    return del_epoll_fd (main_epfd, fd);

  uint32_t evt = 0;
  if (events & MEMIF_FD_EVENT_READ)
    evt |= EPOLLIN;
  if (events & MEMIF_FD_EVENT_WRITE)
    evt |= EPOLLOUT;

  if (events & MEMIF_FD_EVENT_MOD)
    return mod_epoll_fd (main_epfd, fd, evt);

  return add_epoll_fd (main_epfd, fd, evt);
}

int
icmpr_memif_create (long index)
{
  if (index >= MAX_CONNS)
    {
      INFO ("connection array overflow");
      return 0;
    }
  if (index < 0)
    {
      INFO ("don't even try...");
      return 0;
    }
  memif_connection_t *c = &memif_connection[index];

  /* setting memif connection arguments */
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));
  args.is_master = 0;
  args.log2_ring_size = 10;
  args.buffer_size = 2048;
  args.num_s2m_rings = 2;
  args.num_m2s_rings = 2;
  strncpy ((char *) args.interface_name, IF_NAME, strlen (IF_NAME));
  args.mode = 0;
  /* socket filename is not specified, because this app is supposed to
     connect to VPP over memif. so default socket filename will be used */
  /* default socketfile = /run/vpp/memif.sock */

  args.interface_id = index;
  /* last argument for memif_create (void * private_ctx) is used by user
     to identify connection. this context is returned with callbacks */
  int err = memif_create (&c->conn,
			  &args, on_connect, on_disconnect, NULL,
			  &ctx[index]);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_create: %s", memif_strerror (err));
      return 0;
    }

  c->index = index;

  c->ip_addr[0] = 192;
  c->ip_addr[1] = 168;
  c->ip_addr[2] = c->index + 1;
  c->ip_addr[3] = 2;
  return 0;
}

int
icmpr_memif_delete (long index)
{
  if (index >= MAX_CONNS)
    {
      INFO ("connection array overflow");
      return 0;
    }
  if (index < 0)
    {
      INFO ("don't even try...");
      return 0;
    }
  memif_connection_t *c = &memif_connection[index];

  int err;
  /* disconnect then delete memif connection */
  err = memif_delete (&c->conn);
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_delete: %s", memif_strerror (err));
  return 0;
}

void
print_help ()
{
  printf ("LIBMEMIF EXAMPLE APP: %s", APP_NAME);
#ifdef ICMP_DBG
  printf (" (debug)");
#endif
  printf ("\n");
  printf ("==============================\n");
  printf ("libmemif version: %s", LIBMEMIF_VERSION);
#ifdef MEMIF_DBG
  printf (" (debug)");
#endif
  printf ("\n");
  printf ("memif version: %d\n", memif_get_version ());
  printf ("commands:\n");
  printf ("\thelp - prints this help\n");
  printf ("\texit - exit app\n");
  printf ("\tconn <index> - create memif (slave-mode)\n");
  printf ("\tdel  <index> - delete memif\n");
  printf ("\tshow - show connection details\n");
  printf ("\tip-set <index> <ip-addr> - set interface ip address\n");
}

int
icmpr_free ()
{
  /* application cleanup */
  int err;
  long i;
  for (i = 0; i < MAX_CONNS; i++)
    {
      memif_connection_t *c = &memif_connection[i];
      if (c->conn)
	icmpr_memif_delete (i);
    }

  err = memif_cleanup ();
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_delete: %s", memif_strerror (err));

  return 0;
}

int
icmpr_set_ip (long index, char *ip)
{
  if (index >= MAX_CONNS)
    {
      INFO ("connection array overflow");
      return 0;
    }
  if (index < 0)
    {
      INFO ("don't even try...");
      return 0;
    }
  memif_connection_t *c = &memif_connection[index];
  if (c->conn == NULL)
    {
      INFO ("no connection at index %ld", index);
      return 0;
    }

  char *end;
  char *ui;
  uint8_t tmp[4];
  ui = strtok (ip, ".");
  if (ui == NULL)
    goto error;
  tmp[0] = strtol (ui, &end, 10);

  ui = strtok (NULL, ".");
  if (ui == NULL)
    goto error;
  tmp[1] = strtol (ui, &end, 10);

  ui = strtok (NULL, ".");
  if (ui == NULL)
    goto error;
  tmp[2] = strtol (ui, &end, 10);

  ui = strtok (NULL, ".");
  if (ui == NULL)
    goto error;
  tmp[3] = strtol (ui, &end, 10);

  c->ip_addr[0] = tmp[0];
  c->ip_addr[1] = tmp[1];
  c->ip_addr[2] = tmp[2];
  c->ip_addr[3] = tmp[3];

  INFO ("memif %ld ip address set to %u.%u.%u.%u",
	index, c->ip_addr[0], c->ip_addr[1], c->ip_addr[2], c->ip_addr[3]);

  return 0;

error:
  INFO ("invalid ip address");
  return 0;
}


int
user_input_handler ()
{
  char *in = (char *) malloc (256);
  char *ui = fgets (in, 256, stdin);
  char *end;
  if (in[0] == '\n')
    goto done;
  ui = strtok (in, " ");
  if (strncmp (ui, "exit", 4) == 0)
    {
      free (in);
      icmpr_free ();
      exit (EXIT_SUCCESS);
    }
  else if (strncmp (ui, "help", 4) == 0)
    {
      print_help ();
      goto done;
    }
  else if (strncmp (ui, "conn", 4) == 0)
    {
      ui = strtok (NULL, " ");
      if (ui != NULL)
	icmpr_memif_create (strtol (ui, &end, 10));
      else
	INFO ("expected id");
      goto done;
    }
  else if (strncmp (ui, "del", 3) == 0)
    {
      ui = strtok (NULL, " ");
      if (ui != NULL)
	icmpr_memif_delete (strtol (ui, &end, 10));
      else
	INFO ("expected id");
      goto done;
    }
  else if (strncmp (ui, "show", 4) == 0)
    {
      print_memif_details ();
      goto done;
    }
  else if (strncmp (ui, "ip-set", 6) == 0)
    {
      ui = strtok (NULL, " ");
      if (ui != NULL)
	icmpr_set_ip (strtol (ui, &end, 10), strtok (NULL, " "));
      else
	INFO ("expected id");
      goto done;
    }
  else
    {
      DBG ("unknown command: %s", ui);
      goto done;
    }

  return 0;
done:
  free (in);
  return 0;
}

int
poll_event (int timeout)
{
  struct epoll_event evt;
  int app_err = 0, memif_err = 0, en = 0;
  uint32_t events = 0;
  memset (&evt, 0, sizeof (evt));
  evt.events = EPOLLIN | EPOLLOUT;
  sigset_t sigset;
  sigemptyset (&sigset);
  en = epoll_pwait (main_epfd, &evt, 1, timeout, &sigset);
  if (en < 0)
    {
      DBG ("epoll_pwait: %s", strerror (errno));
      return -1;
    }
  if (en > 0)
    {
      /* this app does not use any other file descriptors than stds and memif control fds */
      if (evt.data.fd > 2)
	{
	  /* event of memif control fd */
	  /* convert epoll events to memif events */
	  if (evt.events & EPOLLIN)
	    events |= MEMIF_FD_EVENT_READ;
	  if (evt.events & EPOLLOUT)
	    events |= MEMIF_FD_EVENT_WRITE;
	  if (evt.events & EPOLLERR)
	    events |= MEMIF_FD_EVENT_ERROR;
	  memif_err = memif_control_fd_handler (evt.data.fd, events);
	  if (memif_err != MEMIF_ERR_SUCCESS)
	    INFO ("memif_control_fd_handler: %s", memif_strerror (memif_err));
	}
      else if (evt.data.fd == 0)
	{
	  app_err = user_input_handler ();
	}
      else
	{
	  DBG ("unexpected event at memif_epfd. fd %d", evt.data.fd);
	}
    }

  if ((app_err < 0) || (memif_err < 0))
    {
      if (app_err < 0)
	DBG ("user input handler error");
      if (memif_err < 0)
	DBG ("memif control fd handler error");
      return -1;
    }

  return 0;
}

int
main ()
{
  main_epfd = epoll_create (1);
  add_epoll_fd (main_epfd, 0, EPOLLIN);

  /* initialize memory interface */
  int err, i;
  /* if valid callback is passed as argument, fd event polling will be done by user
     all file descriptors and events will be passed to user in this callback */
  /* if callback is set to NULL libmemif will handle fd event polling */
  err = memif_init (control_fd_update, APP_NAME, NULL, NULL, NULL);
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_init: %s", memif_strerror (err));

  for (i = 0; i < MAX_CONNS; i++)
    {
      memif_connection[i].conn = NULL;
      ctx[i] = i;
    }

  memset (&thread_data, 0, sizeof (memif_thread_data_t) * MAX_THREADS);

  print_help ();

  /* main loop */
  while (1)
    {
      if (poll_event (-1) < 0)
	{
	  DBG ("poll_event error!");
	}
    }
}
