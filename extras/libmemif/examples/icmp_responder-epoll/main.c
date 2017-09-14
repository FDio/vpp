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

int epfd;

typedef struct
{
  uint16_t index;
  /* memif conenction handle */
  memif_conn_handle_t conn;
  /* tx buffers */
  memif_buffer_t *tx_bufs;
  /* allocated tx buffers counter */
  /* number of tx buffers pointing to shared memory */
  uint16_t tx_buf_num;
  /* rx buffers */
  memif_buffer_t *rx_bufs;
  /* allcoated rx buffers counter */
  /* number of rx buffers pointing to shared memory */
  uint16_t rx_buf_num;
  /* interface ip address */
  uint8_t ip_addr[4];
} memif_connection_t;

memif_connection_t memif_connection[MAX_CONNS];
long ctx[MAX_CONNS];

/* print details for all memif connections */
static void
print_memif_details ()
{
  memif_details_t md;
  ssize_t buflen;
  char *buf;
  int err, i, e;
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
	  printf ("\t\tqueue id: %u\n", md.rx_queues[e].qid);
	  printf ("\t\tring size: %u\n", md.rx_queues[e].ring_size);
	  printf ("\t\tbuffer size: %u\n", md.rx_queues[e].buffer_size);
	}
      printf ("\ttx queues:\n");
      for (e = 0; e < md.tx_queues_num; e++)
	{
	  printf ("\t\tqueue id: %u\n", md.tx_queues[e].qid);
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
add_epoll_fd (int fd, uint32_t events)
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
mod_epoll_fd (int fd, uint32_t events)
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
  DBG ("fd %d moddified on epoll", fd);
  return 0;
}

int
del_epoll_fd (int fd)
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

/* informs user about connected status. private_ctx is used by user to identify connection
    (multiple connections WIP) */
int
on_connect (memif_conn_handle_t conn, void *private_ctx)
{
  INFO ("memif connected!");
  return 0;
}

/* informs user about disconnected status. private_ctx is used by user to identify connection
    (multiple connections WIP) */
int
on_disconnect (memif_conn_handle_t conn, void *private_ctx)
{
  INFO ("memif disconnected!");
  return 0;
}

/* user needs to watch new fd or stop watching fd that is about to be closed.
    control fd will be modified during connection establishment to minimize CPU usage */
int
control_fd_update (int fd, uint8_t events)
{
  /* convert memif event definitions to epoll events */
  if (events & MEMIF_FD_EVENT_DEL)
    return del_epoll_fd (fd);

  uint32_t evt = 0;
  if (events & MEMIF_FD_EVENT_READ)
    evt |= EPOLLIN;
  if (events & MEMIF_FD_EVENT_WRITE)
    evt |= EPOLLOUT;

  if (events & MEMIF_FD_EVENT_MOD)
    return mod_epoll_fd (fd, evt);

  return add_epoll_fd (fd, evt);
}

int
icmpr_buffer_alloc (long index, long n, uint16_t qid)
{
  memif_connection_t *c = &memif_connection[index];
  int err;
  uint16_t r;
  /* set data pointer to shared memory and set buffer_len to shared mmeory buffer len */
  err = memif_buffer_alloc (c->conn, qid, c->tx_bufs, n, &r, 0);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_buffer_alloc: %s", memif_strerror (err));
      c->tx_buf_num += r;
      return -1;
    }
  c->tx_buf_num += r;
  DBG ("allocated %d/%ld buffers, %u free buffers", r, n,
       MAX_MEMIF_BUFS - c->tx_buf_num);
  return 0;
}

int
icmpr_tx_burst (long index, uint16_t qid)
{
  memif_connection_t *c = &memif_connection[index];
  int err;
  uint16_t r;
  /* inform peer memif interface about data in shared memory buffers */
  /* mark memif buffers as free */
  err = memif_tx_burst (c->conn, qid, c->tx_bufs, c->tx_buf_num, &r);
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_tx_burst: %s", memif_strerror (err));
  DBG ("tx: %d/%u", r, c->tx_buf_num);
  c->tx_buf_num -= r;
  return 0;
}

/* called when event is polled on interrupt file descriptor.
    there are packets in shared memory ready to be received */
int
on_interrupt (memif_conn_handle_t conn, void *private_ctx, uint16_t qid)
{
  long index = *((long *) private_ctx);
  memif_connection_t *c = &memif_connection[index];
  if (c->index != index)
    {
      INFO ("invalid context: %ld/%u", index, c->index);
      return 0;
    }
  int err;
  uint16_t rx;
  uint16_t fb;
  /* receive data from shared memory buffers */
  err = memif_rx_burst (c->conn, qid, c->rx_bufs, MAX_MEMIF_BUFS, &rx);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_rx_burst: %s", memif_strerror (err));
      c->rx_buf_num += rx;
      goto error;
    }
  c->rx_buf_num += rx;

  DBG ("received %d buffers. %u/%u alloc/free buffers",
       rx, c->rx_buf_num, MAX_MEMIF_BUFS - c->rx_buf_num);

  if (icmpr_buffer_alloc (index, rx, qid) < 0)
    {
      INFO ("buffer_alloc error");
      goto error;
    }
  int i;
  for (i = 0; i < rx; i++)
    {
      resolve_packet ((void *) (c->rx_bufs + i)->data,
		      (c->rx_bufs + i)->data_len,
		      (void *) (c->tx_bufs + i)->data,
		      &(c->tx_bufs + i)->data_len, c->ip_addr);
    }

  /* mark memif buffers and shared memory buffers as free */
  err = memif_buffer_free (c->conn, qid, c->rx_bufs, rx, &fb);
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_buffer_free: %s", memif_strerror (err));
  c->rx_buf_num -= fb;

  DBG ("freed %d buffers. %u/%u alloc/free buffers",
       fb, c->rx_buf_num, MAX_MEMIF_BUFS - c->rx_buf_num);

  icmpr_tx_burst (index, qid);

  return 0;

error:
  err = memif_buffer_free (c->conn, qid, c->rx_bufs, rx, &fb);
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_buffer_free: %s", memif_strerror (err));
  c->rx_buf_num -= fb;
  DBG ("freed %d buffers. %u/%u alloc/free buffers",
       fb, c->rx_buf_num, MAX_MEMIF_BUFS - c->rx_buf_num);
  return 0;
}

int
icmpr_memif_create (long index, long mode)
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
  int fd = -1;
  memset (&args, 0, sizeof (args));
  args.is_master = mode;
  args.log2_ring_size = 10;
  args.buffer_size = 2048;
  args.num_s2m_rings = 2;
  args.num_m2s_rings = 2;
  strncpy ((char *) args.interface_name, IF_NAME, strlen (IF_NAME));
  strncpy ((char *) args.instance_name, APP_NAME, strlen (APP_NAME));
  args.mode = 0;
  /* socket filename is not specified, because this app is supposed to
     connect to VPP over memif. so default socket filename will be used */
  /* default socketfile = /run/vpp/memif.sock */

  args.interface_id = index;
  /* last argument for memif_create (void * private_ctx) is used by user
     to identify connection. this context is returned with callbacks */
  int err = memif_create (&c->conn,
			  &args, on_connect, on_disconnect, on_interrupt,
			  &ctx[index]);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_create: %s", memif_strerror (err));
      return 0;
    }

  c->index = index;
  /* alloc memif buffers */
  c->rx_buf_num = 0;
  c->rx_bufs =
    (memif_buffer_t *) malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);
  c->tx_buf_num = 0;
  c->tx_bufs =
    (memif_buffer_t *) malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);

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

  if (c->rx_bufs)
    free (c->rx_bufs);
  c->rx_bufs = NULL;
  c->rx_buf_num = 0;
  if (c->tx_bufs)
    free (c->tx_bufs);
  c->tx_bufs = NULL;
  c->tx_buf_num = 0;

  int err;
  /* disconenct then delete memif connection */
  err = memif_delete (&c->conn);
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_delete: %s", memif_strerror (err));
  if (c->conn != NULL)
    INFO ("memif delete fail");
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
  printf ("memif version: %d\n", MEMIF_VERSION);
  printf ("commands:\n");
  printf ("\thelp - prints this help\n");
  printf ("\texit - exit app\n");
  printf
    ("\tconn <index> <mode> - create memif. index is also used as interface id, mode 0 = slave 1 = master\n");
  printf ("\tdel  <index> - delete memif\n");
  printf ("\tshow - show connection details\n");
  printf ("\tip-set <index> <ip-addr> - set interface ip address\n");
  printf
    ("\trx-mode <index> <qid> <polling|interrupt> - set queue rx mode\n");
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
icmpr_set_rx_mode (long index, long qid, char *mode)
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

  if (strncmp (mode, "interrupt", 9) == 0)
    {
      memif_set_rx_mode (c->conn, MEMIF_RX_MODE_INTERRUPT, qid);
    }

  else if (strncmp (mode, "polling", 7) == 0)
    {
      memif_set_rx_mode (c->conn, MEMIF_RX_MODE_POLLING, qid);
    }
  else
    INFO ("expected rx mode <interrupt|polling>");
  return 0;
}

int
user_input_handler ()
{
  int i;
  char *in = (char *) malloc (256);
  char *ui = fgets (in, 256, stdin);
  char *end;
  long a;
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
	a = strtol (ui, &end, 10);
      else
	{
	  INFO ("expected id");
	  goto done;
	}
      ui = strtok (NULL, " ");
      if (ui != NULL)
	icmpr_memif_create (a, strtol (ui, &end, 10));
      else
	INFO ("expected mode <0|1>");
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
  else if (strncmp (ui, "rx-mode", 7) == 0)
    {
      ui = strtok (NULL, " ");
      if (ui != NULL)
	a = strtol (ui, &end, 10);
      else
	{
	  INFO ("expected id");
	  goto done;
	}
      ui = strtok (NULL, " ");
      if (ui != NULL)
	icmpr_set_rx_mode (a, strtol (ui, &end, 10), strtok (NULL, " "));
      else
	INFO ("expected qid");
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
  struct epoll_event evt, *e;
  int app_err = 0, memif_err = 0, en = 0;
  int tmp, nfd;
  uint32_t events = 0;
  memset (&evt, 0, sizeof (evt));
  evt.events = EPOLLIN | EPOLLOUT;
  sigset_t sigset;
  sigemptyset (&sigset);
  en = epoll_pwait (epfd, &evt, 1, timeout, &sigset);
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
	  /* convert epolle events to memif events */
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
  epfd = epoll_create (1);
  add_epoll_fd (0, EPOLLIN);

  /* initialize memory interface */
  int err, i;
  /* if valid callback is passed as argument, fd event polling will be done by user
     all file descriptors and events will be passed to user in this callback */
  /* if callback is set to NULL libmemif will handle fd event polling */
  err = memif_init (control_fd_update, APP_NAME);
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_init: %s", memif_strerror (err));

  for (i = 0; i < MAX_CONNS; i++)
    {
      memif_connection[i].conn = NULL;
      ctx[i] = i;
    }

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
