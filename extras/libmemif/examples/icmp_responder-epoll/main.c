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

#include <time.h>

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
#define LOG(...) do {                                               \
                    if (enable_log) {                               \
                        dprintf (out_fd, __VA_ARGS__);              \
                        dprintf (out_fd, "\n");                     \
                    }                                               \
                } while (0)
#define LOG_FILE "/tmp/memif_time_test.txt"
#else
#define DBG(...)
#define LOG(...)
#endif

#define INFO(...) do {                                              \
                    printf ("INFO: "__VA_ARGS__);                   \
                    printf ("\n");                                  \
                } while (0)


/* maximum tx/rx memif buffers */
#define MAX_MEMIF_BUFS  256
#define MAX_CONNS       50

int epfd;
int out_fd;
uint8_t enable_log;

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
  uint16_t seq;
  uint64_t tx_counter, rx_counter, tx_err_counter;
  uint64_t t_sec, t_nsec;
} memif_connection_t;

typedef struct
{
  uint16_t index;
  uint64_t packet_num;
  uint8_t ip_daddr[4];
  uint8_t hw_daddr[6];
} icmpr_thread_data_t;

memif_connection_t memif_connection[MAX_CONNS];
icmpr_thread_data_t icmpr_thread_data[MAX_CONNS];
pthread_t thread[MAX_CONNS];
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
	  printf ("\t\tring rx mode: %s\n",
		  md.rx_queues[e].flags ? "polling" : "interrupt");
	  printf ("\t\tring head: %u\n", md.rx_queues[e].head);
	  printf ("\t\tring tail: %u\n", md.rx_queues[e].tail);
	  printf ("\t\tbuffer size: %u\n", md.rx_queues[e].buffer_size);
	}
      printf ("\ttx queues:\n");
      for (e = 0; e < md.tx_queues_num; e++)
	{
	  printf ("\t\tqueue id: %u\n", md.tx_queues[e].qid);
	  printf ("\t\tring size: %u\n", md.tx_queues[e].ring_size);
	  printf ("\t\tring rx mode: %s\n",
		  md.tx_queues[e].flags ? "polling" : "interrupt");
	  printf ("\t\tring head: %u\n", md.tx_queues[e].head);
	  printf ("\t\tring tail: %u\n", md.tx_queues[e].tail);
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
  enable_log = 1;
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
icmpr_buffer_alloc (long index, long n, uint16_t * r, uint16_t i,
		    uint16_t qid)
{
  memif_connection_t *c = &memif_connection[index];
  int err;
  /* set data pointer to shared memory and set buffer_len to shared mmeory buffer len */
  err = memif_buffer_alloc (c->conn, qid, c->tx_bufs + i, n, r, 0);
  if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF_RING))
    {
      INFO ("memif_buffer_alloc: %s", memif_strerror (err));
      return -1;
    }
  c->tx_buf_num += *r;
  DBG ("allocated %d/%ld buffers, %u free buffers", *r, n,
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
  c->tx_buf_num -= r;
  c->tx_counter += r;
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

  int err = MEMIF_ERR_SUCCESS, ret_val;
  uint16_t rx, tx;
  uint16_t fb;
  int i;			/* rx buffer iterator */
  int j;			/* tx bufferiterator */

  /* loop while there are packets in shm */
  do
    {
      /* receive data from shared memory buffers */
      err = memif_rx_burst (c->conn, qid, c->rx_bufs, MAX_MEMIF_BUFS, &rx);
      ret_val = err;
      c->rx_counter += rx;
      if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF))
	{
	  INFO ("memif_rx_burst: %s", memif_strerror (err));
	  goto error;
	}

      i = 0;

      /* try to alloc required number of buffers buffers */
      err = memif_buffer_alloc (c->conn, qid, c->tx_bufs, rx, &tx, 0);
      if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF_RING))
	{
	  INFO ("memif_buffer_alloc: %s", memif_strerror (err));
	  goto error;
	}
      j = 0;
      c->tx_err_counter = rx - tx;

      /* process bufers */
      while (tx)
	{
	  while (tx > 2)
	    {
	      resolve_packet ((void *) (c->rx_bufs + i)->data,
			      (c->rx_bufs + i)->data_len,
			      (void *) (c->tx_bufs + j)->data,
			      &(c->tx_bufs + j)->data_len, c->ip_addr);
	      resolve_packet ((void *) (c->rx_bufs + i + 1)->data,
			      (c->rx_bufs + i + 1)->data_len,
			      (void *) (c->tx_bufs + j + 1)->data,
			      &(c->tx_bufs + j + 1)->data_len, c->ip_addr);

	      i += 2;
	      j += 2;
	      tx -= 2;
	    }
	  resolve_packet ((void *) (c->rx_bufs + i)->data,
			  (c->rx_bufs + i)->data_len,
			  (void *) (c->tx_bufs + j)->data,
			  &(c->tx_bufs + j)->data_len, c->ip_addr);
	  i++;
	  j++;
	  tx--;
	}
      /* mark memif buffers and shared memory buffers as free */
      /* free processed buffers */
      err = memif_buffer_free (c->conn, qid, c->rx_bufs, rx, &fb);
      if (err != MEMIF_ERR_SUCCESS)
	INFO ("memif_buffer_free: %s", memif_strerror (err));
      rx -= fb;

      DBG ("freed %d buffers. %u/%u alloc/free buffers",
	   fb, rx, MAX_MEMIF_BUFS - rx);

      /* transmit allocated buffers */
      err = memif_tx_burst (c->conn, qid, c->tx_bufs, j, &tx);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_tx_burst: %s", memif_strerror (err));
	  goto error;
	}
      c->tx_counter += tx;

    }
  while (ret_val == MEMIF_ERR_NOBUF);

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

/* called when event is polled on interrupt file descriptor.
    there are packets in shared memory ready to be received */
/* dev test modification: loop until TX == RX (don't drop buffers) */
int
on_interrupt0 (memif_conn_handle_t conn, void *private_ctx, uint16_t qid)
{
  long index = *((long *) private_ctx);
  memif_connection_t *c = &memif_connection[index];
  if (c->index != index)
    {
      INFO ("invalid context: %ld/%u", index, c->index);
      return 0;
    }

  int err = MEMIF_ERR_SUCCESS, ret_val;
  uint16_t rx, tx;
  uint16_t fb;
  int i;			/* rx buffer iterator */
  int j;			/* tx bufferiterator */
  int prev_i;			/* first allocated rx buffer */

  /* loop while there are packets in shm */
  do
    {
      /* receive data from shared memory buffers */
      err = memif_rx_burst (c->conn, qid, c->rx_bufs, MAX_MEMIF_BUFS, &rx);
      ret_val = err;
      c->rx_counter += rx;
      if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF))
	{
	  INFO ("memif_rx_burst: %s", memif_strerror (err));
	  goto error;
	}

      prev_i = i = 0;

      /* loop while there are RX buffers to be processed */
      while (rx)
	{

	  /* try to alloc required number of buffers buffers */
	  err = memif_buffer_alloc (c->conn, qid, c->tx_bufs, rx, &tx, 0);
	  if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF_RING))
	    {
	      INFO ("memif_buffer_alloc: %s", memif_strerror (err));
	      goto error;
	    }
	  j = 0;

	  /* process bufers */
	  while (tx)
	    {
	      while (tx > 2)
		{
		  resolve_packet ((void *) (c->rx_bufs + i)->data,
				  (c->rx_bufs + i)->data_len,
				  (void *) (c->tx_bufs + j)->data,
				  &(c->tx_bufs + j)->data_len, c->ip_addr);
		  resolve_packet ((void *) (c->rx_bufs + i + 1)->data,
				  (c->rx_bufs + i + 1)->data_len,
				  (void *) (c->tx_bufs + j + 1)->data,
				  &(c->tx_bufs + j + 1)->data_len,
				  c->ip_addr);

		  i += 2;
		  j += 2;
		  tx -= 2;
		}
	      resolve_packet ((void *) (c->rx_bufs + i)->data,
			      (c->rx_bufs + i)->data_len,
			      (void *) (c->tx_bufs + j)->data,
			      &(c->tx_bufs + j)->data_len, c->ip_addr);
	      i++;
	      j++;
	      tx--;
	    }
	  /* mark memif buffers and shared memory buffers as free */
	  /* free processed buffers */
	  err = memif_buffer_free (c->conn, qid, c->rx_bufs + prev_i, j, &fb);
	  if (err != MEMIF_ERR_SUCCESS)
	    INFO ("memif_buffer_free: %s", memif_strerror (err));
	  rx -= fb;
	  prev_i = i;

	  DBG ("freed %d buffers. %u/%u alloc/free buffers",
	       fb, rx, MAX_MEMIF_BUFS - rx);

	  /* transmit allocated buffers */
	  err = memif_tx_burst (c->conn, qid, c->tx_bufs, j, &tx);
	  if (err != MEMIF_ERR_SUCCESS)
	    {
	      INFO ("memif_tx_burst: %s", memif_strerror (err));
	      goto error;
	    }
	  c->tx_counter += tx;

	}

    }
  while (ret_val == MEMIF_ERR_NOBUF);

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

/* called when event is polled on interrupt file descriptor.
    there are packets in shared memory ready to be received */
/* dev test modification: handle only ARP requests */
int
on_interrupt1 (memif_conn_handle_t conn, void *private_ctx, uint16_t qid)
{
  long index = *((long *) private_ctx);
  memif_connection_t *c = &memif_connection[index];
  if (c->index != index)
    {
      INFO ("invalid context: %ld/%u", index, c->index);
      return 0;
    }

  int err = MEMIF_ERR_SUCCESS, ret_val;
  int i;
  uint16_t rx, tx;
  uint16_t fb;
  uint16_t pck_seq;

  do
    {
      /* receive data from shared memory buffers */
      err = memif_rx_burst (c->conn, qid, c->rx_bufs, MAX_MEMIF_BUFS, &rx);
      ret_val = err;
      if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF))
	{
	  INFO ("memif_rx_burst: %s", memif_strerror (err));
	  goto error;
	}
      c->rx_buf_num += rx;
      c->rx_counter += rx;

      for (i = 0; i < rx; i++)
	{
	  if (((struct ether_header *) (c->rx_bufs + i)->data)->ether_type ==
	      0x0608)
	    {
	      if (icmpr_buffer_alloc (c->index, 1, &tx, i, qid) < 0)
		break;
	      resolve_packet ((void *) (c->rx_bufs + i)->data,
			      (c->rx_bufs + i)->data_len,
			      (void *) (c->tx_bufs + i)->data,
			      &(c->tx_bufs + i)->data_len, c->ip_addr);
	      icmpr_tx_burst (c->index, qid);
	    }
	}

      err = memif_buffer_free (c->conn, qid, c->rx_bufs, rx, &fb);
      if (err != MEMIF_ERR_SUCCESS)
	INFO ("memif_buffer_free: %s", memif_strerror (err));
      c->rx_buf_num -= fb;


    }
  while (ret_val == MEMIF_ERR_NOBUF);

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
icmpr_memif_create (long index, long mode, char *s)
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
  args.log2_ring_size = 11;
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
  int err;
  /* default interrupt */
  if (s == NULL)
    {
      err = memif_create (&c->conn,
			  &args, on_connect, on_disconnect, on_interrupt,
			  &ctx[index]);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_create: %s", memif_strerror (err));
	  return 0;
	}
    }
  else
    {
      if (strncmp (s, "0", 1) == 0)
	{
	  err = memif_create (&c->conn,
			      &args, on_connect, on_disconnect, on_interrupt0,
			      &ctx[index]);
	  if (err != MEMIF_ERR_SUCCESS)
	    {
	      INFO ("memif_create: %s", memif_strerror (err));
	      return 0;
	    }
	}
      else if (strncmp (s, "1", 1) == 0)
	{
	  err = memif_create (&c->conn,
			      &args, on_connect, on_disconnect, on_interrupt1,
			      &ctx[index]);
	  if (err != MEMIF_ERR_SUCCESS)
	    {
	      INFO ("memif_create: %s", memif_strerror (err));
	      return 0;
	    }
	}
      else
	{
	  INFO ("Unknown interrupt descriptor");
	  goto done;
	}
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

  c->seq = c->tx_err_counter = c->tx_counter = c->rx_counter = 0;

done:
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
    ("\tconn <index> <mode> [<interrupt-desc>] - create memif. index is also used as interface id, mode 0 = slave 1 = master, interrupt-desc none = default 0 = if ring is full wait 1 = handle only ARP requests\n");
  printf ("\tdel  <index> - delete memif\n");
  printf ("\tshow - show connection details\n");
  printf ("\tip-set <index> <ip-addr> - set interface ip address\n");
  printf
    ("\trx-mode <index> <qid> <polling|interrupt> - set queue rx mode\n");
  printf ("\tsh-count - print counters\n");
  printf ("\tcl-count - clear counters\n");
  printf ("\tsend <index> <tx> <ip> <mac> - send icmp\n");
}

int
icmpr_free ()
{
  /* application cleanup */
  int err;
  long i;
  if (out_fd > 0)
    close (out_fd);
  out_fd = -1;
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

void
icmpr_print_counters ()
{
  int i;
  for (i = 0; i < MAX_CONNS; i++)
    {
      memif_connection_t *c = &memif_connection[i];
      if (c->conn == NULL)
	continue;
      printf ("===============================\n");
      printf ("interface index: %d\n", c->index);
      printf ("\trx: %lu\n", c->rx_counter);
      printf ("\ttx: %lu\n", c->tx_counter);
      printf ("\ttx_err: %lu\n", c->tx_err_counter);
      printf ("\tts: %lus %luns\n", c->t_sec, c->t_nsec);
    }
}

void
icmpr_reset_counters ()
{
  int i;
  for (i = 0; i < MAX_CONNS; i++)
    {
      memif_connection_t *c = &memif_connection[i];
      if (c->conn == NULL)
	continue;
      c->t_sec = c->t_nsec = c->tx_err_counter = c->tx_counter =
	c->rx_counter = 0;
    }
}

void *
icmpr_send_proc (void *data)
{
  icmpr_thread_data_t *d = (icmpr_thread_data_t *) data;
  int index = d->index;
  uint64_t count = d->packet_num;
  memif_connection_t *c = &memif_connection[index];
  if (c->conn == NULL)
    {
      INFO ("No connection at index %d. Thread exiting...\n", index);
      pthread_exit (NULL);
    }
  uint16_t tx, i;
  int err = MEMIF_ERR_SUCCESS;
  uint32_t seq = 0;
  struct timespec start, end;
  memset (&start, 0, sizeof (start));
  memset (&end, 0, sizeof (end));

  timespec_get (&start, TIME_UTC);
  while (count)
    {
      i = 0;
      err = memif_buffer_alloc (c->conn, 0, c->tx_bufs,
				MAX_MEMIF_BUFS >
				count ? count : MAX_MEMIF_BUFS, &tx, 0);
      if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF_RING))
	{
	  INFO ("memif_buffer_alloc: %s Thread exiting...\n",
		memif_strerror (err));
	  pthread_exit (NULL);
	}
      c->tx_buf_num += tx;

      while (tx)
	{
	  while (tx > 2)
	    {
	      generate_packet ((void *) c->tx_bufs[i].data,
			       &c->tx_bufs[i].data_len, c->ip_addr,
			       d->ip_daddr, d->hw_daddr, seq++);
	      generate_packet ((void *) c->tx_bufs[i + 1].data,
			       &c->tx_bufs[i + 1].data_len, c->ip_addr,
			       d->ip_daddr, d->hw_daddr, seq++);
	      i += 2;
	      tx -= 2;
	    }
	  generate_packet ((void *) c->tx_bufs[i].data,
			   &c->tx_bufs[i].data_len, c->ip_addr,
			   d->ip_daddr, d->hw_daddr, seq++);
	  i++;
	  tx--;
	}
      err = memif_tx_burst (c->conn, 0, c->tx_bufs, c->tx_buf_num, &tx);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_tx_burst: %s Thread exiting...\n",
		memif_strerror (err));
	  pthread_exit (NULL);
	}
      c->tx_buf_num -= tx;
      c->tx_counter += tx;
      count -= tx;
    }
  timespec_get (&end, TIME_UTC);
  INFO ("Pakcet sequence finished!");
  INFO ("Seq len: %u", seq);
  uint64_t t1 = end.tv_sec - start.tv_sec;
  uint64_t t2;
  if (end.tv_nsec > start.tv_nsec)
    {
      t2 = end.tv_nsec - start.tv_nsec;
    }
  else
    {
      t2 = start.tv_nsec - end.tv_nsec;
      t1--;
    }
  c->t_sec = t1;
  c->t_nsec = t2;
  INFO ("Seq time: %lus %luns", t1, t2);
  double tmp = t1;
  tmp += t2 / 1e+9;
  tmp = seq / tmp;
  INFO ("Average pps: %f", tmp);
  INFO ("Thread exiting...");
  pthread_exit (NULL);
}

int
icmpr_send (long index, long packet_num, char *hw, char *ip)
{
  memif_connection_t *c = &memif_connection[index];
  char *end;
  char *ui;
  uint8_t tmp[6];
  if (c->conn == NULL)
    return -1;
  c->seq = 0;
  icmpr_thread_data_t *data = &icmpr_thread_data[index];
  data->index = index;
  data->packet_num = packet_num;
  INFO ("PN: %lu", data->packet_num);
  printf ("%s\n", ip);
  printf ("%s\n", hw);

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

  data->ip_daddr[0] = tmp[0];
  data->ip_daddr[1] = tmp[1];
  data->ip_daddr[2] = tmp[2];
  data->ip_daddr[3] = tmp[3];

  ui = strtok (hw, ":");
  if (ui == NULL)
    goto error;
  tmp[0] = strtol (ui, &end, 16);
  ui = strtok (NULL, ":");
  if (ui == NULL)
    goto error;
  tmp[1] = strtol (ui, &end, 16);
  ui = strtok (NULL, ":");
  if (ui == NULL)
    goto error;
  tmp[2] = strtol (ui, &end, 16);
  ui = strtok (NULL, ":");
  if (ui == NULL)
    goto error;
  tmp[3] = strtol (ui, &end, 16);
  ui = strtok (NULL, ":");
  if (ui == NULL)
    goto error;
  tmp[4] = strtol (ui, &end, 16);
  ui = strtok (NULL, ":");
  if (ui == NULL)
    goto error;
  tmp[5] = strtol (ui, &end, 16);

  data->hw_daddr[0] = tmp[0];
  data->hw_daddr[1] = tmp[1];
  data->hw_daddr[2] = tmp[2];
  data->hw_daddr[3] = tmp[3];
  data->hw_daddr[4] = tmp[4];
  data->hw_daddr[5] = tmp[5];

  pthread_create (&thread[index], NULL, icmpr_send_proc, (void *) data);
  return 0;

error:
  INFO ("Invalid input\n");
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
	icmpr_memif_create (a, strtol (ui, &end, 10), strtok (NULL, " "));
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
  else if (strncmp (ui, "sh-count", 8) == 0)
    {
      icmpr_print_counters ();
    }
  else if (strncmp (ui, "cl-count", 8) == 0)
    {
      icmpr_reset_counters ();
    }
  else if (strncmp (ui, "send", 4) == 0)
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
	icmpr_send (a, strtol (ui, &end, 10), strtok (NULL, " "),
		    strtok (NULL, " "));
      else
	INFO ("expected count");
      goto done;
    }
  else
    {
      INFO ("unknown command: %s", ui);
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
  struct timespec start, end;
  memset (&evt, 0, sizeof (evt));
  evt.events = EPOLLIN | EPOLLOUT;
  sigset_t sigset;
  sigemptyset (&sigset);
  en = epoll_pwait (epfd, &evt, 1, timeout, &sigset);
  /* id event polled */
  timespec_get (&start, TIME_UTC);
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

  timespec_get (&end, TIME_UTC);
  LOG ("interrupt: %ld", end.tv_nsec - start.tv_nsec);

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

#ifdef LOG_FILE
  remove (LOG_FILE);
  enable_log = 0;

  out_fd = open (LOG_FILE, O_WRONLY | O_CREAT, S_IRWXO);
  if (out_fd < 0)
    INFO ("Error opening log file: %s", strerror (errno));
#endif /* LOG_FILE */

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
