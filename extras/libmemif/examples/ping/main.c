/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/queue.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <icmp_proto.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>

#include "parser.h"
#include "set_events.h"
#include "common.h"


#define IF_NAME  "memif_connection"
#define HEADROOM 0x80		/* 128b */
#define MAX_MEMIF_BUFS  256
#define MAX_QUEUES      255
#define MAX_PING_CNT 5
#define WAIT_ECHO_MS 1000
#define MAX_LOG_CHAR 120


pthread_mutex_t lock;

TAILQ_HEAD (, memif_log_msg) head_info;

     struct memif_log_msg
     {
       char *msg;
       log_type type;
       struct timespec timestamp;
         TAILQ_ENTRY (memif_log_msg) next;
     };


     const struct memif_log_msg *memif_get_log ()
{
  return TAILQ_FIRST (&head_info);
}

void
ping_log (log_type type, const char *args, ...)
{
  va_list arg;
  int done;

  struct memif_log_msg *data = malloc (sizeof (struct memif_log_msg));
  data->msg = malloc (MAX_LOG_CHAR);
  data->type = type;

  timespec_get (&data->timestamp, TIME_UTC);

  va_start (arg, args);
  done = vsnprintf (data->msg, MAX_LOG_CHAR, args, arg);
  va_end (arg);

  pthread_mutex_lock (&lock);
  TAILQ_INSERT_TAIL (&head_info, data, next);
  pthread_mutex_unlock (&lock);
}

typedef struct
{
/* thread id */
  uint16_t id;

/* memif connection index */
  uint16_t index;

/* id of queue to be handled by thread */
  uint8_t qid;

/* thread state */
  volatile uint8_t isRunning;

/* number of used rx buffers (pointing to shared memory) */
  uint16_t rx_buf_num;

/* number of used tx buffers (pointing to shared memory) */
  uint16_t tx_buf_num;

/* rx buffers */
  memif_buffer_t *rx_bufs;

/* tx buffers */
  memif_buffer_t *tx_bufs;
  uint64_t tx_counter, rx_counter, tx_err_counter;
} memif_thread_data_t;



static struct _tabs_socks
{
/* array of all created sockets*/
  memif_socket_handle_t *socks;

/* count of all created sockets */
  int cnt_elm;
}
tab_socks;

struct _itms_bridge itms_bridge = { 0 };


memif_connection_t memif_connections[MAX_CONNS] = { 0 };

int epfd;
int out_fd;
uint16_t id_packet = 53;
char key_interrupt = 0;
char cmd_is_running = 0;
memif_thread_data_t thread_data[MAX_CONNS][MAX_QUEUES] = { 0 };
pthread_t thread[MAX_CONNS][MAX_QUEUES] = { 0 };

int cnt_conn = 0;
int ping_qid = 0;
int ping_index = 0;
/* Watch for stdin and memif controll channel events.
 * Increased by each rx queue in interrupt mode
 */
int cnt_poll_events = 1;
uint8_t ip_ping[4] = { 0 };


void
print_help_args ()
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
  printf ("\n");
  printf ("Example usage: ping --vdev=memif0 --master-lcore=0\n");
  printf
    ("	Creates one memif interface named memif0 and sets the affinity of main thread to cpu 0.\n");
  printf ("\n");
  printf ("Arguments:\n");
  printf
    ("	--vdev=<name>,[opt1=<val>,opt2=<val>,...] - Create memif interface with specific options.\n");
  printf
    ("	--master-lcore=<id_cpu> - Set affinity of main thread to specific cpu.\n");
  printf ("\n");
  printf ("Options for --vdev:\n");
  printf ("	id=<num>                   : Unique interface id.\n");
  printf ("	ip=<ip4>                   : Ipv4 address.\n");
  printf
    ("	role=<master|slave>        : Role in which interface operates.\n");
  printf
    ("	socket=<filename>          : Controll channel socket filename.\n");
  printf
    ("	domain=<num>               : Bridge domain, packets are replicated to all interfaces\n");
  printf
    ("	                             assigned to the same bridge domain. Interfaces in\n");
  printf
    ("	                             bridge domain won't respond to ICMP requests.\n");
  printf ("	qpairs=<num>               : Number of queue pairs.\n");
  printf ("	q0-rxmode=<interrupt|poll> : Mode in which qid0 operates.\n");
  printf
    ("	rsize=<num>                : Log2 of ring size. If rsize is 10, actual ring size is 1024.\n");
  printf
    ("	bsize=<num>                : Size of single packet buffer.\n");
  printf
    ("	lcores=[0,1,...]           : Core list. Polling queues are assigned cores from this list.\n");
}

void
print_help_cmds ()
{
  printf ("\n");
  printf ("commands:\n");
  printf ("	help - prints this help\n");
  printf ("	show - show connection details\n");
  printf ("	show log <info|debug> - show runtime logs\n");
  printf ("	sh-count - print counters\n");
  printf ("	cl-count - clear counters\n");
  printf ("	exit - exit app\n");
  printf
    ("	ping <ip4> [-q idx] [-i idx] - ping ip4 address. ping specific queue and\n");
  printf
    ("		                         interface by setting -q and -i respectively\n");
}

static void
print_memif_details ()
{
  memif_details_t md;
  ssize_t buflen;
  char *buf;
  int err, e, ti;
  buflen = 2048;
  buf = malloc (buflen);

  printf ("MEMIF DETAILS\n");
  printf ("==============================\n");

  memset (&md, 0, sizeof (md));
  memset (buf, 0, buflen);

  int idx_conn;
  for (idx_conn = 0; idx_conn < cnt_conn; idx_conn++)
    {
      memif_connection_t *c = &memif_connections[idx_conn];

      err = memif_get_details (c->conn, &md, buf, buflen);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  if (err != MEMIF_ERR_NOCONN)
	    INFO ("%s", memif_strerror (err));
	  continue;
	}
      printf ("index %d\n", idx_conn);
      printf ("\tinterface ip: %u.%u.%u.%u\n",
	      c->ip_src[0], c->ip_src[1], c->ip_src[2], c->ip_src[3]);
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
	  ti = e;
	  printf ("\tqueue id: %u\n", md.rx_queues[e].qid);
	  printf ("\t\tring size: %u\n", md.rx_queues[e].ring_size);
	  printf ("\t\tbuffer size: %u\n", md.rx_queues[e].buffer_size);
	  printf ("\t\tthread id: %u\n", thread_data[idx_conn][ti].id);
	  printf ("\t\tthread connection index: %u\n",
		  thread_data[idx_conn][ti].index);
	  printf ("\t\tthread running: ");
	  if (thread_data[idx_conn][ti].isRunning)
	    printf ("yes\n");
	  else
	    printf ("no\n");
	}
      printf ("\ttx queues:\n");
      for (e = 0; e < md.tx_queues_num; e++)
	{
	  ti = e;
	  printf ("\tqueue id: %u\n", md.tx_queues[e].qid);
	  printf ("\t\tring size: %u\n", md.tx_queues[e].ring_size);
	  printf ("\t\tbuffer size: %u\n", md.tx_queues[e].buffer_size);
	  printf ("\t\tthread id: %u\n", thread_data[idx_conn][ti].id);
	  printf ("\t\tthread connection index: %u\n",
		  thread_data[idx_conn][ti].index);
	  printf ("\t\tthread running: ");
	  if (thread_data[idx_conn][ti].isRunning)
	    printf ("yes\n");
	  else
	    printf ("no\n");
	}
      printf ("\tlink: ");
      if (md.link_up_down)
	printf ("up\n");
      else
	printf ("down\n");
      printf ("\n");
    }
  free (buf);
}

void
icmpr_print_counters ()
{
  int idx_conn;
  for (idx_conn = 0; idx_conn < cnt_conn; idx_conn++)
    {
      memif_connection_t *c = &memif_connections[idx_conn];
      int i;
      printf ("connection index: %d\n", c->args.interface_id);
      for (i = 0; i < c->args.num_s2m_rings; i++)
	{
	  printf ("===============================\n");
	  printf ("queue identification: %d\n", thread_data[idx_conn][i].qid);
	  printf ("\trx: %lu\n", thread_data[idx_conn][i].rx_counter);
	  printf ("\ttx: %lu\n", thread_data[idx_conn][i].tx_counter);
	  printf ("\ttx_err: %lu\n", thread_data[idx_conn][i].tx_err_counter);
	}
      printf ("\n\n");
    }
}

void
icmpr_reset_counters ()
{
  int idx_conn;
  for (idx_conn = 0; idx_conn < cnt_conn; idx_conn++)
    {
      memif_connection_t *c = &memif_connections[idx_conn];
      int i;
      for (i = 0; i < c->current_cnt_q; i++)
	{
	  thread_data[idx_conn][i].rx_counter = 0;
	  thread_data[idx_conn][i].tx_counter = 0;
	  thread_data[idx_conn][i].tx_err_counter = 0;
	}
    }
}

void
print_log (log_type type)
{
  const struct memif_log_msg *log_msg = memif_get_log ();

  while (log_msg != NULL)
    {
      if (log_msg->type & type)
	{
	  struct timespec ts = log_msg->timestamp;

	  char buff[100];
	  strftime (buff, sizeof buff, "%T", gmtime (&ts.tv_sec));
	  printf ("%s.%09ld: ", buff, ts.tv_nsec);

	  printf ("%s\n", log_msg->msg);
	}

      log_msg = TAILQ_NEXT (log_msg, next);
    }
}

/* Any packets received on an interface assigned to bridge domain are
 * replicated to all the interfaces in the same bridge domain.
 */
static int
bridge_handler (memif_connection_t * c, uint16_t rx,
		memif_thread_data_t * thr_data)
{
  struct _table *table = &itms_bridge.table[c->idx_domain];
  memif_buffer_t *rx_bufs = thr_data->rx_bufs;
  memif_buffer_t *tx_bufs = thr_data->tx_bufs;
  long index = thr_data->index;
  uint16_t idx_tab = table->cnt_items;
  int err;
  uint16_t tx = 0;

  while (idx_tab)
    {
      long index1 = table->idx_conn[--idx_tab];

      if (index1 == index)
	continue;

      memif_connection_t *c1 = &memif_connections[index1];
      memset (tx_bufs, 0, sizeof (memif_buffer_t) * rx);

      if (!c1->is_connected)
	continue;

      memif_thread_data_t *thr_data1 = &thread_data[index1][0];
      thr_data1->tx_err_counter += rx;

      /* as this is not the interface which received this packet,
       * rx buffers can't be directly enqueues to tx queue. Instead
       * new tx buffers will be allocated on this interface.
       */
      err =
	memif_buffer_alloc (c1->conn, thr_data->qid, tx_bufs, rx, &tx, 128);

      if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF_RING))
	{
	  INFO ("memif_buffer_alloc: %s", memif_strerror (err));
	  return -1;
	}

      uint16_t tx_rem = tx;
      while (tx_rem--)
	{
	  memcpy (tx_bufs[tx_rem].data, rx_bufs[tx_rem].data,
		  rx_bufs[tx_rem].len);
	  tx_bufs[tx_rem].len = rx_bufs[tx_rem].len;
	}

      DBG ("send packet to index: %ld", index1);

      err = memif_tx_burst (c1->conn, thr_data->qid, tx_bufs, rx, &tx);

      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_tx_burst: %s", memif_strerror (err));
	  return -1;
	}

      thr_data1->tx_err_counter -= tx;
      thr_data1->tx_counter += tx;
    }

  err = memif_refill_queue (c->conn, thr_data->qid, rx, HEADROOM);
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_buffer_free: %s", memif_strerror (err));

  return 0;
}

/* handle ping reply */
static int
ping_handler (memif_connection_t * c, uint16_t rx,
	      memif_thread_data_t * thr_data)
{
  memif_buffer_t *rx_bufs = thr_data->rx_bufs;
  memif_buffer_t *tx_bufs = thr_data->tx_bufs;
  int skip_packet = 0;
  uint16_t tx_cnt = 0;
  int err;

  while (rx--)
    {
      if (ip_src_match (rx_bufs->data, &rx_bufs->len, c->ip_src))
	{
	  INFO ("icmp error: invalid source address");
	  skip_packet = 1;
	}
      else
	if (!ip_dst_match ((void *) rx_bufs->data, &rx_bufs->len, c->ip_src))
	{
	  INFO ("icmp error: invalid destination address");
	  skip_packet = 1;
	}
      else if (echo_ident (rx_bufs->data, &rx_bufs->len, id_packet)
	       || arp_ident (rx_bufs->data, &rx_bufs->len))
	{
	  INFO ("icmp error: unknown L4 protocol");
	  skip_packet = 1;
	}

      /* don't forget to put the skipped buffer back to queue */
      if (skip_packet)
	{
	  err = memif_refill_queue (c->conn, thr_data->qid, 1, HEADROOM);
	  if (err != MEMIF_ERR_SUCCESS)
	    INFO ("memif_buffer_free: %s", memif_strerror (err));
	  continue;
	}

      thr_data->tx_err_counter++;

      if (c->args.is_master)
	{
	  memset (tx_bufs, 0, sizeof (memif_buffer_t));
	  /* allocate tx buffers */
	  err =
	    memif_buffer_alloc (c->conn, thr_data->qid, tx_bufs, 1,
				&tx_cnt, 128);
	  if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF_RING))
	    {
	      INFO ("memif_buffer_alloc: %s", memif_strerror (err));
	      return -1;
	    }

	  resolve_packet ((void *) (rx_bufs)->data, (rx_bufs)->len,
			  (void *) (tx_bufs)->data, &(tx_bufs)->len,
			  c->ip_src);
	}
      else
	{
	  /* resolve packet in place (in rx buffer without copy) */
	  resolve_packet2 ((void *) rx_bufs->data, &rx_bufs->len, c->ip_src);
	  /* equeue rx buffer to tx queue */
	  err =
	    memif_buffer_enq_tx (c->conn, thr_data->qid, rx_bufs, 1, &tx_cnt);
	  if (err != MEMIF_ERR_SUCCESS)
	    {
	      INFO ("memif_buffer_free: %s", memif_strerror (err));
	      return -1;
	    }

	  tx_bufs = rx_bufs;
	}

      /* put rx buffers back to queue */
      err = memif_refill_queue (c->conn, thr_data->qid, 1, HEADROOM);
      if (err != MEMIF_ERR_SUCCESS)
	INFO ("memif_buffer_free: %s", memif_strerror (err));

      err = memif_tx_burst (c->conn, thr_data->qid, tx_bufs, 1, &tx_cnt);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_tx_burst: %s", memif_strerror (err));
	  return -1;
	}

      thr_data->tx_counter += tx_cnt;
      thr_data->tx_err_counter -= tx_cnt;
    }

  return 0;
}

/* polling rx mode, exits on error or disconnect */
void *
memif_rx_poll (void *ptr)
{
  memif_thread_data_t *thr_data = (memif_thread_data_t *) ptr;
  thr_data->isRunning = 1;
  int err = MEMIF_ERR_SUCCESS;
  uint16_t rx = 0, fb = 0;
  char err_thread = 0;

  long index = thr_data->index;
  memif_connection_t *c = &memif_connections[index];

  if (!thr_data->rx_bufs)
    thr_data->rx_bufs = malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);
  if (!thr_data->tx_bufs)
    thr_data->tx_bufs = malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);

  memif_buffer_t *rx_bufs = thr_data->rx_bufs;
  thr_data->rx_buf_num = 0;
  thr_data->tx_buf_num = 0;

  INFO ("pthread id %u starts in polling mode", thr_data->id);

  while (c->is_connected)
    {

/* receive data from shared memory buffers */
      err =
	memif_rx_burst (c->conn, thr_data->qid, rx_bufs, MAX_MEMIF_BUFS, &rx);

      if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF))
	{
	  INFO ("memif_rx_burst: %s", memif_strerror (err));
	  thr_data->rx_buf_num += rx;
	  err_thread = 1;
	  break;
	}

      if (rx == 0)
	continue;

      thr_data->rx_buf_num += rx;
      thr_data->rx_counter += rx;

      DBG ("recv %d, qid: %d", rx, thr_data->qid);

      /* intefaces in bridge domain won't handle ping requests */
      if (c->idx_domain >= 0)
	{
	  if (bridge_handler (c, rx, thr_data) < 0)
	    {
	      err_thread = 1;
	      break;
	    }
	}
      else
	{
	  if (ping_handler (c, rx, thr_data) < 0)
	    {
	      err_thread = 1;
	      break;
	    }
	}
    }

  if (err_thread)
    INFO ("thread %u error!", thr_data->id);

  err = memif_refill_queue (c->conn, thr_data->qid, -1, HEADROOM);

  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_buffer_free: %s", memif_strerror (err));

  thr_data->rx_buf_num -= fb;
  DBG ("freed %d buffers. %u/%u alloc/free buffers",
       fb, thr_data->rx_buf_num, MAX_MEMIF_BUFS - thr_data->rx_buf_num);

  if (thr_data->rx_bufs)
    free (thr_data->rx_bufs);
  if (thr_data->tx_bufs)
    free (thr_data->tx_bufs);
  thr_data->rx_bufs = thr_data->tx_bufs = 0;
  INFO ("pthread id %u exit", thr_data->id);
  thr_data->isRunning = 0;
  pthread_exit (NULL);
}


/* informs user about connected status. private_ctx is used by user to identify connection */
int
on_connect (memif_conn_handle_t conn, void *private_ctx)
{
  INFO ("memif connected!");
  long index = (*(long *) private_ctx);
  memif_connection_t *c = &memif_connections[index];
  c->is_connected = 1;
  memif_thread_data_t *thr_data;

  /* increment event counter if queue 0 is in interrupt mode */
  if (!c->set_q0_poll)
    cnt_poll_events++;

  int err;
  memif_details_t md;
  ssize_t buflen;
  char *buf;
  buflen = 2048;
  buf = malloc (buflen);
  err = memif_get_details (conn, &md, buf, buflen);
  free (buf);

  if (err != MEMIF_ERR_SUCCESS)
    {
      if (err != MEMIF_ERR_NOCONN)
	INFO ("memif_get_details: %s", memif_strerror (err));
      return -1;
    }

  c->current_cnt_q = md.rx_queues_num;

  if (md.rx_queues_num < 1)
    {
      INFO ("invalid number of queues");
      return -1;
    }

  DBG ("queues_num: %d", md.rx_queues_num);

  memif_refill_queue (conn, 0, -1, HEADROOM);

  int index_q;

  if (c->set_q0_poll)
    index_q = 0;
  else
    {
      err = memif_set_rx_mode (conn, MEMIF_RX_MODE_INTERRUPT, 0);
      index_q = 1;
      thr_data = &thread_data[index][0];

      if (!thr_data->rx_bufs);
      thr_data->rx_bufs =
	(memif_buffer_t *) malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);
      if (!thr_data->tx_bufs);
      thr_data->tx_bufs =
	(memif_buffer_t *) malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);
      thr_data->index = index;
      thr_data->isRunning = 1;
    }

  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_set_rx_mode: %s qid: %u", memif_strerror (err), 0);

  for (; index_q < md.rx_queues_num; index_q++)
    {
      memif_refill_queue (conn, index_q, -1, HEADROOM);
      err = memif_set_rx_mode (conn, MEMIF_RX_MODE_POLLING, index_q);

      if (err != MEMIF_ERR_SUCCESS)
	INFO ("memif_set_rx_mode: %s qid: %u", memif_strerror (err), index_q);
      else
	{
	  int ti = index * MAX_QUEUES + index_q;
	  thr_data = &thread_data[index][index_q];
	  if (thr_data->isRunning)
	    {
	      INFO ("thread id: %d already running!", ti);
	      continue;
	    }

	  thr_data->index = index;
	  thr_data->qid = index_q;
	  thr_data->id = ti;

	  pthread_create (&thread[index][index_q], NULL,
			  memif_rx_poll, (void *) thr_data);

	  if (index_q == 0 && CPU_COUNT (&c->q0_corelist) > 0)
	    {
	      int s =
		pthread_setaffinity_np (thread[index][0], sizeof (cpu_set_t),
					&c->q0_corelist);
	      if (s != 0)
		INFO
		  ("settin of affinity cpu for connection %d is ending with error code %d",
		   c->index, s);
	    }
	}
    }

  return 0;
}

/* informs user about disconnected status. private_ctx is used by user to identify connection */
int
on_disconnect (memif_conn_handle_t conn, void *private_ctx)
{
  INFO ("memif disconnected!");
  long index = (*(long *) private_ctx);
  memif_connection_t *c = &memif_connections[index];
  c->is_connected = 0;

  /* decrement event counter if queue 0 is in interrupt mode */
  if (!c->set_q0_poll)
    cnt_poll_events--;

  void *ptr;
  int index_q = 0;

  if (!c->set_q0_poll)
    {
      memif_thread_data_t *thr_data = &thread_data[index][0];

      if (thr_data->rx_bufs)
	free (thr_data->rx_bufs);
      thr_data->rx_bufs = NULL;

      if (thr_data->tx_bufs)
	free (thr_data->tx_bufs);
      thr_data->tx_bufs = NULL;
      index_q = 1;
    }

  for (; index_q < c->current_cnt_q; index_q++)
    pthread_join (thread[index][index_q], &ptr);

  return 0;
}

/* user needs to watch new fd or stop watching fd that is about to be closed.
control fd will be modified during connection establishment to minimize CPU usage */
int
control_fd_update (int fd, uint8_t events, void *ctx)
{
/* convert memif event definitions to epoll events */
  if (events & MEMIF_FD_EVENT_DEL)
    return del_epoll_fd (epfd, fd);

  uint32_t evt = 0;
  if (events & MEMIF_FD_EVENT_READ)
    evt |= EPOLLIN;
  if (events & MEMIF_FD_EVENT_WRITE)
    evt |= EPOLLOUT;

  if (events & MEMIF_FD_EVENT_MOD)
    return mod_epoll_fd (epfd, fd, evt);

  return add_epoll_fd (epfd, fd, evt);
}



/* called when event is polled on interrupt file descriptor.
 * there are packets in shared memory ready to be received.
 */
int
on_interrupt (memif_conn_handle_t conn, void *private_ctx, uint16_t qid)
{
  long index = (*(long *) private_ctx);
  int err = MEMIF_ERR_SUCCESS, ret_val;
  uint16_t rx = 0, tx = 0;
  uint8_t req_mrefill = 0, skip_packet = 0;

  memif_connection_t *c = &memif_connections[index];
  memif_thread_data_t *thr_data = &thread_data[index][qid];

/* receive data from shared memory buffers */
  err = memif_rx_burst (conn, qid, thr_data->rx_bufs, MAX_MEMIF_BUFS, &rx);
  ret_val = err;

  if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF))
    {
      INFO ("memif_rx_burst: %s", memif_strerror (err));
      req_mrefill = 1;
    }
  DBG (":rx: %d", rx);
  uint16_t tx_cnt = 0;
  thread_data[index][qid].rx_counter += rx;

  /* intefaces in bridge domain won't handle ping requests */
  if (c->idx_domain >= 0)
    {
      if (bridge_handler (c, rx, thr_data) < 0)
	{
	  req_mrefill = 1;
	}
    }
  else
    {
      if (ping_handler (c, rx, thr_data) < 0)
	{
	  req_mrefill = 1;
	}
    }

  if (req_mrefill)
    {
      err = memif_refill_queue (conn, qid, -1, HEADROOM);

      if (err != MEMIF_ERR_SUCCESS)
	INFO ("memif_buffer_free: %s", memif_strerror (err));
    }

  return 0;
}


int
icmpr_memif_create ()
{
  int err;

  int idx_conn;
  for (idx_conn = 0; idx_conn < cnt_conn; idx_conn++)
    {
      memif_connection_t *c = &memif_connections[idx_conn];

      if (c->sock_name)
	{
	  memif_socket_handle_t sock;
	  int cp_idx_conn = idx_conn;

	  /* check if socket with this filename exists */
	  while (cp_idx_conn > 0)
	    {
	      memif_connection_t *c1 = &memif_connections[--cp_idx_conn];

	      if (!c1->sock_name)
		continue;

	      if (strcmp (c1->sock_name, c->sock_name) == 0)
		{
		  c->args.socket = c1->args.socket;
		  break;
		}
	    }
	  if (c->args.socket == 0)
	    {
	      int err = memif_create_socket (&sock, c->sock_name, &c->index);

	      if (err != MEMIF_ERR_SUCCESS)
		INFO ("memif_create_socket: %s\n", memif_strerror (err));
	      else
		{
		  tab_socks.socks[tab_socks.cnt_elm++] = sock;
		  c->args.socket = sock;
		}
	    }
	}

      if (c->set_q0_poll)
	err = memif_create (&c->conn, &c->args, on_connect, on_disconnect,
			    NULL, &c->index);
      else
	err = memif_create (&c->conn, &c->args, on_connect, on_disconnect,
			    on_interrupt, &c->index);

      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("index: %d", idx_conn);
	  INFO ("memif_create: %s\n", memif_strerror (err));
	  continue;
	}
    }

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
  memif_connection_t *c = &memif_connections[index];

  if (c->sock_name)
    free (c->sock_name);
  c->sock_name = NULL;

  int err;

  void *ptr;
  int index_q;

  uint8_t cnt_q = c->current_cnt_q;

  if (!c->set_q0_poll)
    {
      thread_data[index][0].isRunning = 0;
      cnt_q = cnt_q <= 0 ? 1 : cnt_q;
    }

  c->is_connected = 0;
  for (index_q = 0; index_q < cnt_q; index_q++)
    {
      memif_thread_data_t *thr_data = &thread_data[index][index_q];
      if (index_q != 0 || c->set_q0_poll)
	pthread_join (thread[index][index_q], &ptr);

      if (thr_data->rx_bufs)
	free (thr_data->rx_bufs);
      thr_data->rx_bufs = NULL;

      if (thr_data->tx_bufs)
	free (thr_data->tx_bufs);
      thr_data->tx_bufs = NULL;
    }

/* disconenct then delete memif connection */

  err = memif_delete (&c->conn);
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_delete: %s", memif_strerror (err));

  return 0;
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

  for (i = 0; i < cnt_conn; i++)
    {
      memif_connection_t *c = &memif_connections[i];
      if (c->conn)
	icmpr_memif_delete (i);
    }

  int idx = tab_socks.cnt_elm;
  while (idx--)
    {
      INFO ("idx: %d", idx);
      err = memif_delete_socket (&tab_socks.socks[idx]);
      if (err != MEMIF_ERR_SUCCESS)
	INFO ("memif_delete: %s", memif_strerror (err));
    }

  err = memif_cleanup ();
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_delete: %s", memif_strerror (err));

  free (tab_socks.socks);
  return 0;
}

void
logs_free ()
{
  struct memif_log_msg *head_remove;

  while (!TAILQ_EMPTY (&head_info))
    {
      head_remove = TAILQ_FIRST (&head_info);
      free (head_remove->msg);
      TAILQ_REMOVE (&head_info, head_remove, next);
      free (head_remove);
    }
}

void
icmpr_exit (int sig)
{
  icmpr_free ();
  logs_free ();
  exit (EXIT_SUCCESS);
}

int
icmp_ping (uint32_t seq)
{
  int err = MEMIF_ERR_SUCCESS, ret_val;
  uint16_t tx = 0;

  memif_connection_t *c = &memif_connections[ping_index];
  memif_buffer_t *tx_bufs = thread_data[ping_index][0].tx_bufs;
  err = memif_buffer_alloc (c->conn, ping_qid, tx_bufs, 1, &tx, 128);

  if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF_RING))
    {
      INFO ("memif_buffer_alloc: %s Thread exiting...\n",
	    memif_strerror (err));
      return -1;
    }

  if (tx)
    {
      generate_ping (tx_bufs->data, &tx_bufs->len, c->ip_src, ip_ping,
		     seq, id_packet);
    }

  err = memif_tx_burst (c->conn, ping_qid, tx_bufs, 1, &tx);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_tx_burst: %s Thread exiting...\n", memif_strerror (err));
      return -1;
    }

  thread_data[ping_index][ping_qid].tx_counter += tx;

  return 0;
}


int
user_input_handler ()
{
  char in[256];
  char *ui = fgets (in, 256, stdin);
  int last_pos = strlen (in) - 1;

  if (in[last_pos] == '\n')
    in[last_pos] = '\0';


  if (in[0] != '\0' && !cmd_is_running)
    {
      ui = strtok (in, " ");

      if (strcmp (ui, "ping") == 0)
	{
	  ui += strlen (ui) + 1;
	  if (valid_ping (ui, ip_ping, &ping_index, &ping_qid))
	    {
	      start_ping ();
	      cmd_is_running = 1;
	      key_interrupt = 0;
	    }
	}
      else if (strcmp (ui, "show") == 0)
	{
	  ui = strtok (NULL, " ");
	  if (!ui)
	    print_memif_details ();
	  else if (strcmp (ui, "log") == 0)
	    {
	      ui = strtok (NULL, " ");
	      if (!ui)
		print_log (INFO_TYPE | DEBUG_TYPE);
	      else
		{
		  log_type type = 0;
		  do
		    {
		      if (strcmp (ui, "info") == 0)
			type |= INFO_TYPE;
		      else if (strcmp (ui, "debug") == 0)
			type |= DEBUG_TYPE;
		    }
		  while (ui = strtok (NULL, " "));
		  print_log (type);
		}
	    }
	}
      else if (strcmp (ui, "help") == 0)
	{
	  print_help_cmds ();
	}
      else if (strcmp (ui, "sh-count") == 0)
	{
	  icmpr_print_counters ();
	}
      else if (strcmp (ui, "cl-count") == 0)
	{
	  icmpr_reset_counters ();
	}
      else if (strcmp (ui, "exit") == 0)
	{
	  icmpr_free ();
	  logs_free ();
	  exit (EXIT_SUCCESS);
	}
      else
	{
	  printf ("unknown command\n");
	}
    }

  if (!cmd_is_running)
    {
      printf ("> ");
      fflush (stdout);
    }

  return 0;
}

int
poll_event (int timeout)
{
  struct epoll_event evts[cnt_poll_events];
  struct epoll_event *evt;
  int app_err = 0, memif_err = 0, en = 0;
  uint32_t events = 0;
  struct timespec end;
  memset (evts, 0, cnt_poll_events * sizeof (struct epoll_event));

  uint32_t rem_poll_events = cnt_poll_events;
  while (rem_poll_events)
    {
      evts[--rem_poll_events].events = EPOLLIN | EPOLLOUT;
    }

  sigset_t sigset;
  sigemptyset (&sigset);

  if (key_interrupt && cmd_is_running)
    {
      printf ("Aborted due to a keypress.");
    }

  if (poll_ping (&timeout, key_interrupt) == 1)
    {
      cmd_is_running = 0;
      printf ("> ");
      fflush (stdout);
    }

  key_interrupt = 0;
  en = epoll_pwait (epfd, evts, cnt_poll_events, timeout, &sigset);
/* id event polled */

  if (en < 0)
    {
      INFO ("epoll_pwait: %s", strerror (errno));
      return -1;
    }

  while (en-- > 0)
    {
      evt = &evts[en];
/* this app does not use any other file descriptors than stds and memif control fds */
      if (evt->data.fd > 2)
	{
/* convert epoll events to memif events */
	  if (evt->events & EPOLLIN)
	    events |= MEMIF_FD_EVENT_READ;
	  if (evt->events & EPOLLOUT)
	    events |= MEMIF_FD_EVENT_WRITE;
	  if (evt->events & EPOLLERR)
	    events |= MEMIF_FD_EVENT_ERROR;
	  memif_err = memif_control_fd_handler (evt->data.fd, events);
	  if (memif_err != MEMIF_ERR_SUCCESS)
	    INFO ("memif_control_fd_handler: %s", memif_strerror (memif_err));
	}
      else if (evt->data.fd == 0)
	{
	  key_interrupt = 1;
	  app_err = user_input_handler ();
	}
      else
	{
	  INFO ("unexpected event at memif_epfd. fd %d", evt->data.fd);
	}
    }

  return 0;
}

int
main (int argc, char *argv[])
{
  int pos_arg;
  char *err_msg;
  TAILQ_INIT (&head_info);

  if (argc > 1 && strcmp (argv[1], "-h") == 0)
    {
      print_help_args ();
      return 1;
    }

  for (pos_arg = 1; pos_arg < argc; pos_arg++)
    {
      if (parse_arg (argv[pos_arg], &err_msg) < 0)
	{
	  printf ("argument \"%s\" will be skipped - %s\n", argv[pos_arg],
		  err_msg);
	}
    }

  if (!cnt_conn)
    {
      print_help_args ();
      return 1;
    }

  signal (SIGINT, icmpr_exit);

  tab_socks.socks =
    (memif_socket_handle_t *) malloc (cnt_conn *
				      sizeof (memif_socket_handle_t));
  memset (tab_socks.socks, 0, cnt_conn * sizeof (memif_socket_handle_t));
  tab_socks.cnt_elm = 0;

  srand (time (NULL));
  id_packet = rand () % (2 << 16 - 1);
  DBG ("id_packet: %d", id_packet);
  epfd = epoll_create (1);
  add_epoll_fd (epfd, 0, EPOLLIN);

  int err;
  err = memif_init (control_fd_update, APP_NAME, NULL, NULL, NULL);

  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_init: %s", memif_strerror (err));
      icmpr_free ();
      logs_free ();
      return -1;
    }

  icmpr_memif_create ();
  ping_init (WAIT_ECHO_MS, MAX_PING_CNT, icmp_ping);

  printf ("> ");
  fflush (stdout);

  while (1)
    {
      if (poll_event (-1) < 0)
	{
	  DBG ("poll_event error!");
	}
    }

  return 0;
}
