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
#define MAX_MEMIF_BUFS 256

typedef struct
{
  uint16_t index;
  /* memif conenction handle */
  memif_conn_handle_t conn;
  /* transmit queue id */
  uint16_t tx_qid;
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

memif_connection_t memif_connection;
int epfd;

static void
print_memif_details ()
{
  memif_connection_t *c = &memif_connection;
  printf ("MEMIF DETAILS\n");
  printf ("==============================\n");


  memif_details_t md;
  memset (&md, 0, sizeof (md));
  ssize_t buflen = 2048;
  char *buf = malloc (buflen);
  memset (buf, 0, buflen);
  int err, e;

  err = memif_get_details (c->conn, &md, buf, buflen);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("%s", memif_strerror (err));
      if (err == MEMIF_ERR_NOCONN)
	{
	  free (buf);
	  return;
	}
    }

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

  free (buf);
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

int
icmpr_memif_delete ()
{
  int err;
  /* disconnect then delete memif connection */
  err = memif_delete (&(&memif_connection)->conn);
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
  printf ("\tuse CTRL+C to exit\n");
}

int
icmpr_buffer_alloc (long n, uint16_t qid)
{
  memif_connection_t *c = &memif_connection;
  int err;
  uint16_t r;
  /* set data pointer to shared memory and set buffer_len to shared memory buffer len */
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
icmpr_tx_burst (uint16_t qid)
{
  memif_connection_t *c = &memif_connection;
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

int
icmpr_free ()
{
  /* application cleanup */
  int err;
  memif_connection_t *c = &memif_connection;
  free (c->tx_bufs);
  c->tx_bufs = NULL;
  free (c->rx_bufs);
  c->rx_bufs = NULL;

  err = memif_cleanup ();
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_delete: %s", memif_strerror (err));

  return 0;
}

void
icmpr_exit (int sig)
{
  printf ("\n");
  icmpr_memif_delete ();
  icmpr_free ();
  exit (EXIT_SUCCESS);
}

/* called when event is polled on interrupt file descriptor.
    there are packets in shared memory ready to be received */
int
on_interrupt (memif_conn_handle_t conn, void *private_ctx, uint16_t qid)
{
  DBG ("interrupted");
  memif_connection_t *c = &memif_connection;
  int err;
  uint16_t rx;
  /* receive data from shared memory buffers */
  err = memif_rx_burst (c->conn, qid, c->rx_bufs, MAX_MEMIF_BUFS, &rx);
  c->rx_buf_num += rx;

  DBG ("received %d buffers. %u/%u alloc/free buffers",
       rx, c->rx_buf_num, MAX_MEMIF_BUFS - c->rx_buf_num);

  if (icmpr_buffer_alloc (rx, c->tx_qid) < 0)
    {
      INFO ("buffer_alloc error");
      goto error;
    }
  int i;
  for (i = 0; i < rx; i++)
    {
      resolve_packet ((void *) (c->rx_bufs + i)->data,
		      (c->rx_bufs + i)->len,
		      (void *) (c->tx_bufs + i)->data,
		      &(c->tx_bufs + i)->len, c->ip_addr);
    }

  /* mark memif buffers and shared memory buffers as free */
  err = memif_refill_queue (c->conn, qid, rx, 0);
  /*
   * In this example we can assert that c->conn points to valid connection
   * and 'rx <= c->rx_buf_num'.
   */
  c->rx_buf_num -= rx;

  DBG ("freed %d buffers. %u/%u alloc/free buffers",
       rx, c->rx_buf_num, MAX_MEMIF_BUFS - c->rx_buf_num);

  icmpr_tx_burst (c->tx_qid);

  return 0;

error:
  err = memif_refill_queue (c->conn, qid, rx, 0);
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_buffer_free: %s", memif_strerror (err));
  c->rx_buf_num -= rx;
  DBG ("freed %d buffers. %u/%u alloc/free buffers",
       rx, c->rx_buf_num, MAX_MEMIF_BUFS - c->rx_buf_num);
  return 0;
}

int
icmpr_memif_create (int is_master)
{
  /* setting memif connection arguments */
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));
  args.is_master = is_master;
  args.log2_ring_size = 10;
  args.buffer_size = 2048;
  args.num_s2m_rings = 2;
  args.num_m2s_rings = 2;
  strncpy ((char *) args.interface_name, IF_NAME, strlen (IF_NAME));
  args.mode = 0;
  /* socket filename is not specified, because this app is supposed to
     connect to VPP over memif. so default socket filename will be used */
  /* default socketfile = /run/vpp/memif.sock */

  args.interface_id = 0;
  /* last argument for memif_create (void * private_ctx) is used by user
     to identify connection. this context is returned with callbacks */
  int err = memif_create (&(&memif_connection)->conn,
			  &args, on_connect, on_disconnect, on_interrupt,
			  NULL);
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_create: %s", memif_strerror (err));
  return 0;
}

int
main (int argc, char *argv[])
{
  memif_connection_t *c = &memif_connection;

  signal (SIGINT, icmpr_exit);

  /* initialize global memif connection handle */
  c->conn = NULL;
  if (argc == 1)
    c->tx_qid = 0;
  else
    {
      char *end;
      c->tx_qid = strtol (argv[1], &end, 10);
    }
  INFO ("tx qid: %u", c->tx_qid);
  /* alloc memif buffers */
  c->rx_buf_num = 0;
  c->rx_bufs =
    (memif_buffer_t *) malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);
  c->tx_buf_num = 0;
  c->tx_bufs =
    (memif_buffer_t *) malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);
  c->ip_addr[0] = 192;
  c->ip_addr[1] = 168;
  c->ip_addr[2] = 1;
  c->ip_addr[3] = 2;
  /* initialize memory interface */
  int err;
  /* if valid callback is passed as argument, fd event polling will be done by user
     all file descriptors and events will be passed to user in this callback */
  /* if callback is set to NULL libmemif will handle fd event polling */
  err = memif_init (NULL, APP_NAME, NULL, NULL, NULL);
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_init: %s", memif_strerror (err));

  print_help ();

  icmpr_memif_create (0);
  print_memif_details ();

  /* main loop */
  while (1)
    {
      if (memif_poll_event (-1) < 0)
	{
	  DBG ("poll_event error!");
	}
    }
}
