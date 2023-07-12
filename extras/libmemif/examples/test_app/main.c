/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>

#include <libmemif.h>
#include <common.h>

#define APP_NAME "test_app"

#define IF_NAME0    "libmemif0"
#define IF_ID0	    0
#define IF_NAME1    "libmemif1"
#define IF_ID1	    1
#define SOCKET_PATH "/run/vpp/memif.sock"

memif_connection_t intf0, intf1;
int epfd;

/* informs user about connected status. private_ctx is used by user to identify
 * connection */
int
on_connect (memif_conn_handle_t conn, void *private_ctx)
{
  INFO ("memif connected!");
  int err;

  memif_connection_t *c = (memif_connection_t *) private_ctx;

  c->is_connected = 1;
  alloc_memif_buffers (c);

  err = memif_refill_queue (conn, 0, -1, 0);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_refill_queue: %s", memif_strerror (err));
      return err;
    }

  print_memif_details (c);

  return 0;
}

/* informs user about disconnected status. private_ctx is used by user to
 * identify connection */
int
on_disconnect (memif_conn_handle_t conn, void *private_ctx)
{
  INFO ("memif disconnected!");

  memif_connection_t *c = (memif_connection_t *) private_ctx;

  c->is_connected = 0;
  free_memif_buffers (c);

  /* stop event polling thread */
  int err = memif_cancel_poll_event (memif_get_socket_handle (conn));
  if (err != MEMIF_ERR_SUCCESS)
    INFO ("We are doomed...");

  return 0;
}

int
on_interrupt (memif_conn_handle_t conn, void *private_ctx, uint16_t qid)
{
  memif_connection_t *c = (memif_connection_t *) private_ctx;
  memif_connection_t *s, *r;
  int err, i;
  uint16_t tx;

  if (c == &intf0)
    {
      r = &intf0;
      s = &intf1;
    }
  else
    {
      r = &intf1;
      s = &intf0;
    }

  /* receive packets from the shared memory */
  err =
    memif_rx_burst (r->conn, qid, r->rx_bufs, MAX_MEMIF_BUFS, &r->rx_buf_num);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_rx_burst: %s", memif_strerror (err));
      return err;
    }

  do
    {
      /* allocate tx buffers */
      err = memif_buffer_alloc (s->conn, s->tx_qid, s->tx_bufs, r->rx_buf_num,
				&s->tx_buf_num, s->buffer_size);
      /* suppress full ring error MEMIF_ERR_NOBUF_RING */
      if (err != MEMIF_ERR_SUCCESS && err != MEMIF_ERR_NOBUF_RING)
	{
	  INFO ("memif_buffer_alloc: %s", memif_strerror (err));
	  goto error;
	}

      /* Process the packets */
      for (i = 0; i < s->tx_buf_num; i++)
	{
	  memcpy (s->tx_bufs[i].data, r->rx_bufs[i].data, r->rx_bufs[i].len);
	  s->tx_bufs[i].flags = r->rx_bufs[i].flags;
	  s->tx_bufs[i].len = r->rx_bufs[i].len;
	}

      /* Done processing packets */
      /* refill the queue */
      err = memif_refill_queue (r->conn, qid, s->tx_buf_num, 0);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_refill_queue: %s", memif_strerror (err));
	  goto error;
	}
      r->rx_buf_num -= s->tx_buf_num;

      err =
	memif_tx_burst (s->conn, s->tx_qid, s->tx_bufs, s->tx_buf_num, &tx);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_tx_burst: %s", memif_strerror (err));
	  goto error;
	}
      s->tx_buf_num -= tx;
      /* This should never happen */
      if (s->tx_buf_num != 0)
	{
	  INFO ("memif_tx_burst failed to send all allocated buffers.");
	  goto error;
	}
    }
  while (r->rx_buf_num > 0);

  return 0;

error:
  err = memif_refill_queue (conn, qid, r->rx_buf_num, 0);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_refill_queue: %s", memif_strerror (err));
      return err;
    }
  r->rx_buf_num = 0;

  return -1;
}

void
print_help ()
{
  printf ("LIBMEMIF TEST APP: %s", APP_NAME);
#ifdef TEST_DBG
  printf (" (debug)");
#endif
  printf ("\n");
  printf ("==============================\n");
  print_version ();
  printf ("==============================\n");
  printf (
    "In this testing application, memif endpoints connect to an external "
    "application.\n");
  printf ("The test application loopbacks recieved packets from one memif to "
	  "another memif .\n");
  printf ("The program will exit once the interfaces are disconnected.\n");
  printf ("==============================\n");
  printf ("Usage: test_app [OPTIONS]\n\n");
  printf ("Options:\n");
  printf ("\t-r\tInterface role <slave|master>. Default: slave\n");
  printf ("\t-s\tSocket path. Supports abstract socket using @ before the "
	  "path. Default: /run/vpp/memif.sock\n");
  printf ("\t-i\tInterface id. Default: 0\n");
  printf ("\t-t\tInterface id2. Default: 1\n");
  printf ("\t-b\tBuffer Size. Default: 2048\n");
  printf ("\t-h\tShow help and exit.\n");
  printf ("\t-v\tShow libmemif and memif version information and exit.\n");
}

int
main (int argc, char *argv[])
{
  memif_socket_args_t memif_socket_args = { 0 };
  memif_socket_handle_t memif_socket;
  memif_conn_args_t memif_conn_args = { 0 };
  int opt, err, ret = 0;
  uint8_t is_master = 0;
  char socket_path[108];
  int id0 = IF_ID0;
  int id1 = IF_ID1;

  strncpy (socket_path, SOCKET_PATH, sizeof (SOCKET_PATH));

  /* prepare the private data */
  memset (&intf0, 0, sizeof (intf0));
  memset (&intf1, 0, sizeof (intf1));

  while ((opt = getopt (argc, argv, "r:s:i:t:b:hv")) != -1)
    {
      switch (opt)
	{
	case 'r':
	  if (strncmp (optarg, "master", sizeof (optarg)) == 0)
	    {
	      is_master = 1;
	    }
	  else if (strncmp (optarg, "slave", sizeof (optarg)) == 0)
	    {
	      is_master = 0;
	    }
	  else
	    {
	      INFO ("Invalid role value: '%s'", optarg);
	      return -1;
	    }
	  break;
	case 's':
	  sprintf (socket_path, "%s", optarg);
	  break;
	case 'i':
	  id0 = atoi (optarg);
	  break;
	case 't':
	  id1 = atoi (optarg);
	  break;
	case 'b':
	  intf1.buffer_size = intf0.buffer_size = atoi (optarg);
	  break;
	case 'h':
	  print_help ();
	  return 0;
	case 'v':
	  print_version ();
	  return 0;
	}
    }

  /** Create memif socket
   *
   * Interfaces are internally stored in a database referenced by memif socket.
   */
  sprintf (memif_socket_args.path, "%s", socket_path);
  /* Set application name */
  strncpy (memif_socket_args.app_name, APP_NAME, strlen (APP_NAME));

  /* configure autoconnect timer */
  if (is_master == 0)
    {
      memif_socket_args.connection_request_timer.it_value.tv_sec = 2;
      memif_socket_args.connection_request_timer.it_value.tv_nsec = 0;
      memif_socket_args.connection_request_timer.it_interval.tv_sec = 2;
      memif_socket_args.connection_request_timer.it_interval.tv_nsec = 0;
    }

  err = memif_create_socket (&memif_socket, &memif_socket_args, NULL);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_create_socket: %s", memif_strerror (err));
      goto error;
    }

  /**
   * Create memif interfaces
   */
  memif_conn_args.socket = memif_socket;
  memif_conn_args.interface_id = id0;
  strncpy (memif_conn_args.interface_name, IF_NAME0,
	   sizeof (memif_conn_args.interface_name));
  memif_conn_args.is_master = is_master;
  if (intf0.buffer_size)
    memif_conn_args.buffer_size = intf0.buffer_size;
  else
    memif_conn_args.buffer_size = intf0.buffer_size = intf1.buffer_size = 2048;

  err = memif_create (&intf0.conn, &memif_conn_args, on_connect, on_disconnect,
		      on_interrupt, (void *) &intf0);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_create_socket: %s", memif_strerror (err));
      return err;
    }

  memif_conn_args.interface_id = id1;
  strncpy (memif_conn_args.interface_name, IF_NAME1,
	   sizeof (memif_conn_args.interface_name));

  err = memif_create (&intf1.conn, &memif_conn_args, on_connect, on_disconnect,
		      on_interrupt, (void *) &intf1);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_create_socket: %s", memif_strerror (err));
      return err;
    }

  do
    {
      err = memif_poll_event (memif_socket, -1);
    }
  while (err == MEMIF_ERR_SUCCESS);

  return 0;

error:
  ret = -1;
done:
  free_memif_buffers (&intf0);
  free_memif_buffers (&intf1);
  memif_delete (&intf0.conn);
  memif_delete (&intf1.conn);
  memif_delete_socket (&memif_socket);
  return ret;
}
