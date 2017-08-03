/*
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
 */

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <uri/sock_test.h>

typedef struct
{
  uint8_t *buf;
  uint32_t buf_size;
  sock_test_cfg_t cfg;
  sock_test_stats_t stats;
} sock_server_main_t;

sock_server_main_t sock_server_main;

static void
echo_test_server (sock_test_cfg_t * rx_cfg)
{
  sock_server_main_t *ssm = &sock_server_main;

  printf ("SERVER: Configuring for Echo Test.\n");
  ssm->cfg = *rx_cfg;
  sock_test_buf_alloc (&ssm->cfg, 1 /* is_rxbuf */ ,
		       &ssm->buf, &ssm->buf_size);
  ssm->cfg.txbuf_size = ssm->cfg.rxbuf_size;
}

static void
stream_test_server (int client_fd, sock_test_t test, int cfg_rx_bytes)
{
  sock_server_main_t *ssm = &sock_server_main;
  int rv, rx_bytes;
  sock_test_cfg_t *rx_cfg = (sock_test_cfg_t *) ssm->buf;

  if (cfg_rx_bytes == sizeof (sock_test_cfg_t))
    {
      ssm->cfg = *rx_cfg;
      sock_test_buf_alloc (&ssm->cfg, 1 /* is_rxbuf */ ,
			   &ssm->buf, &ssm->buf_size);
      ssm->cfg.txbuf_size = ssm->cfg.rxbuf_size;
      printf ("\n" SOCK_TEST_BANNER_STRING
	      "SERVER: %s-directional Stream Test!\n"
	      "  Sending client the test cfg to start streaming data...\n",
	      test == SOCK_TEST_TYPE_BI ? "Bi" : "Uni");
      if (ssm->cfg.verbose)
	sock_test_cfg_dump (&ssm->cfg, 0 /* is_client */ );
      rv = sock_test_write (client_fd, (uint8_t *) & ssm->cfg,
			    sizeof (ssm->cfg), &ssm->stats, ssm->cfg.verbose);
      if (rv < 0)
	{
	  printf ("SERVER: test cfg send failed -- aborting!\n");
	  return;
	}
    }
  else
    {
      printf ("Error: Bad sock_test_cfg_t received -- aborting test!\n");
      ssm->cfg.rxbuf_size = 0;
      ssm->cfg.num_writes = 0;
      rv =
	sock_test_write (client_fd, (uint8_t *) & ssm->cfg,
			 sizeof (ssm->cfg), &ssm->stats, ssm->cfg.verbose);
      return;
    }

  /* read the 1st chunk, record start time */
  memset (&ssm->stats, 0, sizeof (ssm->stats));
  rx_bytes = sock_test_read (client_fd, ssm->buf, ssm->buf_size, &ssm->stats);
  clock_gettime (CLOCK_REALTIME, &ssm->stats.start);
  if (test == SOCK_TEST_TYPE_BI)
    (void) sock_test_write (client_fd, ssm->buf, rx_bytes, &ssm->stats,
			    ssm->cfg.verbose);
  while (ssm->stats.rx_bytes < ssm->cfg.total_bytes)
    {
      rx_bytes = sock_test_read (client_fd, ssm->buf, ssm->buf_size,
				 &ssm->stats);
      if (test == SOCK_TEST_TYPE_BI)
	(void) sock_test_write (client_fd, ssm->buf, rx_bytes, &ssm->stats,
				ssm->cfg.verbose);
    }

  clock_gettime (CLOCK_REALTIME, &ssm->stats.stop);

  sock_test_stats_dump ("SERVER RESULTS", &ssm->stats, 1 /* show_rx */ ,
			(test == SOCK_TEST_TYPE_BI) /* show_tx */ ,
			ssm->cfg.verbose);
  sock_test_cfg_dump (&ssm->cfg, 0 /* is_client */ );
  if (ssm->cfg.verbose)
    {
      printf ("  sock server main\n"
	      SOCK_TEST_SEPARATOR_STRING
	      "       buf:  %p\n"
	      "  buf size:  %u (0x%08x)\n"
	      SOCK_TEST_SEPARATOR_STRING,
	      ssm->buf, ssm->buf_size, ssm->buf_size);
    }

  rx_bytes = sock_test_read (client_fd, ssm->buf, sizeof (ssm->cfg),
			     &ssm->stats);

  if ((rx_bytes == sizeof (ssm->cfg))
      && (rx_cfg->ctrl == SOCK_TEST_CFG_CTRL_MAGIC))
    {
      if (ssm->cfg.verbose)
	{
	  printf ("SERVER: Received a cfg message!\n");
	  sock_test_cfg_dump (rx_cfg, 0 /* is_client */ );
	}
      ssm->cfg = *rx_cfg;
      sock_test_buf_alloc (&ssm->cfg, 1 /* is_rxbuf */ ,
			   &ssm->buf, &ssm->buf_size);
    }
  else
    {
      fprintf (stderr, "ERROR: Last read was not a test cfg message!\n"
	       "  bytes read = %d (0x%08x), cfg.ctrl = 0x%08x\n"
	       "  Run the echo test to see error stats.\n",
	       rx_bytes, rx_bytes, rx_cfg->ctrl);
    }

  printf ("SERVER: %s-directional Stream Test Complete!\n"
	  SOCK_TEST_BANNER_STRING "\n",
	  test == SOCK_TEST_TYPE_BI ? "Bi" : "Uni");
}

int
main (int argc, char **argv)
{
  sock_server_main_t *ssm = &sock_server_main;
  int listen_fd, client_fd, rv;
  int tx_bytes, rx_bytes, nbytes;
  sock_test_cfg_t *rx_cfg;
  uint32_t xtra = 0;
  uint64_t xtra_bytes = 0;
  struct sockaddr_in servaddr;
  int errno_val;
  int v;
  uint16_t port = SOCK_TEST_SERVER_PORT;
#ifdef VCL_TEST
  vppcom_endpt_t endpt;
#endif

  if ((argc == 2) && (sscanf (argv[1], "%d", &v) == 1))
    port = (uint16_t) v;

  sock_test_cfg_init (&ssm->cfg);
  sock_test_buf_alloc (&ssm->cfg, 1 /* is_rxbuf */ ,
		       &ssm->buf, &ssm->buf_size);
  ssm->cfg.txbuf_size = ssm->cfg.rxbuf_size;

#ifdef VCL_TEST
  rv = vppcom_app_create ("vcl_test_server");
  if (rv)
    {
      errno = -rv;
      listen_fd = -1;
    }
  else
    {
      listen_fd =
	vppcom_session_create (VPPCOM_VRF_DEFAULT, VPPCOM_PROTO_TCP,
			       0 /* is_nonblocking */ );
    }
#else
  listen_fd = socket (AF_INET, SOCK_STREAM, 0);
#endif
  if (listen_fd < 0)
    {
      errno_val = errno;
      perror ("ERROR in main()");
      fprintf (stderr, "ERROR: socket() failed (errno = %d)!\n", errno_val);
      return listen_fd;
    }

  memset (&servaddr, 0, sizeof (servaddr));

  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htons (INADDR_ANY);
  servaddr.sin_port = htons (port);

#ifdef VCL_TEST
  endpt.vrf = VPPCOM_VRF_DEFAULT;
  endpt.is_ip4 = (servaddr.sin_family == AF_INET);
  endpt.ip = (uint8_t *) & servaddr.sin_addr;
  endpt.port = (uint16_t) servaddr.sin_port;

  rv = vppcom_session_bind (listen_fd, &endpt);
  if (rv)
    {
      errno = -rv;
      rv = -1;
    }
#else
  rv = bind (listen_fd, (struct sockaddr *) &servaddr, sizeof (servaddr));
#endif
  if (rv < 0)
    {
      errno_val = errno;
      perror ("ERROR in main()");
      fprintf (stderr, "ERROR: bind failed (errno = %d)!\n", errno_val);
      return rv;
    }

#ifdef VCL_TEST
  rv = vppcom_session_listen (listen_fd, 10);
  if (rv)
    {
      errno = -rv;
      rv = -1;
    }
#else
  rv = listen (listen_fd, 10);
#endif
  if (rv < 0)
    {
      errno_val = errno;
      perror ("ERROR in main()");
      fprintf (stderr, "ERROR: listen failed (errno = %d)!\n", errno_val);
      return rv;
    }

  do
    {
      printf ("\nSERVER: Waiting for the client to connect on port %d...\n",
	      port);

#ifdef VCL_TEST
      client_fd = vppcom_session_accept (listen_fd, &endpt,
					 -1.0 /* wait forever */ );
#else
      client_fd = accept (listen_fd, (struct sockaddr *) NULL, NULL);
#endif
      if (client_fd < 0)
	{
	  errno_val = errno;
	  perror ("ERROR in main()");
	  fprintf (stderr, "ERROR: accept failed (errno = %d)!\n", errno_val);
	}
    }
  while (client_fd < 0);

  printf ("SERVER: Got a connection -- fd = %d (0x%08x)!\n",
	  client_fd, client_fd);

  while (1)
    {
      rx_bytes = sock_test_read (client_fd, ssm->buf, ssm->buf_size,
				 &ssm->stats);
      if (rx_bytes > 0)
	{
	  rx_cfg = (sock_test_cfg_t *) ssm->buf;
	  if (rx_cfg->ctrl == SOCK_TEST_CFG_CTRL_MAGIC)
	    {
	      if (rx_cfg->verbose)
		{
		  printf ("SERVER: Received a cfg message!\n");
		  sock_test_cfg_dump (rx_cfg, 0 /* is_client */ );
		}

	      switch (rx_cfg->test)
		{
		case SOCK_TEST_TYPE_ECHO:
		  if (rx_bytes == sizeof (*rx_cfg))
		    echo_test_server (rx_cfg);
		  else
		    printf ("SERVER: Invalid cfg message size (%d)!\n"
			    "  Should be %lu bytes.\n",
			    rx_bytes, sizeof (*rx_cfg));
		  break;

		case SOCK_TEST_TYPE_BI:
		case SOCK_TEST_TYPE_UNI:
		  stream_test_server (client_fd, rx_cfg->test, rx_bytes);
		  break;

		case SOCK_TEST_TYPE_EXIT:
		  if (rx_bytes == sizeof (*rx_cfg))
		    {
		      printf ("\nSERVER: Have a great day!\n\n");
#ifdef VCL_TEST
		      vppcom_session_close (client_fd);
#else
		      close (client_fd);
#endif
		      goto done;
		    }
		  else
		    printf ("SERVER: Invalid cfg message size (%d)!\n"
			    "  Should be %lu bytes.\n",
			    rx_bytes, sizeof (*rx_cfg));

		default:
		  fprintf (stderr, "ERROR: Unknown test type!\n");
		  sock_test_cfg_dump (rx_cfg, 0 /* is_client */ );
		  break;
		}
	      continue;
	    }
	  else if (strlen ((char *) ssm->buf))
	    printf ("\nSERVER: RX (%d bytes) - '%s'\n", rx_bytes, ssm->buf);
	}
      else			// rx_bytes < 0
	{
	  if (errno == ECONNRESET)
	    {
	      printf ("\nSERVER: Connection reset by remote peer.\n"
		      "  Y'all have a great day now!\n\n");
	      break;
	    }
	  else
	    continue;
	}

      if (isascii (ssm->buf[0]) && strlen ((const char *) ssm->buf))
	{
	  if (xtra)
	    fprintf (stderr,
		     "ERROR: FIFO not drained during previous test!\n"
		     "       extra chunks %u (0x%x)\n"
		     "        extra bytes %lu (0x%lx)\n",
		     xtra, xtra, xtra_bytes, xtra_bytes);

	  xtra = 0;
	  xtra_bytes = 0;

	  if (ssm->cfg.verbose)
	    printf ("SERVER: Echoing back\n");

	  nbytes = strlen ((const char *) ssm->buf) + 1;

	  tx_bytes = sock_test_write (client_fd, ssm->buf, nbytes,
				      &ssm->stats, ssm->cfg.verbose);
	  if (tx_bytes >= 0)
	    printf ("SERVER: TX (%d bytes) - '%s'\n", tx_bytes, ssm->buf);
	}
      else			// Extraneous read data from non-echo tests???
	{
	  xtra++;
	  xtra_bytes += rx_bytes;
	}
    }

done:
#ifdef VCL_TEST
  vppcom_session_close (listen_fd);
  vppcom_app_destroy ();
#else
  close (listen_fd);
#endif
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
