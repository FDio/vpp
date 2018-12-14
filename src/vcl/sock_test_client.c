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
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <vcl/sock_test.h>
#include <fcntl.h>
#ifndef VCL_TEST
#include <sys/un.h>
#endif

typedef struct
{
#ifdef VCL_TEST
  vppcom_endpt_t server_endpt;
#else
  int af_unix_echo_tx;
  int af_unix_echo_rx;
#endif
  struct sockaddr_storage server_addr;
  uint32_t server_addr_size;
  uint32_t cfg_seq_num;
  vcl_test_session_t ctrl_socket;
  vcl_test_session_t *test_socket;
  uint32_t num_test_sockets;
  uint8_t dump_cfg;
} sock_client_main_t;

sock_client_main_t vcl_client_main;


static int
sock_test_cfg_sync (vcl_test_session_t * socket)
{
  sock_client_main_t *scm = &vcl_client_main;
  vcl_test_session_t *ctrl = &scm->ctrl_socket;
  vcl_test_cfg_t *rl_cfg = (vcl_test_cfg_t *) socket->rxbuf;
  int rx_bytes, tx_bytes;

  if (socket->cfg.verbose)
    vcl_test_cfg_dump (&socket->cfg, 1 /* is_client */ );

  ctrl->cfg.seq_num = ++scm->cfg_seq_num;
  if (socket->cfg.verbose)
    {
      printf ("CLIENT (fd %d): Sending config sent to server.\n", socket->fd);
      vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );
    }
  tx_bytes = sock_test_write (socket->fd, (uint8_t *) & ctrl->cfg,
			      sizeof (ctrl->cfg), NULL, ctrl->cfg.verbose);
  if (tx_bytes < 0)
    {
      fprintf (stderr, "CLIENT (fd %d): ERROR: write test cfg failed (%d)!\n",
	       socket->fd, tx_bytes);
      return tx_bytes;
    }

  rx_bytes = sock_test_read (socket->fd, (uint8_t *) socket->rxbuf,
			     sizeof (vcl_test_cfg_t), NULL);
  if (rx_bytes < 0)
    return rx_bytes;

  if (rl_cfg->magic != VCL_TEST_CFG_CTRL_MAGIC)
    {
      fprintf (stderr, "CLIENT (fd %d): ERROR: Bad server reply cfg "
	       "-- aborting!\n", socket->fd);
      return -1;
    }
  if ((rx_bytes != sizeof (vcl_test_cfg_t))
      || !vcl_test_cfg_verify (rl_cfg, &ctrl->cfg))
    {
      fprintf (stderr, "CLIENT (fd %d): ERROR: Invalid config received "
	       "from server!\n", socket->fd);
      if (rx_bytes != sizeof (vcl_test_cfg_t))
	{
	  fprintf (stderr, "\tRx bytes %d != cfg size %lu\n",
		   rx_bytes, sizeof (vcl_test_cfg_t));
	}
      else
	{
	  vcl_test_cfg_dump (rl_cfg, 1 /* is_client */ );
	  fprintf (stderr, "CLIENT (fd %d): Valid config sent to server.\n",
		   socket->fd);
	  vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );
	}
      return -1;
    }
  else if (socket->cfg.verbose)
    {
      printf ("CLIENT (fd %d): Got config back from server.\n", socket->fd);
      vcl_test_cfg_dump (rl_cfg, 1 /* is_client */ );
    }
  ctrl->cfg.ctrl_handle = ((ctrl->cfg.ctrl_handle == ~0) ?
			   rl_cfg->ctrl_handle : ctrl->cfg.ctrl_handle);

  return 0;
}

static void
echo_test_client ()
{
  sock_client_main_t *scm = &vcl_client_main;
  vcl_test_session_t *ctrl = &scm->ctrl_socket;
  vcl_test_session_t *tsock;
  int rx_bytes, tx_bytes, nbytes;
  uint32_t i, n;
  int rv;
  int nfds = 0;
  fd_set wr_fdset, rd_fdset;
  fd_set _wfdset, *wfdset = &_wfdset;
  fd_set _rfdset, *rfdset = &_rfdset;

  FD_ZERO (&wr_fdset);
  FD_ZERO (&rd_fdset);
  memset (&ctrl->stats, 0, sizeof (ctrl->stats));
  ctrl->cfg.total_bytes = nbytes = strlen (ctrl->txbuf) + 1;
  for (n = 0; n != ctrl->cfg.num_test_sessions; n++)
    {
      tsock = &scm->test_socket[n];
      tsock->cfg = ctrl->cfg;
      vcl_test_session_buf_alloc (tsock);
      if (sock_test_cfg_sync (tsock))
	return;

      memcpy (tsock->txbuf, ctrl->txbuf, nbytes);
      memset (&tsock->stats, 0, sizeof (tsock->stats));

      FD_SET (tsock->fd, &wr_fdset);
      FD_SET (tsock->fd, &rd_fdset);
      nfds = ((tsock->fd + 1) > nfds) ? (tsock->fd + 1) : nfds;
    }

  nfds++;
  clock_gettime (CLOCK_REALTIME, &ctrl->stats.start);
  while (n)
    {
      _wfdset = wr_fdset;
      _rfdset = rd_fdset;

#ifdef VCL_TEST
      rv =
	vppcom_select (nfds, (unsigned long *) rfdset,
		       (unsigned long *) wfdset, NULL, 0);
#else
      {
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;
	rv = select (nfds, rfdset, wfdset, NULL, &timeout);
      }
#endif
      if (rv < 0)
	{
	  perror ("select()");
	  fprintf (stderr, "\nCLIENT: ERROR: select() failed -- "
		   "aborting test!\n");
	  return;
	}
      else if (rv == 0)
	continue;

      for (i = 0; i < ctrl->cfg.num_test_sessions; i++)
	{
	  tsock = &scm->test_socket[i];
	  if (!((tsock->stats.stop.tv_sec == 0) &&
		(tsock->stats.stop.tv_nsec == 0)))
	    continue;

	  if (FD_ISSET (tsock->fd, wfdset) &&
	      (tsock->stats.tx_bytes < ctrl->cfg.total_bytes))

	    {
	      tx_bytes =
		sock_test_write (tsock->fd, (uint8_t *) tsock->txbuf, nbytes,
				 &tsock->stats, ctrl->cfg.verbose);
	      if (tx_bytes < 0)
		{
		  fprintf (stderr, "\nCLIENT: ERROR: sock_test_write(%d) "
			   "failed -- aborting test!\n", tsock->fd);
		  return;
		}

	      printf ("CLIENT (fd %d): TX (%d bytes) - '%s'\n",
		      tsock->fd, tx_bytes, tsock->txbuf);
	    }

	  if ((FD_ISSET (tsock->fd, rfdset)) &&
	      (tsock->stats.rx_bytes < ctrl->cfg.total_bytes))
	    {
	      rx_bytes =
		sock_test_read (tsock->fd, (uint8_t *) tsock->rxbuf,
				nbytes, &tsock->stats);
	      if (rx_bytes > 0)
		{
		  printf ("CLIENT (fd %d): RX (%d bytes) - '%s'\n",
			  tsock->fd, rx_bytes, tsock->rxbuf);

		  if (tsock->stats.rx_bytes != tsock->stats.tx_bytes)
		    printf ("CLIENT: WARNING: bytes read (%lu) "
			    "!= bytes written (%lu)!\n",
			    tsock->stats.rx_bytes, tsock->stats.tx_bytes);
		}
	    }

	  if (tsock->stats.rx_bytes >= ctrl->cfg.total_bytes)
	    {
	      clock_gettime (CLOCK_REALTIME, &tsock->stats.stop);
	      n--;
	    }
	}
    }
  clock_gettime (CLOCK_REALTIME, &ctrl->stats.stop);

#ifndef VCL_TEST
  {
    int fd, errno_val;
    struct sockaddr_un serveraddr;
    uint8_t buffer[256];
    size_t nbytes = strlen (SOCK_TEST_MIXED_EPOLL_DATA) + 1;
    struct timeval timeout;

    /* Open AF_UNIX socket and send an echo to test mixed epoll on server.
     */
    fd = socket (AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
      {
	errno_val = errno;
	perror ("ERROR in echo_test_client(): socket(AF_UNIX) failed");
	fprintf (stderr,
		 "CLIENT: ERROR: socket(AF_UNIX, SOCK_STREAM, 0) failed "
		 "(errno = %d)!\n", errno_val);
	goto out;
      }
    memset (&serveraddr, 0, sizeof (serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strcpy (serveraddr.sun_path, SOCK_TEST_AF_UNIX_FILENAME);
    rv = connect (fd, (struct sockaddr *) &serveraddr, SUN_LEN (&serveraddr));
    if (rv < 0)
      {
	errno_val = errno;
	perror ("ERROR in echo_test_client(): connect() failed");
	fprintf (stderr, "CLIENT: ERROR: connect(fd %d, \"%s\", %lu) "
		 "failed (errno = %d)!\n", fd, SOCK_TEST_AF_UNIX_FILENAME,
		 SUN_LEN (&serveraddr), errno_val);
	goto done;
      }

    scm->af_unix_echo_tx++;
    strcpy ((char *) buffer, SOCK_TEST_MIXED_EPOLL_DATA);
    timeout.tv_sec = 0;
    timeout.tv_usec = 250000;
    select (0, NULL, NULL, NULL, &timeout);	/* delay .25 secs */
    rv = write (fd, buffer, nbytes);
    if (rv < 0)
      {
	errno_val = errno;
	perror ("ERROR in echo_test_client(): write() failed");
	fprintf (stderr, "CLIENT: ERROR: write(fd %d, \"%s\", %lu) "
		 "failed (errno = %d)!\n", fd, buffer, nbytes, errno_val);
	goto done;
      }
    else if (rv < nbytes)
      {
	fprintf (stderr, "CLIENT: ERROR: write(fd %d, \"%s\", %lu) "
		 "returned %d!\n", fd, buffer, nbytes, rv);
	goto done;
      }

    printf ("CLIENT (AF_UNIX): TX (%d bytes) - '%s'\n", rv, buffer);
    memset (buffer, 0, sizeof (buffer));
    rv = read (fd, buffer, nbytes);
    if (rv < 0)
      {
	errno_val = errno;
	perror ("ERROR in echo_test_client(): read() failed");
	fprintf (stderr, "CLIENT: ERROR: read(fd %d, %p, %lu) "
		 "failed (errno = %d)!\n", fd, buffer, nbytes, errno_val);
	goto done;
      }
    else if (rv < nbytes)
      {
	fprintf (stderr, "CLIENT: ERROR: read(fd %d, %p, %lu) "
		 "returned %d!\n", fd, buffer, nbytes, rv);
	goto done;
      }

    if (!strncmp (SOCK_TEST_MIXED_EPOLL_DATA, (const char *) buffer, nbytes))
      {
	printf ("CLIENT (AF_UNIX): RX (%d bytes) - '%s'\n", rv, buffer);
	scm->af_unix_echo_rx++;
      }
    else
      printf ("CLIENT (AF_UNIX): ERROR: RX (%d bytes) - '%s'\n", rv, buffer);

  done:
    close (fd);
  out:
    ;
  }
#endif

  for (i = 0; i < ctrl->cfg.num_test_sessions; i++)
    {
      tsock = &scm->test_socket[i];
      tsock->stats.start = ctrl->stats.start;

      if (ctrl->cfg.verbose)
	{
	  static char buf[64];

	  sprintf (buf, "CLIENT (fd %d) RESULTS", tsock->fd);
	  vcl_test_stats_dump (buf, &tsock->stats,
			       1 /* show_rx */ , 1 /* show tx */ ,
			       ctrl->cfg.verbose);
	}

      vcl_test_stats_accumulate (&ctrl->stats, &tsock->stats);
    }

  if (ctrl->cfg.verbose)
    {
      vcl_test_stats_dump ("CLIENT RESULTS", &ctrl->stats,
			   1 /* show_rx */ , 1 /* show tx */ ,
			   ctrl->cfg.verbose);
      vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );

      if (ctrl->cfg.verbose > 1)
	{
	  printf ("  ctrl socket info\n"
		  VCL_TEST_SEPARATOR_STRING
		  "          fd:  %d (0x%08x)\n"
		  "       rxbuf:  %p\n"
		  "  rxbuf size:  %u (0x%08x)\n"
		  "       txbuf:  %p\n"
		  "  txbuf size:  %u (0x%08x)\n"
		  VCL_TEST_SEPARATOR_STRING,
		  ctrl->fd, (uint32_t) ctrl->fd,
		  ctrl->rxbuf, ctrl->rxbuf_size, ctrl->rxbuf_size,
		  ctrl->txbuf, ctrl->txbuf_size, ctrl->txbuf_size);
	}
    }
}

static void
stream_test_client (vcl_test_t test)
{
  sock_client_main_t *scm = &vcl_client_main;
  vcl_test_session_t *ctrl = &scm->ctrl_socket;
  vcl_test_session_t *tsock;
  int tx_bytes;
  uint32_t i, n;
  int rv;
  int nfds = 0;
  fd_set wr_fdset, rd_fdset;
  fd_set _wfdset, *wfdset = &_wfdset;
  fd_set _rfdset, *rfdset = (test == VCL_TEST_TYPE_BI) ? &_rfdset : 0;

  ctrl->cfg.total_bytes = ctrl->cfg.num_writes * ctrl->cfg.txbuf_size;
  ctrl->cfg.ctrl_handle = ~0;

  printf ("\n" SOCK_TEST_BANNER_STRING
	  "CLIENT (fd %d): %s-directional Stream Test!\n\n"
	  "CLIENT (fd %d): Sending config to server on ctrl socket...\n",
	  ctrl->fd, test == VCL_TEST_TYPE_BI ? "Bi" : "Uni", ctrl->fd);

  if (sock_test_cfg_sync (ctrl))
    {
      fprintf (stderr, "CLIENT: ERROR: test cfg sync failed -- aborting!");
      return;
    }

  FD_ZERO (&wr_fdset);
  FD_ZERO (&rd_fdset);
  memset (&ctrl->stats, 0, sizeof (ctrl->stats));
  for (n = 0; n != ctrl->cfg.num_test_sessions; n++)
    {
      tsock = &scm->test_socket[n];
      tsock->cfg = ctrl->cfg;
      vcl_test_session_buf_alloc (tsock);
      printf ("CLIENT (fd %d): Sending config to server on "
	      "test socket %d...\n", tsock->fd, n);
      sock_test_cfg_sync (tsock);

      /* Fill payload with incrementing uint32's */
      for (i = 0; i < tsock->txbuf_size; i++)
	tsock->txbuf[i] = i & 0xff;

      memset (&tsock->stats, 0, sizeof (tsock->stats));
      FD_SET (tsock->fd, &wr_fdset);
      FD_SET (tsock->fd, &rd_fdset);
      nfds = ((tsock->fd + 1) > nfds) ? (tsock->fd + 1) : nfds;
    }

  nfds++;
  clock_gettime (CLOCK_REALTIME, &ctrl->stats.start);
  while (n)
    {
      _wfdset = wr_fdset;
      _rfdset = rd_fdset;

#ifdef VCL_TEST
      rv =
	vppcom_select (nfds, (unsigned long *) rfdset,
		       (unsigned long *) wfdset, NULL, 0);
#else
      {
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;
	rv = select (nfds, rfdset, wfdset, NULL, &timeout);
      }
#endif
      if (rv < 0)
	{
	  perror ("select()");
	  fprintf (stderr, "\nCLIENT: ERROR: select() failed -- "
		   "aborting test!\n");
	  return;
	}
      else if (rv == 0)
	continue;

      for (i = 0; i < ctrl->cfg.num_test_sessions; i++)
	{
	  tsock = &scm->test_socket[i];
	  if (!((tsock->stats.stop.tv_sec == 0) &&
		(tsock->stats.stop.tv_nsec == 0)))
	    continue;

	  if ((test == VCL_TEST_TYPE_BI) &&
	      FD_ISSET (tsock->fd, rfdset) &&
	      (tsock->stats.rx_bytes < ctrl->cfg.total_bytes))
	    {
	      (void) sock_test_read (tsock->fd,
				     (uint8_t *) tsock->rxbuf,
				     tsock->rxbuf_size, &tsock->stats);
	    }

	  if (FD_ISSET (tsock->fd, wfdset) &&
	      (tsock->stats.tx_bytes < ctrl->cfg.total_bytes))
	    {
	      tx_bytes = sock_test_write (tsock->fd, (uint8_t *) tsock->txbuf,
					  ctrl->cfg.txbuf_size, &tsock->stats,
					  ctrl->cfg.verbose);
	      if (tx_bytes < 0)
		{
		  fprintf (stderr, "\nCLIENT: ERROR: sock_test_write(%d) "
			   "failed -- aborting test!\n", tsock->fd);
		  return;
		}
	    }

	  if (((test == VCL_TEST_TYPE_UNI) &&
	       (tsock->stats.tx_bytes >= ctrl->cfg.total_bytes)) ||
	      ((test == VCL_TEST_TYPE_BI) &&
	       (tsock->stats.rx_bytes >= ctrl->cfg.total_bytes)))
	    {
	      clock_gettime (CLOCK_REALTIME, &tsock->stats.stop);
	      n--;
	    }
	}
    }
  clock_gettime (CLOCK_REALTIME, &ctrl->stats.stop);

  printf ("CLIENT (fd %d): Sending config to server on ctrl socket...\n",
	  ctrl->fd);

  if (sock_test_cfg_sync (ctrl))
    {
      fprintf (stderr, "CLIENT: ERROR: test cfg sync failed -- aborting!");
      return;
    }

  for (i = 0; i < ctrl->cfg.num_test_sessions; i++)
    {
      tsock = &scm->test_socket[i];

      if (ctrl->cfg.verbose)
	{
	  static char buf[64];

	  sprintf (buf, "CLIENT (fd %d) RESULTS", tsock->fd);
	  vcl_test_stats_dump (buf, &tsock->stats,
			       test == VCL_TEST_TYPE_BI /* show_rx */ ,
			       1 /* show tx */ , ctrl->cfg.verbose);
	}

      vcl_test_stats_accumulate (&ctrl->stats, &tsock->stats);
    }

  vcl_test_stats_dump ("CLIENT RESULTS", &ctrl->stats,
		       test == VCL_TEST_TYPE_BI /* show_rx */ ,
		       1 /* show tx */ , ctrl->cfg.verbose);
  vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );

  if (ctrl->cfg.verbose)
    {
      printf ("  ctrl socket info\n"
	      VCL_TEST_SEPARATOR_STRING
	      "          fd:  %d (0x%08x)\n"
	      "       rxbuf:  %p\n"
	      "  rxbuf size:  %u (0x%08x)\n"
	      "       txbuf:  %p\n"
	      "  txbuf size:  %u (0x%08x)\n"
	      VCL_TEST_SEPARATOR_STRING,
	      ctrl->fd, (uint32_t) ctrl->fd,
	      ctrl->rxbuf, ctrl->rxbuf_size, ctrl->rxbuf_size,
	      ctrl->txbuf, ctrl->txbuf_size, ctrl->txbuf_size);
    }

  ctrl->cfg.test = VCL_TEST_TYPE_ECHO;
  if (sock_test_cfg_sync (ctrl))
    fprintf (stderr, "CLIENT: ERROR: post-test cfg sync failed!");

  printf ("CLIENT (fd %d): %s-directional Stream Test Complete!\n"
	  SOCK_TEST_BANNER_STRING "\n", ctrl->fd,
	  test == VCL_TEST_TYPE_BI ? "Bi" : "Uni");
}

static void
exit_client (void)
{
  sock_client_main_t *scm = &vcl_client_main;
  vcl_test_session_t *ctrl = &scm->ctrl_socket;
  vcl_test_session_t *tsock;
  int i;

#ifndef VCL_TEST
  printf ("CLIENT: af_unix_echo_tx %d, af_unix_echo_rx %d\n",
	  scm->af_unix_echo_tx, scm->af_unix_echo_rx);
#endif
  for (i = 0; i < ctrl->cfg.num_test_sessions; i++)
    {
      tsock = &scm->test_socket[i];
      tsock->cfg.test = VCL_TEST_TYPE_EXIT;

      /* coverity[COPY_PASTE_ERROR] */
      if (ctrl->cfg.verbose)
	{
	  printf ("\nCLIENT (fd %d): Sending exit cfg to server...\n",
		  tsock->fd);
	  vcl_test_cfg_dump (&tsock->cfg, 1 /* is_client */ );
	}
      (void) sock_test_write (tsock->fd, (uint8_t *) & tsock->cfg,
			      sizeof (tsock->cfg), &tsock->stats,
			      ctrl->cfg.verbose);
    }

  ctrl->cfg.test = VCL_TEST_TYPE_EXIT;
  if (ctrl->cfg.verbose)
    {
      printf ("\nCLIENT (fd %d): Sending exit cfg to server...\n", ctrl->fd);
      vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );
    }
  (void) sock_test_write (ctrl->fd, (uint8_t *) & ctrl->cfg,
			  sizeof (ctrl->cfg), &ctrl->stats,
			  ctrl->cfg.verbose);
  printf ("\nCLIENT: So long and thanks for all the fish!\n\n");
  sleep (1);
}

static int
sock_test_connect_test_sockets (uint32_t num_test_sockets)
{
  sock_client_main_t *scm = &vcl_client_main;
  vcl_test_session_t *ctrl = &scm->ctrl_socket;
  vcl_test_session_t *tsock;
  int i, rv, errno_val;

  if (num_test_sockets < 1)
    {
      errno = EINVAL;
      return -1;
    }

  if (num_test_sockets < scm->num_test_sockets)
    {
      for (i = scm->num_test_sockets - 1; i >= num_test_sockets; i--)
	{
	  tsock = &scm->test_socket[i];
#ifdef VCL_TEST
	  vppcom_session_close (tsock->fd);
#else
	  close (tsock->fd);
#endif
	  free (tsock->txbuf);
	  free (tsock->rxbuf);
	}
    }

  else if (num_test_sockets > scm->num_test_sockets)
    {
      tsock = realloc (scm->test_socket,
		       sizeof (vcl_test_session_t) * num_test_sockets);
      if (!tsock)
	{
	  errno_val = errno;
	  perror ("ERROR in sock_test_connect_test_sockets()");
	  fprintf (stderr, "CLIENT: ERROR: socket failed (errno = %d)!\n",
		   errno_val);
	  return -1;
	}

      if (!scm->test_socket)
	memset (tsock, 0, sizeof (*tsock));

      scm->test_socket = tsock;
      for (i = scm->num_test_sockets; i < num_test_sockets; i++)
	{
	  tsock = &scm->test_socket[i];
#ifdef VCL_TEST
	  tsock->fd = vppcom_session_create (ctrl->cfg.transport_udp ?
					     VPPCOM_PROTO_UDP :
					     VPPCOM_PROTO_TCP,
					     1 /* is_nonblocking */ );
	  if (tsock->fd < 0)
	    {
	      errno = -tsock->fd;
	      tsock->fd = -1;
	    }
#else
	  tsock->fd = socket (ctrl->cfg.address_ip6 ? AF_INET6 : AF_INET,
			      ctrl->cfg.transport_udp ?
			      SOCK_DGRAM : SOCK_STREAM, 0);
#endif
	  if (tsock->fd < 0)
	    {
	      errno_val = errno;
	      perror ("ERROR in sock_test_connect_test_sockets()");
	      fprintf (stderr, "CLIENT: ERROR: socket failed (errno = %d)!\n",
		       errno_val);
	      return tsock->fd;
	    }
	  if (fcntl (tsock->fd, F_SETFL, O_NONBLOCK) < 0)
	    {
	      errno_val = errno;
	      perror ("ERROR in sock_test_connect_test_sockets()");
	      fprintf (stderr, "CLIENT: ERROR: fcntl failed (errno = %d)!\n",
		       errno_val);
	      return -1;
	    }

#ifdef VCL_TEST
	  rv = vppcom_session_connect (tsock->fd, &scm->server_endpt);
	  if (rv)
	    {
	      errno = -rv;
	      rv = -1;
	    }
#else
	  rv =
	    connect (tsock->fd, (struct sockaddr *) &scm->server_addr,
		     scm->server_addr_size);
#endif
	  if (rv < 0)
	    {
	      errno_val = errno;
	      perror ("ERROR in sock_test_connect_test_sockets()");
	      fprintf (stderr, "CLIENT: ERROR: connect failed "
		       "(errno = %d)!\n", errno_val);
	      return -1;
	    }
	  tsock->cfg = ctrl->cfg;
	  vcl_test_session_buf_alloc (tsock);
	  sock_test_cfg_sync (tsock);

	  printf ("CLIENT (fd %d): Test socket %d connected.\n",
		  tsock->fd, i);
	}
    }

  scm->num_test_sockets = num_test_sockets;
  printf ("CLIENT: All sockets (%d) connected!\n", scm->num_test_sockets + 1);
  return 0;
}

static void
dump_help (void)
{
#define INDENT "\n  "

  printf ("CLIENT: Test configuration commands:"
	  INDENT VCL_TEST_TOKEN_HELP
	  "\t\t\tDisplay help."
	  INDENT VCL_TEST_TOKEN_EXIT
	  "\t\t\tExit test client & server."
	  INDENT VCL_TEST_TOKEN_SHOW_CFG
	  "\t\t\tShow the current test cfg."
	  INDENT VCL_TEST_TOKEN_RUN_UNI
	  "\t\t\tRun the Uni-directional test."
	  INDENT VCL_TEST_TOKEN_RUN_BI
	  "\t\t\tRun the Bi-directional test."
	  INDENT VCL_TEST_TOKEN_VERBOSE
	  "\t\t\tToggle verbose setting."
	  INDENT VCL_TEST_TOKEN_RXBUF_SIZE
	  "<rxbuf size>\tRx buffer size (bytes)."
	  INDENT VCL_TEST_TOKEN_TXBUF_SIZE
	  "<txbuf size>\tTx buffer size (bytes)."
	  INDENT VCL_TEST_TOKEN_NUM_WRITES
	  "<# of writes>\tNumber of txbuf writes to server." "\n");
}

static void
cfg_txbuf_size_set (void)
{
  sock_client_main_t *scm = &vcl_client_main;
  vcl_test_session_t *ctrl = &scm->ctrl_socket;
  char *p = ctrl->txbuf + strlen (VCL_TEST_TOKEN_TXBUF_SIZE);
  uint64_t txbuf_size = strtoull ((const char *) p, NULL, 10);

  if (txbuf_size >= VCL_TEST_CFG_BUF_SIZE_MIN)
    {
      ctrl->cfg.txbuf_size = txbuf_size;
      ctrl->cfg.total_bytes = ctrl->cfg.num_writes * ctrl->cfg.txbuf_size;
      vcl_test_buf_alloc (&ctrl->cfg, 0 /* is_rxbuf */ ,
			  (uint8_t **) & ctrl->txbuf, &ctrl->txbuf_size);
      vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );
    }
  else
    fprintf (stderr, "CLIENT: ERROR: Invalid txbuf size (%lu) < "
	     "minimum buf size (%u)!\n",
	     txbuf_size, VCL_TEST_CFG_BUF_SIZE_MIN);
}

static void
cfg_num_writes_set (void)
{
  sock_client_main_t *scm = &vcl_client_main;
  vcl_test_session_t *ctrl = &scm->ctrl_socket;
  char *p = ctrl->txbuf + strlen (VCL_TEST_TOKEN_NUM_WRITES);
  uint32_t num_writes = strtoul ((const char *) p, NULL, 10);

  if (num_writes > 0)
    {
      ctrl->cfg.num_writes = num_writes;
      ctrl->cfg.total_bytes = ctrl->cfg.num_writes * ctrl->cfg.txbuf_size;
      vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );
    }
  else
    {
      fprintf (stderr, "CLIENT: ERROR: invalid num writes: %u\n", num_writes);
    }
}

static void
cfg_num_test_sockets_set (void)
{
  sock_client_main_t *scm = &vcl_client_main;
  vcl_test_session_t *ctrl = &scm->ctrl_socket;
  char *p = ctrl->txbuf + strlen (VCL_TEST_TOKEN_NUM_TEST_SESS);
  uint32_t num_test_sockets = strtoul ((const char *) p, NULL, 10);

  if ((num_test_sockets > 0) &&
      (num_test_sockets <= VCL_TEST_CFG_MAX_TEST_SESS))
    {
      ctrl->cfg.num_test_sessions = num_test_sockets;
      sock_test_connect_test_sockets (num_test_sockets);

      vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );
    }
  else
    {
      fprintf (stderr, "CLIENT: ERROR: invalid num test sockets: "
	       "%u, (%d max)\n",
	       num_test_sockets, VCL_TEST_CFG_MAX_TEST_SESS);
    }
}

static void
cfg_rxbuf_size_set (void)
{
  sock_client_main_t *scm = &vcl_client_main;
  vcl_test_session_t *ctrl = &scm->ctrl_socket;
  char *p = ctrl->txbuf + strlen (VCL_TEST_TOKEN_RXBUF_SIZE);
  uint64_t rxbuf_size = strtoull ((const char *) p, NULL, 10);

  if (rxbuf_size >= VCL_TEST_CFG_BUF_SIZE_MIN)
    {
      ctrl->cfg.rxbuf_size = rxbuf_size;
      vcl_test_buf_alloc (&ctrl->cfg, 1 /* is_rxbuf */ ,
			  (uint8_t **) & ctrl->rxbuf, &ctrl->rxbuf_size);
      vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );
    }
  else
    fprintf (stderr, "CLIENT: ERROR: Invalid rxbuf size (%lu) < "
	     "minimum buf size (%u)!\n",
	     rxbuf_size, VCL_TEST_CFG_BUF_SIZE_MIN);
}

static void
cfg_verbose_toggle (void)
{
  sock_client_main_t *scm = &vcl_client_main;
  vcl_test_session_t *ctrl = &scm->ctrl_socket;

  ctrl->cfg.verbose = ctrl->cfg.verbose ? 0 : 1;
  vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );

}

static vcl_test_t
parse_input ()
{
  sock_client_main_t *scm = &vcl_client_main;
  vcl_test_session_t *ctrl = &scm->ctrl_socket;
  vcl_test_t rv = VCL_TEST_TYPE_NONE;

  if (!strncmp (VCL_TEST_TOKEN_EXIT, ctrl->txbuf,
		strlen (VCL_TEST_TOKEN_EXIT)))
    rv = VCL_TEST_TYPE_EXIT;

  else if (!strncmp (VCL_TEST_TOKEN_HELP, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_HELP)))
    dump_help ();

  else if (!strncmp (VCL_TEST_TOKEN_SHOW_CFG, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_SHOW_CFG)))
    scm->dump_cfg = 1;

  else if (!strncmp (VCL_TEST_TOKEN_VERBOSE, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_VERBOSE)))
    cfg_verbose_toggle ();

  else if (!strncmp (VCL_TEST_TOKEN_TXBUF_SIZE, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_TXBUF_SIZE)))
    cfg_txbuf_size_set ();

  else if (!strncmp (VCL_TEST_TOKEN_NUM_TEST_SESS, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_NUM_TEST_SESS)))
    cfg_num_test_sockets_set ();

  else if (!strncmp (VCL_TEST_TOKEN_NUM_WRITES, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_NUM_WRITES)))
    cfg_num_writes_set ();

  else if (!strncmp (VCL_TEST_TOKEN_RXBUF_SIZE, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_RXBUF_SIZE)))
    cfg_rxbuf_size_set ();

  else if (!strncmp (VCL_TEST_TOKEN_RUN_UNI, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_RUN_UNI)))
    rv = ctrl->cfg.test = VCL_TEST_TYPE_UNI;

  else if (!strncmp (VCL_TEST_TOKEN_RUN_BI, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_RUN_BI)))
    rv = ctrl->cfg.test = VCL_TEST_TYPE_BI;

  else
    rv = VCL_TEST_TYPE_ECHO;

  return rv;
}

void
print_usage_and_exit (void)
{
  fprintf (stderr,
	   "sock_test_client [OPTIONS] <ipaddr> <port>\n"
	   "  OPTIONS\n"
	   "  -h               Print this message and exit.\n"
	   "  -6               Use IPv6\n"
	   "  -u               Use UDP transport layer\n"
	   "  -c               Print test config before test.\n"
	   "  -w <dir>         Write test results to <dir>.\n"
	   "  -X               Exit after running test.\n"
	   "  -E               Run Echo test.\n"
	   "  -N <num-writes>  Test Cfg: number of writes.\n"
	   "  -R <rxbuf-size>  Test Cfg: rx buffer size.\n"
	   "  -T <txbuf-size>  Test Cfg: tx buffer size.\n"
	   "  -U               Run Uni-directional test.\n"
	   "  -B               Run Bi-directional test.\n"
	   "  -V               Verbose mode.\n");
  exit (1);
}

int
main (int argc, char **argv)
{
  sock_client_main_t *scm = &vcl_client_main;
  vcl_test_session_t *ctrl = &scm->ctrl_socket;
  int c, rv, errno_val;
  vcl_test_t post_test = VCL_TEST_TYPE_NONE;

  vcl_test_cfg_init (&ctrl->cfg);
  vcl_test_session_buf_alloc (ctrl);

  opterr = 0;
  while ((c = getopt (argc, argv, "chn:w:XE:I:N:R:T:UBV6D")) != -1)
    switch (c)
      {
      case 'c':
	scm->dump_cfg = 1;
	break;

      case 's':
	if (sscanf (optarg, "0x%x", &ctrl->cfg.num_test_sessions) != 1)
	  if (sscanf (optarg, "%u", &ctrl->cfg.num_test_sessions) != 1)
	    {
	      fprintf (stderr, "CLIENT: ERROR: Invalid value for "
		       "option -%c!\n", c);
	      print_usage_and_exit ();
	    }
	if (!ctrl->cfg.num_test_sessions ||
	    (ctrl->cfg.num_test_sessions > FD_SETSIZE))
	  {
	    fprintf (stderr, "CLIENT: ERROR: Invalid number of "
		     "sockets (%d) specified for option -%c!\n"
		     "       Valid range is 1 - %d\n",
		     ctrl->cfg.num_test_sessions, c, FD_SETSIZE);
	    print_usage_and_exit ();
	  }
	break;

      case 'w':
	fprintf (stderr, "CLIENT: Writing test results to files is TBD.\n");
	break;

      case 'X':
	post_test = VCL_TEST_TYPE_EXIT;
	break;

      case 'E':
	if (strlen (optarg) > ctrl->txbuf_size)
	  {
	    fprintf (stderr, "CLIENT: ERROR: Option -%c value "
		     "larger than txbuf size (%d)!\n",
		     optopt, ctrl->txbuf_size);
	    print_usage_and_exit ();
	  }
	strcpy (ctrl->txbuf, optarg);
	ctrl->cfg.test = VCL_TEST_TYPE_ECHO;
	break;

      case 'I':
	if (sscanf (optarg, "0x%x", &ctrl->cfg.num_test_sessions) != 1)
	  if (sscanf (optarg, "%d", &ctrl->cfg.num_test_sessions) != 1)
	    {
	      fprintf (stderr, "CLIENT: ERROR: Invalid value for "
		       "option -%c!\n", c);
	      print_usage_and_exit ();
	    }
	if (ctrl->cfg.num_test_sessions > VCL_TEST_CFG_MAX_TEST_SESS)
	  {
	    fprintf (stderr, "CLIENT: ERROR: value greater than max "
		     "number test sockets (%d)!", VCL_TEST_CFG_MAX_TEST_SESS);
	    print_usage_and_exit ();
	  }
	break;

      case 'N':
	if (sscanf (optarg, "0x%lx", &ctrl->cfg.num_writes) != 1)
	  if (sscanf (optarg, "%ld", &ctrl->cfg.num_writes) != 1)
	    {
	      fprintf (stderr, "CLIENT: ERROR: Invalid value for "
		       "option -%c!\n", c);
	      print_usage_and_exit ();
	    }
	ctrl->cfg.total_bytes = ctrl->cfg.num_writes * ctrl->cfg.txbuf_size;
	break;

      case 'R':
	if (sscanf (optarg, "0x%lx", &ctrl->cfg.rxbuf_size) != 1)
	  if (sscanf (optarg, "%ld", &ctrl->cfg.rxbuf_size) != 1)
	    {
	      fprintf (stderr, "CLIENT: ERROR: Invalid value for "
		       "option -%c!\n", c);
	      print_usage_and_exit ();
	    }
	if (ctrl->cfg.rxbuf_size >= VCL_TEST_CFG_BUF_SIZE_MIN)
	  {
	    ctrl->rxbuf_size = ctrl->cfg.rxbuf_size;
	    vcl_test_buf_alloc (&ctrl->cfg, 1 /* is_rxbuf */ ,
				(uint8_t **) & ctrl->rxbuf,
				&ctrl->rxbuf_size);
	  }
	else
	  {
	    fprintf (stderr, "CLIENT: ERROR: rxbuf size (%lu) "
		     "less than minumum (%u)\n",
		     ctrl->cfg.rxbuf_size, VCL_TEST_CFG_BUF_SIZE_MIN);
	    print_usage_and_exit ();
	  }

	break;

      case 'T':
	if (sscanf (optarg, "0x%lx", &ctrl->cfg.txbuf_size) != 1)
	  if (sscanf (optarg, "%ld", &ctrl->cfg.txbuf_size) != 1)
	    {
	      fprintf (stderr, "CLIENT: ERROR: Invalid value "
		       "for option -%c!\n", c);
	      print_usage_and_exit ();
	    }
	if (ctrl->cfg.txbuf_size >= VCL_TEST_CFG_BUF_SIZE_MIN)
	  {
	    ctrl->txbuf_size = ctrl->cfg.txbuf_size;
	    vcl_test_buf_alloc (&ctrl->cfg, 0 /* is_rxbuf */ ,
				(uint8_t **) & ctrl->txbuf,
				&ctrl->txbuf_size);
	    ctrl->cfg.total_bytes =
	      ctrl->cfg.num_writes * ctrl->cfg.txbuf_size;
	  }
	else
	  {
	    fprintf (stderr, "CLIENT: ERROR: txbuf size (%lu) "
		     "less than minumum (%u)!\n",
		     ctrl->cfg.txbuf_size, VCL_TEST_CFG_BUF_SIZE_MIN);
	    print_usage_and_exit ();
	  }
	break;

      case 'U':
	ctrl->cfg.test = VCL_TEST_TYPE_UNI;
	break;

      case 'B':
	ctrl->cfg.test = VCL_TEST_TYPE_BI;
	break;

      case 'V':
	ctrl->cfg.verbose = 1;
	break;

      case '6':
	ctrl->cfg.address_ip6 = 1;
	break;

      case 'D':
	ctrl->cfg.transport_udp = 1;
	break;

      case '?':
	switch (optopt)
	  {
	  case 'E':
	  case 'I':
	  case 'N':
	  case 'R':
	  case 'T':
	  case 'w':
	    fprintf (stderr, "CLIENT: ERROR: Option -%c "
		     "requires an argument.\n", optopt);
	    break;

	  default:
	    if (isprint (optopt))
	      fprintf (stderr, "CLIENT: ERROR: Unknown "
		       "option `-%c'.\n", optopt);
	    else
	      fprintf (stderr, "CLIENT: ERROR: Unknown "
		       "option character `\\x%x'.\n", optopt);
	  }
	/* fall thru */
      case 'h':
      default:
	print_usage_and_exit ();
      }

  if (argc < (optind + 2))
    {
      fprintf (stderr, "CLIENT: ERROR: Insufficient number of arguments!\n");
      print_usage_and_exit ();
    }

#ifdef VCL_TEST
  ctrl->fd = vppcom_app_create ("vcl_test_client");
  if (ctrl->fd < 0)
    {
      errno = -ctrl->fd;
      ctrl->fd = -1;
    }
  else
    {
      ctrl->fd = vppcom_session_create (ctrl->cfg.transport_udp ?
					VPPCOM_PROTO_UDP :
					VPPCOM_PROTO_TCP,
					0 /* is_nonblocking */ );
      if (ctrl->fd < 0)
	{
	  errno = -ctrl->fd;
	  ctrl->fd = -1;
	}
    }
#else
  ctrl->fd = socket (ctrl->cfg.address_ip6 ? AF_INET6 : AF_INET,
		     ctrl->cfg.transport_udp ? SOCK_DGRAM : SOCK_STREAM, 0);
#endif

  if (ctrl->fd < 0)
    {
      errno_val = errno;
      perror ("ERROR in main()");
      fprintf (stderr, "CLIENT: ERROR: socket "
	       "failed (errno = %d)!\n", errno_val);
      return ctrl->fd;
    }

  memset (&scm->server_addr, 0, sizeof (scm->server_addr));
  if (ctrl->cfg.address_ip6)
    {
      struct sockaddr_in6 *server_addr =
	(struct sockaddr_in6 *) &scm->server_addr;
      scm->server_addr_size = sizeof (*server_addr);
      server_addr->sin6_family = AF_INET6;
      inet_pton (AF_INET6, argv[optind++], &(server_addr->sin6_addr));
      server_addr->sin6_port = htons (atoi (argv[optind]));
    }
  else
    {
      struct sockaddr_in *server_addr =
	(struct sockaddr_in *) &scm->server_addr;
      scm->server_addr_size = sizeof (*server_addr);
      server_addr->sin_family = AF_INET;
      inet_pton (AF_INET, argv[optind++], &(server_addr->sin_addr));
      server_addr->sin_port = htons (atoi (argv[optind]));
    }

#ifdef VCL_TEST
  if (ctrl->cfg.address_ip6)
    {
      struct sockaddr_in6 *server_addr =
	(struct sockaddr_in6 *) &scm->server_addr;
      scm->server_endpt.is_ip4 = 0;
      scm->server_endpt.ip = (uint8_t *) & server_addr->sin6_addr;
      scm->server_endpt.port = (uint16_t) server_addr->sin6_port;
    }
  else
    {
      struct sockaddr_in *server_addr =
	(struct sockaddr_in *) &scm->server_addr;
      scm->server_endpt.is_ip4 = 1;
      scm->server_endpt.ip = (uint8_t *) & server_addr->sin_addr;
      scm->server_endpt.port = (uint16_t) server_addr->sin_port;
    }
#endif

  do
    {
      printf ("\nCLIENT: Connecting to server...\n");

#ifdef VCL_TEST
      rv = vppcom_session_connect (ctrl->fd, &scm->server_endpt);
      if (rv)
	{
	  errno = -rv;
	  rv = -1;
	}
#else
      rv =
	connect (ctrl->fd, (struct sockaddr *) &scm->server_addr,
		 scm->server_addr_size);
#endif
      if (rv < 0)
	{
	  errno_val = errno;
	  perror ("ERROR in main()");
	  fprintf (stderr, "CLIENT: ERROR: connect failed (errno = %d)!\n",
		   errno_val);
	  return -1;
	}

      sock_test_cfg_sync (ctrl);
      printf ("CLIENT (fd %d): Control socket connected.\n", ctrl->fd);
    }
  while (rv < 0);

  sock_test_connect_test_sockets (ctrl->cfg.num_test_sessions);

  while (ctrl->cfg.test != VCL_TEST_TYPE_EXIT)
    {
      if (scm->dump_cfg)
	{
	  vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );
	  scm->dump_cfg = 0;
	}

      switch (ctrl->cfg.test)
	{
	case VCL_TEST_TYPE_ECHO:
	  echo_test_client ();
	  break;

	case VCL_TEST_TYPE_UNI:
	case VCL_TEST_TYPE_BI:
	  stream_test_client (ctrl->cfg.test);
	  break;

	case VCL_TEST_TYPE_EXIT:
	  continue;

	case VCL_TEST_TYPE_NONE:
	default:
	  break;
	}
      switch (post_test)
	{
	case VCL_TEST_TYPE_EXIT:
	  switch (ctrl->cfg.test)
	    {
	    case VCL_TEST_TYPE_EXIT:
	    case VCL_TEST_TYPE_UNI:
	    case VCL_TEST_TYPE_BI:
	    case VCL_TEST_TYPE_ECHO:
	      ctrl->cfg.test = VCL_TEST_TYPE_EXIT;
	      continue;

	    case VCL_TEST_TYPE_NONE:
	    default:
	      break;
	    }
	  break;

	case VCL_TEST_TYPE_NONE:
	case VCL_TEST_TYPE_ECHO:
	case VCL_TEST_TYPE_UNI:
	case VCL_TEST_TYPE_BI:
	default:
	  break;
	}

      memset (ctrl->txbuf, 0, ctrl->txbuf_size);
      memset (ctrl->rxbuf, 0, ctrl->rxbuf_size);

      printf ("\nCLIENT: Type some characters and hit <return>\n"
	      "('" VCL_TEST_TOKEN_HELP "' for help): ");

      if (fgets (ctrl->txbuf, ctrl->txbuf_size, stdin) != NULL)
	{
	  if (strlen (ctrl->txbuf) == 1)
	    {
	      printf ("\nCLIENT: Nothing to send!  Please try again...\n");
	      continue;
	    }
	  ctrl->txbuf[strlen (ctrl->txbuf) - 1] = 0;	// chomp the newline.

	  /* Parse input for keywords */
	  ctrl->cfg.test = parse_input ();
	}
    }

  exit_client ();
#ifdef VCL_TEST
  vppcom_session_close (ctrl->fd);
  vppcom_app_destroy ();
  return 0;
#else
  close (ctrl->fd);
  return (scm->af_unix_echo_tx == scm->af_unix_echo_rx) ? 0 : -1;
#endif
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
