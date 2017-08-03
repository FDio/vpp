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
#include <uri/sock_test.h>

typedef struct
{
  int fd;
  uint32_t txbuf_size;
  char *txbuf;
  uint32_t rxbuf_size;
  char *rxbuf;
  uint8_t dump_cfg;
  sock_test_cfg_t cfg;
  sock_test_stats_t stats;
} sock_client_main_t;

sock_client_main_t sock_client_main;


static void
echo_test_client (void)
{
  sock_client_main_t *scm = &sock_client_main;
  int rx_bytes, tx_bytes, nbytes;

  memset (&scm->stats, 0, sizeof (scm->stats));
  nbytes = strlen (scm->txbuf) + 1;
  tx_bytes = sock_test_write (scm->fd, (uint8_t *) scm->txbuf, nbytes,
			      &scm->stats, scm->cfg.verbose);
  if (tx_bytes < 0)
    return;

  printf ("\nCLIENT: TX (%d bytes) - '%s'\n", tx_bytes, scm->txbuf);

  rx_bytes = sock_test_read (scm->fd, (uint8_t *) scm->rxbuf, nbytes,
			     &scm->stats);
  if (rx_bytes > 0)
    {
      printf ("CLIENT: RX (%d bytes) - '%s'\n", rx_bytes, scm->rxbuf);
      if (rx_bytes != tx_bytes)
	printf ("WARNING: bytes read (%d) != bytes written (%d)!\n",
		rx_bytes, tx_bytes);
    }

  if (scm->cfg.verbose)
    sock_test_stats_dump ("CLIENT RESULTS", &scm->stats,
			  1 /* show_rx */ , 1 /* show tx */ ,
			  scm->cfg.verbose);
}

static void
stream_test_client (sock_test_t test)
{
  sock_client_main_t *scm = &sock_client_main;
  sock_test_cfg_t *rl_cfg = (sock_test_cfg_t *) scm->rxbuf;
  int rx_bytes, tx_bytes;
  uint32_t i;

  printf ("\n" SOCK_TEST_BANNER_STRING
	  "CLIENT: %s-directional Stream Test!\n"
	  "  Sending config to server...\n",
	  test == SOCK_TEST_TYPE_BI ? "Bi" : "Uni");

  if (scm->cfg.verbose)
    sock_test_cfg_dump (&scm->cfg, 1 /* is_client */ );

  tx_bytes = sock_test_write (scm->fd, (uint8_t *) & scm->cfg,
			      sizeof (scm->cfg), &scm->stats,
			      scm->cfg.verbose);
  if (tx_bytes < 0)
    return;
  rx_bytes = sock_test_read (scm->fd, (uint8_t *) scm->rxbuf,
			     sizeof (sock_test_cfg_t), &scm->stats);
  if (rx_bytes < 0)
    return;
  if (rl_cfg->ctrl != SOCK_TEST_CFG_CTRL_MAGIC)
    {
      fprintf (stderr, "ERROR: Bad server reply cfg -- aborting!\n");
      return;
    }
  printf ("  Got config back from server.\n");
  if (scm->cfg.verbose)
    sock_test_cfg_dump (rl_cfg, 1 /* is_client */ );

  if ((rx_bytes != sizeof (sock_test_cfg_t))
      || !sock_test_cfg_verify (rl_cfg, &scm->cfg))
    {
      fprintf (stderr,
	       "ERROR: Invalid config received from server -- aborting!\n");
      sock_test_cfg_dump (rl_cfg, 1 /* is_client */ );
      return;
    }

  /* Fill payload with incrementing uint32's */
  for (i = 0; i < scm->txbuf_size; i++)
    scm->txbuf[i] = i & 0xff;

  memset (&scm->stats, 0, sizeof (scm->stats));
  clock_gettime (CLOCK_REALTIME, &scm->stats.start);

  while (scm->stats.tx_bytes < scm->cfg.total_bytes)
    {
      tx_bytes = sock_test_write (scm->fd, (uint8_t *) scm->txbuf,
				  scm->txbuf_size, &scm->stats,
				  scm->cfg.verbose);
      if (test == SOCK_TEST_TYPE_BI)
	(void) sock_test_read (scm->fd, (uint8_t *) scm->rxbuf,
			       tx_bytes, &scm->stats);
    }

  while ((test == SOCK_TEST_TYPE_BI) &&
	 scm->stats.rx_bytes < scm->cfg.total_bytes)
    {
      (void) sock_test_read (scm->fd, (uint8_t *) scm->rxbuf,
			     tx_bytes, &scm->stats);
    }

  clock_gettime (CLOCK_REALTIME, &scm->stats.stop);
  sock_test_stats_dump ("CLIENT RESULTS", &scm->stats,
			test == SOCK_TEST_TYPE_BI /* show_rx */ ,
			1 /* show tx */ , scm->cfg.verbose);
  sock_test_cfg_dump (&scm->cfg, 1 /* is_client */ );

  if (scm->cfg.verbose)
    {
      printf ("  sock client main\n"
	      SOCK_TEST_SEPARATOR_STRING
	      "          fd:  %d (0x%08x)\n"
	      "       rxbuf:  %p\n"
	      "  rxbuf size:  %u (0x%08x)\n"
	      "       txbuf:  %p\n"
	      "  txbuf size:  %u (0x%08x)\n"
	      SOCK_TEST_SEPARATOR_STRING,
	      scm->fd, (uint32_t) scm->fd,
	      scm->rxbuf, scm->rxbuf_size, scm->rxbuf_size,
	      scm->txbuf, scm->txbuf_size, scm->txbuf_size);
    }

  // give server time to complete reading test data
  sleep (1);

  scm->cfg.test = SOCK_TEST_TYPE_ECHO;
  if (scm->cfg.verbose)
    {
      printf ("  Sending echo config to server...\n");
      sock_test_cfg_dump (&scm->cfg, 1 /* is_client */ );
    }
  tx_bytes = sock_test_write (scm->fd, (uint8_t *) & scm->cfg,
			      sizeof (scm->cfg), &scm->stats,
			      scm->cfg.verbose);
  if (tx_bytes < 0)
    fprintf (stderr, "ERROR: Test config send to server failed!\n"
	     SOCK_TEST_BANNER_STRING "\n");
  else
    printf ("CLIENT: %s-directional Stream Test Complete!\n"
	    SOCK_TEST_BANNER_STRING "\n",
	    test == SOCK_TEST_TYPE_BI ? "Bi" : "Uni");
}

static void
exit_client (void)
{
  sock_client_main_t *scm = &sock_client_main;

  scm->cfg.test = SOCK_TEST_TYPE_EXIT;
  if (scm->cfg.verbose)
    {
      printf ("  Sending exit cfg to server...\n");
      sock_test_cfg_dump (&scm->cfg, 1 /* is_client */ );
    }
  (void) sock_test_write (scm->fd, (uint8_t *) & scm->cfg,
			  sizeof (scm->cfg), &scm->stats, scm->cfg.verbose);
  printf ("\nCLIENT: So long and thanks for all the fish!\n\n");
}

static void
dump_help (void)
{
#define INDENT "\n  "

  printf ("Test configuration commands:"
	  INDENT SOCK_TEST_TOKEN_HELP
	  "\t\t\tDisplay help."
	  INDENT SOCK_TEST_TOKEN_EXIT
	  "\t\t\tExit test client & server."
	  INDENT SOCK_TEST_TOKEN_SHOW_CFG
	  "\t\t\tShow the current test cfg."
	  INDENT SOCK_TEST_TOKEN_RUN_UNI
	  "\t\t\tRun the Uni-directional test."
	  INDENT SOCK_TEST_TOKEN_RUN_BI
	  "\t\t\tRun the Bi-directional test."
	  INDENT SOCK_TEST_TOKEN_VERBOSE
	  "\t\t\tToggle verbose setting."
	  INDENT SOCK_TEST_TOKEN_RXBUF_SIZE
	  "<rxbuf size>\tRx buffer size (bytes)."
	  INDENT SOCK_TEST_TOKEN_TXBUF_SIZE
	  "<txbuf size>\tTx buffer size (bytes)."
	  INDENT SOCK_TEST_TOKEN_NUM_WRITES
	  "<# of writes>\tNumber of txbuf writes to server." "\n");
}

static void
cfg_txbuf_size_set (void)
{
  sock_client_main_t *scm = &sock_client_main;
  char *p = scm->txbuf + strlen (SOCK_TEST_TOKEN_TXBUF_SIZE);
  uint64_t txbuf_size = strtoull ((const char *) p, NULL, 10);

  if (txbuf_size >= SOCK_TEST_CFG_BUF_SIZE_MIN)
    {
      scm->cfg.txbuf_size = txbuf_size;
      scm->cfg.total_bytes = scm->cfg.num_writes * scm->cfg.txbuf_size;
      sock_test_buf_alloc (&scm->cfg, 0 /* is_rxbuf */ ,
			   (uint8_t **) & scm->txbuf, &scm->txbuf_size);
      sock_test_cfg_dump (&scm->cfg, 1 /* is_client */ );
    }
  else
    fprintf (stderr,
	     "ERROR: Invalid txbuf size (%lu) < minimum buf size (%u)!\n",
	     txbuf_size, SOCK_TEST_CFG_BUF_SIZE_MIN);
}

static void
cfg_num_writes_set (void)
{
  sock_client_main_t *scm = &sock_client_main;
  char *p = scm->txbuf + strlen (SOCK_TEST_TOKEN_NUM_WRITES);
  uint32_t num_writes = strtoul ((const char *) p, NULL, 10);

  if (num_writes >= 0)
    {
      scm->cfg.num_writes = num_writes;
      scm->cfg.total_bytes = scm->cfg.num_writes * scm->cfg.txbuf_size;
      sock_test_cfg_dump (&scm->cfg, 1 /* is_client */ );
    }
  else
    {
      int errno_val = errno;
      perror ("ERROR in cfg_num_writes_set()");
      fprintf (stderr, "ERROR: invalid num chunks (%u) -- errno %d\n",
	       num_writes, errno_val);
    }
}

static void
cfg_rxbuf_size_set (void)
{
  sock_client_main_t *scm = &sock_client_main;
  char *p = scm->txbuf + strlen (SOCK_TEST_TOKEN_RXBUF_SIZE);
  uint64_t rxbuf_size = strtoull ((const char *) p, NULL, 10);

  if (rxbuf_size >= SOCK_TEST_CFG_BUF_SIZE_MIN)
    {
      scm->cfg.rxbuf_size = rxbuf_size;
      sock_test_buf_alloc (&scm->cfg, 1 /* is_rxbuf */ ,
			   (uint8_t **) & scm->rxbuf, &scm->rxbuf_size);
      sock_test_cfg_dump (&scm->cfg, 1 /* is_client */ );
    }
  else
    fprintf (stderr,
	     "ERROR: Invalid rxbuf size (%lu) < minimum buf size (%u)!\n",
	     rxbuf_size, SOCK_TEST_CFG_BUF_SIZE_MIN);
}

static void
cfg_verbose_toggle (void)
{
  sock_client_main_t *scm = &sock_client_main;

  scm->cfg.verbose = scm->cfg.verbose ? 0 : 1;
  sock_test_cfg_dump (&scm->cfg, 1 /* is_client */ );

}

static sock_test_t
parse_input ()
{
  sock_client_main_t *scm = &sock_client_main;
  sock_test_t rv = SOCK_TEST_TYPE_NONE;

  if (!strcmp (SOCK_TEST_TOKEN_EXIT, scm->txbuf))
    rv = SOCK_TEST_TYPE_EXIT;

  else if (!strcmp (SOCK_TEST_TOKEN_HELP, scm->txbuf))
    dump_help ();

  else if (!strcmp (SOCK_TEST_TOKEN_SHOW_CFG, scm->txbuf))
    scm->dump_cfg = 1;

  else if (!strcmp (SOCK_TEST_TOKEN_VERBOSE, scm->txbuf))
    cfg_verbose_toggle ();

  else if (!strncmp (SOCK_TEST_TOKEN_TXBUF_SIZE, scm->txbuf,
		     strlen (SOCK_TEST_TOKEN_TXBUF_SIZE)))
    cfg_txbuf_size_set ();

  else if (!strncmp (SOCK_TEST_TOKEN_NUM_WRITES, scm->txbuf,
		     strlen (SOCK_TEST_TOKEN_NUM_WRITES)))
    cfg_num_writes_set ();

  else if (!strncmp (SOCK_TEST_TOKEN_RXBUF_SIZE, scm->txbuf,
		     strlen (SOCK_TEST_TOKEN_RXBUF_SIZE)))
    cfg_rxbuf_size_set ();

  else if (!strncmp (SOCK_TEST_TOKEN_RUN_UNI, scm->txbuf,
		     strlen (SOCK_TEST_TOKEN_RUN_UNI)))
    rv = scm->cfg.test = SOCK_TEST_TYPE_UNI;

  else if (!strncmp (SOCK_TEST_TOKEN_RUN_BI, scm->txbuf,
		     strlen (SOCK_TEST_TOKEN_RUN_BI)))
    rv = scm->cfg.test = SOCK_TEST_TYPE_BI;

  else
    rv = SOCK_TEST_TYPE_ECHO;

  return rv;
}

void
print_usage_and_exit (void)
{
  fprintf (stderr,
	   "sock_test_client [OPTIONS] <ipaddr> <port>\n"
	   "  OPTIONS\n"
	   "  -h               Print this message and exit.\n"
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
  sock_client_main_t *scm = &sock_client_main;
  int rv, errno_val;
  sock_test_t post_test = SOCK_TEST_TYPE_NONE;
  struct sockaddr_in server_addr;
  int c;
#ifdef VCL_TEST
  vppcom_endpt_t server_endpt;
#endif

  sock_test_cfg_init (&scm->cfg);
  scm->rxbuf_size = scm->cfg.rxbuf_size;
  scm->txbuf_size = scm->cfg.txbuf_size;
  sock_test_buf_alloc (&scm->cfg, 0 /* is_rxbuf */ ,
		       (uint8_t **) & scm->txbuf, &scm->txbuf_size);
  sock_test_buf_alloc (&scm->cfg, 1 /* is_rxbuf */ ,
		       (uint8_t **) & scm->rxbuf, &scm->rxbuf_size);
  opterr = 0;
  while ((c = getopt (argc, argv, "chw:XE:N:R:T:UBV")) != -1)
    switch (c)
      {
      case 'c':
	scm->dump_cfg = 1;
	break;

      case 'w':
	fprintf (stderr, "Writing test results to files is TBD.\n");
	break;

      case 'X':
	post_test = SOCK_TEST_TYPE_EXIT;
	break;

      case 'E':
	if (strlen (optarg) > scm->txbuf_size)
	  {
	    fprintf (stderr,
		     "ERROR: Option -%c value larger than txbuf size (%d)!\n",
		     optopt, scm->txbuf_size);
	    print_usage_and_exit ();
	  }
	strcpy (scm->txbuf, optarg);
	scm->cfg.test = SOCK_TEST_TYPE_ECHO;
	break;

      case 'N':
	if (sscanf (optarg, "0x%lx", &scm->cfg.num_writes) != 1)
	  if (sscanf (optarg, "%ld", &scm->cfg.num_writes) != 1)
	    {
	      fprintf (stderr, "ERROR: Invalid value for option -%c!\n", c);
	      print_usage_and_exit ();
	    }
	scm->cfg.total_bytes = scm->cfg.num_writes * scm->cfg.txbuf_size;
	break;

      case 'R':
	if (sscanf (optarg, "0x%lx", &scm->cfg.rxbuf_size) != 1)
	  if (sscanf (optarg, "%ld", &scm->cfg.rxbuf_size) != 1)
	    {
	      fprintf (stderr, "ERROR: Invalid value for option -%c!\n", c);
	      print_usage_and_exit ();
	    }
	if (scm->cfg.rxbuf_size >= SOCK_TEST_CFG_BUF_SIZE_MIN)
	  {
	    scm->rxbuf_size = scm->cfg.rxbuf_size;
	    sock_test_buf_alloc (&scm->cfg, 1 /* is_rxbuf */ ,
				 (uint8_t **) & scm->rxbuf, &scm->rxbuf_size);
	  }
	else
	  {
	    fprintf (stderr,
		     "ERROR: rxbuf size (%lu) less than minumum (%u)\n",
		     scm->cfg.rxbuf_size, SOCK_TEST_CFG_BUF_SIZE_MIN);
	    print_usage_and_exit ();
	  }

	break;

      case 'T':
	if (sscanf (optarg, "0x%lx", &scm->cfg.txbuf_size) != 1)
	  if (sscanf (optarg, "%ld", &scm->cfg.txbuf_size) != 1)
	    {
	      fprintf (stderr, "ERROR: Invalid value for option -%c!\n", c);
	      print_usage_and_exit ();
	    }
	if (scm->cfg.txbuf_size >= SOCK_TEST_CFG_BUF_SIZE_MIN)
	  {
	    scm->txbuf_size = scm->cfg.txbuf_size;
	    sock_test_buf_alloc (&scm->cfg, 0 /* is_rxbuf */ ,
				 (uint8_t **) & scm->txbuf, &scm->txbuf_size);
	    scm->cfg.total_bytes = scm->cfg.num_writes * scm->cfg.txbuf_size;
	  }
	else
	  {
	    fprintf (stderr,
		     "ERROR: txbuf size (%lu) less than minumum (%u)!\n",
		     scm->cfg.txbuf_size, SOCK_TEST_CFG_BUF_SIZE_MIN);
	    print_usage_and_exit ();
	  }
	break;

      case 'U':
	scm->cfg.test = SOCK_TEST_TYPE_UNI;
	break;

      case 'B':
	scm->cfg.test = SOCK_TEST_TYPE_BI;
	break;

      case 'V':
	scm->cfg.verbose = 1;
	break;

      case '?':
	switch (optopt)
	  {
	  case 'E':
	  case 'N':
	  case 'R':
	  case 'T':
	  case 'w':
	    fprintf (stderr, "ERROR: Option -%c requires an argument.\n",
		     optopt);
	  default:
	    if (isprint (optopt))
	      fprintf (stderr, "ERROR: Unknown option `-%c'.\n", optopt);
	    else
	      fprintf (stderr, "ERROR: Unknown option character `\\x%x'.\n",
		       optopt);
	  }
	/* fall thru */
      case 'h':
      default:
	print_usage_and_exit ();
      }

  if (argc < (optind + 2))
    {
      fprintf (stderr, "ERROR: Insufficient number of arguments!\n");
      print_usage_and_exit ();
    }

#ifdef VCL_TEST
  scm->fd = vppcom_app_create ("vcl_test_client");
  if (scm->fd < 0)
    {
      errno = -scm->fd;
      scm->fd = -1;
    }
  else
    {
      scm->fd = vppcom_session_create (VPPCOM_VRF_DEFAULT, VPPCOM_PROTO_TCP,
				       0 /* is_nonblocking */ );
      if (scm->fd < 0)
	{
	  errno = -scm->fd;
	  scm->fd = -1;
	}
    }
#else
  scm->fd = socket (AF_INET, SOCK_STREAM, 0);
#endif

  if (scm->fd < 0)
    {
      errno_val = errno;
      perror ("ERROR in main()");
      fprintf (stderr, "ERROR: socket failed (errno = %d)!\n", errno_val);
      return scm->fd;
    }

  memset (&server_addr, 0, sizeof server_addr);

  server_addr.sin_family = AF_INET;
  inet_pton (AF_INET, argv[optind++], &(server_addr.sin_addr));
  server_addr.sin_port = htons (atoi (argv[optind]));

#ifdef VCL_TEST
  server_endpt.vrf = VPPCOM_VRF_DEFAULT;
  server_endpt.is_ip4 = (server_addr.sin_family == AF_INET);
  server_endpt.ip = (uint8_t *) & server_addr.sin_addr;
  server_endpt.port = (uint16_t) server_addr.sin_port;
#endif

  do
    {
      printf ("\nCLIENT: Connecting to server...\n");

#ifdef VCL_TEST
      rv = vppcom_session_connect (scm->fd, &server_endpt);
#else
      rv =
	connect (scm->fd, (struct sockaddr *) &server_addr,
		 sizeof (server_addr));
#endif
      if (rv < 0)
	{
	  errno_val = errno;
	  perror ("ERROR in main()");
	  fprintf (stderr, "ERROR: connect failed (errno = %d)!\n",
		   errno_val);
	}
    }
  while (rv < 0);

  printf ("CLIENT: Connected!\n");

  while (scm->cfg.test != SOCK_TEST_TYPE_EXIT)
    {
      if (scm->dump_cfg)
	{
	  sock_test_cfg_dump (&scm->cfg, 1 /* is_client */ );
	  scm->dump_cfg = 0;
	}

      switch (scm->cfg.test)
	{
	case SOCK_TEST_TYPE_ECHO:
	  echo_test_client ();
	  break;

	case SOCK_TEST_TYPE_UNI:
	case SOCK_TEST_TYPE_BI:
	  stream_test_client (scm->cfg.test);
	  break;

	case SOCK_TEST_TYPE_EXIT:
	  continue;

	case SOCK_TEST_TYPE_NONE:
	default:
	  break;
	}
      switch (post_test)
	{
	case SOCK_TEST_TYPE_EXIT:
	  switch (scm->cfg.test)
	    {
	    case SOCK_TEST_TYPE_EXIT:
	    case SOCK_TEST_TYPE_UNI:
	    case SOCK_TEST_TYPE_BI:
	    case SOCK_TEST_TYPE_ECHO:
	      scm->cfg.test = SOCK_TEST_TYPE_EXIT;
	      continue;

	    case SOCK_TEST_TYPE_NONE:
	    default:
	      break;
	    }
	  break;

	case SOCK_TEST_TYPE_NONE:
	case SOCK_TEST_TYPE_ECHO:
	case SOCK_TEST_TYPE_UNI:
	case SOCK_TEST_TYPE_BI:
	default:
	  break;
	}

      memset (scm->txbuf, 0, scm->txbuf_size);
      memset (scm->rxbuf, 0, scm->rxbuf_size);

      printf ("\nType some characters and hit <return>\n"
	      "('" SOCK_TEST_TOKEN_HELP "' for help): ");

      if (fgets (scm->txbuf, scm->txbuf_size, stdin) != NULL)
	{
	  if (strlen (scm->txbuf) == 1)
	    {
	      printf ("\nCLIENT: Nothing to send!  Please try again...\n");
	      continue;
	    }
	  scm->txbuf[strlen (scm->txbuf) - 1] = 0;	// chomp the newline.

	  /* Parse input for keywords */
	  scm->cfg.test = parse_input ();
	}
    }

  exit_client ();
#ifdef VCL_TEST
  vppcom_session_close (scm->fd);
  vppcom_app_destroy ();
#else
  close (scm->fd);
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
