/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

/*
 * vpp_session_stats_export.c
 *
 * Prometheus exporter for SFDP session statistics ring buffer.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vlib/vlib.h>
#include "internal.h"

#define ROOTPAGE                                                                                   \
  "<html><head><title>SFDP Session Stats Exporter</title></head>"                                  \
  "<body><h1>SFDP Session Statistics Prometheus Exporter</h1>"                                     \
  "<ul><li><a href=\"/metrics\">metrics</a></li></ul></body></html>"

#define NOT_FOUND_ERROR                                                                            \
  "<html><head><title>Document not found</title></head>"                                           \
  "<body><h1>404 - Document not found</h1></body></html>"

session_exporter_main_t exporter_main;

static void
http_handler (FILE *stream, u8 *stats_segment_name)
{
  /* Parse request line: "<METHOD> <URI> <HTTP/VERSION>".
   * This handler serves exactly one request per accepted socket. */
  /* Only /metrics is a valid scrape endpoint. */
  char status[80] = { 0 };
  if (fgets (status, sizeof (status) - 1, stream) == 0)
    {
      fprintf (stderr, "fgets error: %s %s\n", status, strerror (errno));
      return;
    }

  char *saveptr;
  char *method = strtok_r (status, " \t\r\n", &saveptr);
  /* only GET request method is supported. */
  if (method == 0 || strncmp (method, "GET", 4) != 0)
    {
      fputs ("HTTP/1.0 405 Method Not Allowed\r\n", stream);
      return;
    }

  char *request_uri = strtok_r (NULL, " \t", &saveptr);
  char *protocol = strtok_r (NULL, " \t\r\n", &saveptr);
  /* enforce HTTP/1.x request format */
  if (protocol == 0 || strncmp (protocol, "HTTP/1.", 7) != 0)
    {
      fputs ("HTTP/1.0 400 Bad Request\r\n", stream);
      return;
    }

  /* Consume HTTP headers */
  for (;;)
    {
      char header[1024];
      if (fgets (header, sizeof (header) - 1, stream) == 0)
	{
	  fprintf (stderr, "fgets error: %s\n", strerror (errno));
	  return;
	}
      if (header[0] == '\n' || header[1] == '\n')
	break;
    }

  /* in case root endpoint is contacted, send reply with simple HTML page pointing to /metrics
   * endpoint */
  if (strcmp (request_uri, "/") == 0)
    {
      fprintf (stream, "HTTP/1.0 200 OK\r\nContent-Length: %lu\r\n\r\n",
	       (unsigned long) strlen (ROOTPAGE));
      fputs (ROOTPAGE, stream);
      return;
    }

  /* check if endpoint matches /metrics */
  if (strcmp (request_uri, "/metrics") != 0)
    {
      fprintf (stream, "HTTP/1.0 404 Not Found\r\nContent-Length: %lu\r\n\r\n",
	       (unsigned long) strlen (NOT_FOUND_ERROR));
      fputs (NOT_FOUND_ERROR, stream);
      return;
    }

  /* Begin scrape response body in Prometheus text format. */
  fputs ("HTTP/1.0 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n", stream);

  /* Fetch current data by connecting to the VPP stats segment per request. */
  stat_client_main_t shm;
  int rv = stat_segment_connect_r ((char *) stats_segment_name, &shm);
  if (rv)
    {
      fprintf (stream, "# ERROR: Couldn't connect to VPP stats segment\n");
      fprintf (stream, "# Check that VPP is running and %s exists\n", stats_segment_name);
      return;
    }

  /* Render metrics and release the stats segment handle. */
  dump_session_metrics (stream, &shm);
  stat_segment_disconnect_r (&shm);
}

static int
start_listen (u16 port)
{
  /* Initialize socket and bind on desired port */
  struct sockaddr_in6 serveraddr;
  int addrlen = sizeof (serveraddr);
  int enable = 1;

  int listenfd = socket (AF_INET6, SOCK_STREAM, 0);
  if (listenfd == -1)
    {
      perror ("Failed opening socket");
      return -1;
    }

  int rv = setsockopt (listenfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof (int));
  if (rv < 0)
    {
      perror ("Failed setsockopt");
      close (listenfd);
      return -1;
    }

  clib_memset (&serveraddr, 0, sizeof (serveraddr));
  serveraddr.sin6_family = AF_INET6;
  serveraddr.sin6_port = htons (port);
  serveraddr.sin6_addr = in6addr_any;

  if (bind (listenfd, (struct sockaddr *) &serveraddr, addrlen) < 0)
    {
      fprintf (stderr, "bind() error %s\n", strerror (errno));
      close (listenfd);
      return -1;
    }

  if (listen (listenfd, SOMAXCONN) != 0)
    {
      fprintf (stderr, "listen() error for %s\n", strerror (errno));
      close (listenfd);
      return -1;
    }

  return listenfd;
}

int
main (int argc, char **argv)
{
  unformat_input_t _argv, *a = &_argv;
  u8 *stat_segment_name;
  u16 port = SERVER_PORT;
  int rv;
  f64 session_timeout = 300.0;

  char *usage = "%s: usage [socket-name <name>] [port <0-65535>] "
		"[session-timeout <seconds>] [instance <name>] "
		"[opaque-label <name>]\n";

  clib_mem_init (0, 256 << 20);
  unformat_init_command_line (a, argv);

  stat_segment_name = (u8 *) STAT_SEGMENT_SOCKET_FILE;

  session_exporter_main_t *em = &exporter_main;
  em->sessions = 0;
  em->session_index_by_id = hash_create (0, sizeof (uword));
  em->thread_states = 0;
  em->instance = 0;
  em->opaque_label = 0;
  em->session_silence_timeout = session_timeout;

  /* initialize empty schema */
  schema_reset (&em->schema);

  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (a, "socket-name %s", &stat_segment_name))
	;
      else if (unformat (a, "port %d", &port))
	;
      else if (unformat (a, "session-timeout %f", &session_timeout))
	em->session_silence_timeout = session_timeout;
      else if (unformat (a, "instance %s", &em->instance))
	;
      else if (unformat (a, "opaque-label %s", &em->opaque_label))
	;
      else if (unformat (a, "help"))
	{
	  fformat (stderr, usage, argv[0]);
	  fformat (stderr, "\nOptions:\n");
	  fformat (stderr,
		   "  socket-name <name>  VPP stats socket path "
		   "(default: %s)\n",
		   STAT_SEGMENT_SOCKET_FILE);
	  fformat (stderr,
		   "  port <0-65535>      HTTP server port "
		   "(default: %d)\n",
		   SERVER_PORT);
	  fformat (stderr, "  session-timeout <s> Stop emitting stale sessions after inactivity "
			   "(default: 300s)\n");
	  fformat (stderr, "  instance <name>      Instance name for metrics "
			   "(optional)\n");
	  fformat (stderr,
		   "  opaque-label <name>  Label name for opaque session field "
		   "(default: %s)\n",
		   OPAQUE_LABEL_DEFAULT_NAME);
	  exit (0);
	}
      else
	{
	  fformat (stderr, usage, argv[0]);
	  exit (1);
	}
    }

  stat_client_main_t shm;
  rv = stat_segment_connect_r ((char *) stat_segment_name, &shm);
  if (rv)
    {
      fformat (stderr, "Couldn't connect to VPP, does %s exist?\n", stat_segment_name);
      exit (1);
    }
  stat_segment_disconnect_r (&shm);

  fprintf (stderr, "SFDP Session Stats Prometheus Exporter starting...\n");
  fprintf (stderr, "  Stats socket: %s\n", stat_segment_name);
  fprintf (stderr, "  HTTP port: %d\n", port);
  fprintf (stderr, "  Session timeout: %.0f seconds (stale entries are kept in cache)\n",
	   em->session_silence_timeout);
  if (em->instance)
    fprintf (stderr, "  Instance: %s\n", em->instance);
  if (em->opaque_label)
    fprintf (stderr, "  Opaque label: %s\n", em->opaque_label);
  else
    fprintf (stderr, "  Opaque label: %s\n", OPAQUE_LABEL_DEFAULT_NAME);
  fprintf (stderr, "  Metrics URL: http://localhost:%d/metrics\n", port);

  int fd = start_listen (port);
  if (fd < 0)
    exit (1);

  for (;;)
    {
      /* await connecton request */
      int conn_sock = accept (fd, NULL, NULL);
      if (conn_sock < 0)
	{
	  fprintf (stderr, "Accept failed: %s\n", strerror (errno));
	  continue;
	}
      else
	{
	  struct sockaddr_in6 clientaddr = { 0 };
	  char address[INET6_ADDRSTRLEN];
	  clib_memset (address, 0, sizeof (address));
	  socklen_t addrlen = sizeof (clientaddr);
	  getpeername (conn_sock, (struct sockaddr *) &clientaddr, &addrlen);

	  /* output client information to stderr*/
	  if (inet_ntop (AF_INET6, &clientaddr.sin6_addr, address, sizeof (address)))
	    fprintf (stderr, "Client: [%s]:%d\n", address, ntohs (clientaddr.sin6_port));
	}

      FILE *stream = fdopen (conn_sock, "r+");
      if (stream == NULL)
	{
	  fprintf (stderr, "fdopen error: %s\n", strerror (errno));
	  close (conn_sock);
	  continue;
	}

      http_handler (stream, stat_segment_name);
      fclose (stream);
    }

  vec_free (em->sessions);
  vec_free (em->thread_states);
  hash_free (em->session_index_by_id);
  vec_free (em->instance);
  vec_free (em->opaque_label);
  close (fd);

  exit (0);
}
