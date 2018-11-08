/*
 *------------------------------------------------------------------
 * vpp_get_stats.c
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <arpa/inet.h>
#include <sys/epoll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <vpp-api/client/stat_client.h>
#include <vlib/vlib.h>
#include <ctype.h>

/* https://github.com/prometheus/prometheus/wiki/Default-port-allocations */
#define SERVER_PORT 9482

static char *
prom_string (char *s)
{
  char *p = s;
  while (*p)
    {
      if (!isalnum (*p))
	*p = '_';
      p++;
    }
  return s;
}

static void
dump_metrics (FILE * stream, u8 ** patterns)
{
  stat_segment_data_t *res;
  int i, j, k;
  static u32 *stats = 0;

retry:
  res = stat_segment_dump (stats);
  if (res == 0)
    {				/* Memory layout has changed */
      if (stats)
	vec_free (stats);
      stats = stat_segment_ls (patterns);
      goto retry;
    }

  for (i = 0; i < vec_len (res); i++)
    {
      switch (res[i].type)
	{
	case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	  fformat (stream, "# TYPE %s counter\n", prom_string (res[i].name));
	  for (k = 0; k < vec_len (res[i].simple_counter_vec); k++)
	    for (j = 0; j < vec_len (res[i].simple_counter_vec[k]); j++)
	      fformat (stream, "%s{thread=\"%d\",interface=\"%d\"} %lld\n",
		       prom_string (res[i].name), k, j,
		       res[i].simple_counter_vec[k][j]);
	  break;

	case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	  fformat (stream, "# TYPE %s_packets counter\n",
		   prom_string (res[i].name));
	  fformat (stream, "# TYPE %s_bytes counter\n",
		   prom_string (res[i].name));
	  for (k = 0; k < vec_len (res[i].simple_counter_vec); k++)
	    for (j = 0; j < vec_len (res[i].combined_counter_vec[k]); j++)
	      {
		fformat (stream,
			 "%s_packets{thread=\"%d\",interface=\"%d\"} %lld\n",
			 prom_string (res[i].name), k, j,
			 res[i].combined_counter_vec[k][j].packets);
		fformat (stream,
			 "%s_bytes{thread=\"%d\",interface=\"%d\"} %lld\n",
			 prom_string (res[i].name), k, j,
			 res[i].combined_counter_vec[k][j].bytes);
	      }
	  break;
	case STAT_DIR_TYPE_ERROR_INDEX:
	  fformat (stream, "# TYPE %s counter\n", prom_string (res[i].name));
	  fformat (stream, "%s{thread=\"0\"} %lld\n",
		   prom_string (res[i].name), res[i].error_value);
	  break;

	case STAT_DIR_TYPE_SCALAR_INDEX:
	  fformat (stream, "# TYPE %s counter\n", prom_string (res[i].name));
	  fformat (stream, "%s %.2f\n", prom_string (res[i].name),
		   res[i].scalar_value);
	  break;

	default:
	  fformat (stderr, "Unknown value %d\n", res[i].type);
	  ;
	}
    }
  stat_segment_data_free (res);

}


#define ROOTPAGE  "<html><head><title>Metrics exporter</title></head><body><ul><li><a href=\"/metrics\">metrics</a></li></ul></body></html>"
#define NOT_FOUND_ERROR "<html><head><title>Document not found</title></head><body><h1>404 - Document not found</h1></body></html>"

static void
http_handler (FILE * stream, u8 ** patterns)
{
  char status[80] = { 0 };
  if (fgets (status, sizeof (status) - 1, stream) == 0)
    {
      fprintf (stderr, "fgets error: %s %s\n", status, strerror (errno));
      return;
    }
  char *saveptr;
  char *method = strtok_r (status, " \t\r\n", &saveptr);
  if (method == 0 || strncmp (method, "GET", 4) != 0)
    {
      fputs ("HTTP/1.0 405 Method Not Allowed\r\n", stream);
      return;
    }
  char *request_uri = strtok_r (NULL, " \t", &saveptr);
  char *protocol = strtok_r (NULL, " \t\r\n", &saveptr);
  if (protocol == 0 || strncmp (protocol, "HTTP/1.", 7) != 0)
    {
      fputs ("HTTP/1.0 400 Bad Request\r\n", stream);
      return;
    }
  /* Read the other headers */
  for (;;)
    {
      char header[1024];
      if (fgets (header, sizeof (header) - 1, stream) == 0)
	{
	  fprintf (stderr, "fgets error: %s\n", strerror (errno));
	  return;
	}
      if (header[0] == '\n' || header[1] == '\n')
	{
	  break;
	}
    }
  if (strcmp (request_uri, "/") == 0)
    {
      fprintf (stream, "HTTP/1.0 200 OK\r\nContent-Length: %lu\r\n\r\n",
	       (unsigned long) strlen (ROOTPAGE));
      fputs (ROOTPAGE, stream);
      return;
    }
  if (strcmp (request_uri, "/metrics") != 0)
    {
      fprintf (stream,
	       "HTTP/1.0 404 Not Found\r\nContent-Length: %lu\r\n\r\n",
	       (unsigned long) strlen (NOT_FOUND_ERROR));
      fputs (NOT_FOUND_ERROR, stream);
      return;
    }
  fputs ("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n", stream);
  dump_metrics (stream, patterns);
}

static int
start_listen (u16 port)
{
  struct sockaddr_in6 serveraddr;
  int addrlen = sizeof (serveraddr);
  int enable = 1;

  int listenfd = socket (AF_INET6, SOCK_STREAM, 0);
  if (listenfd == -1)
    {
      perror ("Failed opening socket");
      return -1;
    }

  int rv =
    setsockopt (listenfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof (int));
  if (rv < 0)
    {
      perror ("Failed setsockopt");
      close (listenfd);
      return -1;
    }

  memset (&serveraddr, 0, sizeof (serveraddr));
  serveraddr.sin6_family = AF_INET6;
  serveraddr.sin6_port = htons (port);
  serveraddr.sin6_addr = in6addr_any;

  if (bind (listenfd, (struct sockaddr *) &serveraddr, addrlen) < 0)
    {
      fprintf (stderr, "bind() error %s\n", strerror (errno));
      close (listenfd);
      return -1;
    }
  if (listen (listenfd, 1000000) != 0)
    {
      fprintf (stderr, "listen() error for %s\n", strerror (errno));
      close (listenfd);
      return -1;
    }
  return listenfd;
}

/* Socket epoll, linux-specific */
union my_sockaddr
{
  struct sockaddr_storage storage;
  struct sockaddr addr;
  struct sockaddr_in sin_addr;
  struct sockaddr_in6 sin6_addr;
};



int
main (int argc, char **argv)
{
  unformat_input_t _argv, *a = &_argv;
  u8 *stat_segment_name, *pattern = 0, **patterns = 0;
  int rv;

  /* Allocating 32MB heap */
  clib_mem_init (0, 32 << 20);

  unformat_init_command_line (a, argv);

  stat_segment_name = (u8 *) STAT_SEGMENT_SOCKET_FILE;

  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (a, "socket-name %s", &stat_segment_name))
	;
      else if (unformat (a, "%s", &pattern))
	{
	  vec_add1 (patterns, pattern);
	}
      else
	{
	  fformat (stderr,
		   "%s: usage [socket-name <name>] <patterns> ...\n",
		   argv[0]);
	  exit (1);
	}
    }

  if (vec_len (patterns) == 0)
    {
      fformat (stderr,
	       "%s: usage [socket-name <name>] <patterns> ...\n", argv[0]);
      exit (1);
    }

  rv = stat_segment_connect ((char *) stat_segment_name);
  if (rv)
    {
      fformat (stderr, "Couldn't connect to vpp, does %s exist?\n",
	       stat_segment_name);
      exit (1);
    }

  int fd = start_listen (SERVER_PORT);
  if (fd < 0)
    {
      exit (1);
    }
  for (;;)
    {
      int conn_sock = accept (fd, NULL, NULL);
      if (conn_sock < 0)
	{
	  fprintf (stderr, "Accept failed: %s", strerror (errno));
	  continue;
	}
      else
	{
	  struct sockaddr_in6 clientaddr = { 0 };
	  char address[INET6_ADDRSTRLEN];
	  socklen_t addrlen;
	  getpeername (conn_sock, (struct sockaddr *) &clientaddr, &addrlen);
	  if (inet_ntop
	      (AF_INET6, &clientaddr.sin6_addr, address, sizeof (address)))
	    {
	      fprintf (stderr, "Client address is [%s]:%d\n", address,
		       ntohs (clientaddr.sin6_port));
	    }
	}

      FILE *stream = fdopen (conn_sock, "r+");
      if (stream == NULL)
	{
	  fprintf (stderr, "fdopen error: %s\n", strerror (errno));
	  close (conn_sock);
	  continue;
	}
      /* Single reader at the moment */
      http_handler (stream, patterns);
      fclose (stream);
    }

  stat_segment_disconnect ();
  close (fd);

  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
