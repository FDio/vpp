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
#ifdef __FreeBSD__
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* __FreeBSD__ */
#include <sys/socket.h>
#include <vpp-api/client/stat_client.h>
#include <vlib/vlib.h>
#include <ctype.h>

/* https://github.com/prometheus/prometheus/wiki/Default-port-allocations */
#define SERVER_PORT 9482

#define MAX_TOKENS 10

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
print_metric_v1 (FILE *stream, stat_segment_data_t *res)
{
  int j, k;

  switch (res->type)
    {
    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      fformat (stream, "# TYPE %s counter\n", prom_string (res->name));
      for (k = 0; k < vec_len (res->simple_counter_vec); k++)
	for (j = 0; j < vec_len (res->simple_counter_vec[k]); j++)
	  fformat (stream, "%s{thread=\"%d\",interface=\"%d\"} %lld\n",
		   prom_string (res->name), k, j,
		   res->simple_counter_vec[k][j]);
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      fformat (stream, "# TYPE %s_packets counter\n", prom_string (res->name));
      fformat (stream, "# TYPE %s_bytes counter\n", prom_string (res->name));
      for (k = 0; k < vec_len (res->simple_counter_vec); k++)
	for (j = 0; j < vec_len (res->combined_counter_vec[k]); j++)
	  {
	    fformat (stream,
		     "%s_packets{thread=\"%d\",interface=\"%d\"} %lld\n",
		     prom_string (res->name), k, j,
		     res->combined_counter_vec[k][j].packets);
	    fformat (stream, "%s_bytes{thread=\"%d\",interface=\"%d\"} %lld\n",
		     prom_string (res->name), k, j,
		     res->combined_counter_vec[k][j].bytes);
	  }
      break;
    case STAT_DIR_TYPE_SCALAR_INDEX:
      fformat (stream, "# TYPE %s counter\n", prom_string (res->name));
      fformat (stream, "%s %.2f\n", prom_string (res->name),
	       res->scalar_value);
      break;

    case STAT_DIR_TYPE_NAME_VECTOR:
      fformat (stream, "# TYPE %s_info gauge\n", prom_string (res->name));
      for (k = 0; k < vec_len (res->name_vector); k++)
	if (res->name_vector[k])
	  fformat (stream, "%s_info{index=\"%d\",name=\"%s\"} 1\n",
		   prom_string (res->name), k, res->name_vector[k]);
      break;

    case STAT_DIR_TYPE_EMPTY:
      break;

    default:
      fformat (stderr, "Unknown value %d\n", res->type);
      ;
    }
}

static void
sanitize (char *str, int len)
{
  for (int i = 0; i < len; i++)
    {
      if (!isalnum (str[i]))
	str[i] = '_';
    }
}

static int
tokenize (const char *name, char **tokens, int *lengths, int max_tokens)
{
  char *p = (char *) name;
  char *savep = p;

  int i = 0;
  while (*p && i < max_tokens - 1)
    {
      if (*p == '/')
	{
	  tokens[i] = (char *) savep;
	  lengths[i] = (int) (p - savep);
	  i++;
	  p++;
	  savep = p;
	}
      else
	{
	  p++;
	}
    }
  tokens[i] = (char *) savep;
  lengths[i] = (int) (p - savep);

  i++;
  return i;
}

static void
print_metric_v2 (FILE *stream, stat_segment_data_t *res)
{
  int num_tokens = 0;
  char *tokens[MAX_TOKENS];
  int lengths[MAX_TOKENS];
  int j, k;

  num_tokens = tokenize (res->name, tokens, lengths, MAX_TOKENS);
  switch (res->type)
    {
    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      if (res->simple_counter_vec == 0)
	return;
      for (k = 0; k < vec_len (res->simple_counter_vec); k++)
	for (j = 0; j < vec_len (res->simple_counter_vec[k]); j++)
	  {
	    if ((num_tokens == 4) &&
		(!strncmp (tokens[1], "nodes", lengths[1]) ||
		 !strncmp (tokens[1], "interfaces", lengths[1])))
	      {
		sanitize (tokens[1], lengths[1]);
		sanitize (tokens[3], lengths[3]);
		fformat (
		  stream,
		  "%.*s_%.*s{%.*s=\"%.*s\",index=\"%d\",thread=\"%d\"} %lu\n",
		  lengths[1], tokens[1], lengths[3], tokens[3], lengths[1] - 1,
		  tokens[1], lengths[2], tokens[2], j, k,
		  res->simple_counter_vec[k][j]);
	      }
	    else if ((num_tokens == 3) &&
		     !strncmp (tokens[1], "sys", lengths[1]))
	      {
		sanitize (tokens[1], lengths[1]);
		fformat (stream, "%.*s_%.*s{index=\"%d\",thread=\"%d\"} %lu\n",
			 lengths[1], tokens[1], lengths[2], tokens[2], j, k,
			 res->simple_counter_vec[k][j]);
	      }
	    else if (!strncmp (tokens[1], "mem", lengths[1]))
	      {
		if (num_tokens == 3)
		  {
		    fformat (
		      stream,
		      "%.*s{heap=\"%.*s\",index=\"%d\",thread=\"%d\"} %lu\n",
		      lengths[1], tokens[1], lengths[2], tokens[2], j, k,
		      res->simple_counter_vec[k][j]);
		  }
		else if (num_tokens == 4)
		  {
		    fformat (stream,
			     "%.*s_%.*s{heap=\"%.*s\",index=\"%d\",thread=\"%"
			     "d\"} %lu\n",
			     lengths[1], tokens[1], lengths[3], tokens[3],
			     lengths[2], tokens[2], j, k,
			     res->simple_counter_vec[k][j]);
		  }
		else
		  {
		    print_metric_v1 (stream, res);
		  }
	      }
	    else if (!strncmp (tokens[1], "err", lengths[1]))
	      {
		// NOTE: the error is in token3, but it may contain '/'.
		// Considering this is the last token, it is safe to print
		// token3 until the end of res->name
		fformat (stream,
			 "%.*s{node=\"%.*s\",error=\"%s\",index=\"%d\",thread="
			 "\"%d\"} %lu\n",
			 lengths[1], tokens[1], lengths[2], tokens[2],
			 tokens[3], j, k, res->simple_counter_vec[k][j]);
	      }
	    else
	      {
		print_metric_v1 (stream, res);
	      }
	  }
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      if (res->combined_counter_vec == 0)
	return;
      for (k = 0; k < vec_len (res->combined_counter_vec); k++)
	for (j = 0; j < vec_len (res->combined_counter_vec[k]); j++)
	  {
	    if ((num_tokens == 4) &&
		!strncmp (tokens[1], "interfaces", lengths[1]))
	      {
		sanitize (tokens[1], lengths[1]);
		sanitize (tokens[3], lengths[3]);
		fformat (stream,
			 "%.*s_%.*s_packets{interface=\"%.*s\",index=\"%d\","
			 "thread=\"%d\"} %lu\n",
			 lengths[1], tokens[1], lengths[3], tokens[3],
			 lengths[2], tokens[2], j, k,
			 res->combined_counter_vec[k][j].packets);
		fformat (stream,
			 "%.*s_%.*s_bytes{interface=\"%.*s\",index=\"%d\","
			 "thread=\"%d\"} %lu\n",
			 lengths[1], tokens[1], lengths[3], tokens[3],
			 lengths[2], tokens[2], j, k,
			 res->combined_counter_vec[k][j].bytes);
	      }
	    else
	      {
		print_metric_v1 (stream, res);
	      }
	  }
      break;

    case STAT_DIR_TYPE_SCALAR_INDEX:
      if ((num_tokens == 4) &&
	  !strncmp (tokens[1], "buffer-pools", lengths[1]))
	{
	  sanitize (tokens[1], lengths[1]);
	  sanitize (tokens[3], lengths[3]);
	  fformat (stream, "%.*s_%.*s{pool=\"%.*s\"} %.2f\n", lengths[1],
		   tokens[1], lengths[3], tokens[3], lengths[2], tokens[2],
		   res->scalar_value);
	}
      else if ((num_tokens == 3) && !strncmp (tokens[1], "sys", lengths[1]))
	{
	  sanitize (tokens[1], lengths[1]);
	  sanitize (tokens[2], lengths[2]);
	  fformat (stream, "%.*s_%.*s %.2f\n", lengths[1], tokens[1],
		   lengths[2], tokens[2], res->scalar_value);
	  if (!strncmp (tokens[2], "boottime", lengths[2]))
	    {
	      struct timeval tv;
	      gettimeofday (&tv, NULL);
	      fformat (stream, "sys_uptime %.2f\n",
		       tv.tv_sec - res->scalar_value);
	    }
	}
      else
	{
	  print_metric_v1 (stream, res);
	}
      break;

    default:;
      fformat (stderr, "Unhandled type %d name %s\n", res->type, res->name);
    }
}

static void
dump_metrics (FILE *stream, u8 **patterns, u8 v2)
{
  stat_segment_data_t *res;
  int i;
  static u32 *stats = 0;

retry:
  res = stat_segment_dump (stats);
  if (res == 0)
    { /* Memory layout has changed */
      if (stats)
	vec_free (stats);
      stats = stat_segment_ls (patterns);
      goto retry;
    }

  for (i = 0; i < vec_len (res); i++)
    {
      if (v2)
	print_metric_v2 (stream, &res[i]);
      else
	print_metric_v1 (stream, &res[i]);
    }
  stat_segment_data_free (res);
}


#define ROOTPAGE  "<html><head><title>Metrics exporter</title></head><body><ul><li><a href=\"/metrics\">metrics</a></li></ul></body></html>"
#define NOT_FOUND_ERROR "<html><head><title>Document not found</title></head><body><h1>404 - Document not found</h1></body></html>"

static void
http_handler (FILE *stream, u8 **patterns, u8 v2)
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
  dump_metrics (stream, patterns, v2);
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
  u16 port = SERVER_PORT;
  char *usage =
    "%s: usage [socket-name <name>] [port <0 - 65535>] [v2] <patterns> ...\n";
  int rv;
  u8 v2 = 0;

  /* Allocating 256MB heap */
  clib_mem_init (0, 256 << 20);

  unformat_init_command_line (a, argv);

  stat_segment_name = (u8 *) STAT_SEGMENT_SOCKET_FILE;

  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (a, "socket-name %s", &stat_segment_name))
	;
      if (unformat (a, "v2"))
	v2 = 1;
      else if (unformat (a, "port %d", &port))
	;
      else if (unformat (a, "%s", &pattern))
	{
	  vec_add1 (patterns, pattern);
	}
      else
	{
	  fformat (stderr, usage, argv[0]);
	  exit (1);
	}
    }

  if (vec_len (patterns) == 0)
    {
      fformat (stderr, usage, argv[0]);
      exit (1);
    }

  rv = stat_segment_connect ((char *) stat_segment_name);
  if (rv)
    {
      fformat (stderr, "Couldn't connect to vpp, does %s exist?\n",
	       stat_segment_name);
      exit (1);
    }

  int fd = start_listen (port);
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
      http_handler (stream, patterns, v2);
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
