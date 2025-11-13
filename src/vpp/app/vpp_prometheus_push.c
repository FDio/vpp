/*
 *------------------------------------------------------------------
 * vpp_prometheus_push.c
 *
 * Copyright (c) 2025 Lolo Company and/or its affiliates.
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
 *
 * Description:
 *
 * This utility connects to a running VPP instance and retrieves statistics
 * from the shared memory segment. It formats the statistics in Prometheus
 * exposition format and pushes them to a specified Prometheus Pushgateway
 * or compatible endpoint using HTTP POST requests.
 * The utility supports both HTTP and HTTPS protocols, with optional
 * basic authentication.
 *
 * Usage:
 *   vpp_prometheus_push: usage [v2] [username=<name>] [password=<pass>]
 *[interval=<seconds>] [debug=<level>] url=<url> <patterns>
 *
 * Sample usage:
 *  vpp_prometheus_push username=admin password=password
 *url=http://127.0.0.1:3000/api/metrics interfaces vpp_prometheus_push
 *username=admin password=password interval=10 debug=1
 *url=https://127.0.0.1:9091/metrics/job/cgnat-dut interfaces
 *
 * Some of the possible pattern values:
 *   - "interfaces"   - Interface statistics (rx/tx packets/bytes, errors)
 *   - "nodes"        - Node statistics (packet processing counters)
 *   - "sys"          - System statistics (uptime, boottime, etc.)
 *   - "mem"          - Memory statistics (heap usage)
 *   - "err"          - Error statistics (node-specific errors)
 *   - "buffer-pools" - Buffer pool statistics
 *
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
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "dump_metrics.h"

struct Url
{
  char *hostname;
  char *path;
  int port;
  int https; // 0 http, 1 https
  char *ipv4;
};

struct Config
{
  const char *username;
  const char *password;
  struct Url url;
  char *basic_auth;
  int interval; // seconds, 0 means once
  int debug;	// 0 = none
};

// Base64 encode username:password e.g basic auth
char *
base64_encode (const char *username, const char *password)
{
  BIO *bio, *b64;
  FILE *stream;
  size_t combined_len = strlen (username) + strlen (password) + 1;
  char *combined = malloc (combined_len + 1);
  if (!combined)
    return NULL;
  sprintf (combined, "%s:%s", username, password);
  size_t encoded_size =
    4 * ((combined_len + 2) / 3); // Base64 output size calculation
  char *encoded_data = malloc (encoded_size + 1);
  if (!encoded_data)
    {
      free (combined);
      return NULL;
    }

  stream = fmemopen (encoded_data, encoded_size + 1, "w");
  b64 = BIO_new (BIO_f_base64 ());
  bio = BIO_new_fp (stream, BIO_NOCLOSE);
  bio = BIO_push (b64, bio);

  BIO_write (bio, combined, combined_len);
  BIO_flush (bio);
  BIO_free_all (bio);
  fclose (stream);

  encoded_data[encoded_size] = '\0'; // Null terminate
  free (combined);
  return encoded_data;
}

// Parse url like http://localhost:3000/api/metrics to struct Url
int
partUrl (const char *url, struct Url *config)
{
  char *url_copy = strdup (url);
  if (!url_copy)
    {
      return -1;
    }
  char *p = strstr (url_copy, "://");
  if (p == NULL)
    {
      free (url_copy);
      fprintf (stderr, "Invalid URL: %s\n", url);
      return -1;
    }
  if (strncmp (url_copy, "https", 5) == 0)
    {
      config->https = 1;
    }
  else
    {
      config->https = 0;
    }
  p += 3; // move past "://"
  char *path_start = strchr (p, '/');
  if (path_start)
    {
      *path_start = '\0';
      config->path = strdup (path_start + 1);
    }
  else
    {
      config->path = strdup ("/");
    }
  char *port_start = strchr (p, ':');
  if (port_start)
    {
      *port_start = '\0';
      config->hostname = strdup (p);
      config->port = atoi (port_start + 1);
    }
  else
    {
      config->hostname = strdup (p);
      config->port = config->https ? 443 : 80;
    }
  free (url_copy);
  // config.hostname is hostname of ip address to resolve to ipv4
  struct hostent *tmp = gethostbyname (config->hostname);
  if (tmp == NULL)
    {
      fprintf (stderr, "Could not resolve hostname %s\n", config->hostname);
      return -2;
    }
  config->ipv4 = strdup (inet_ntoa (*(struct in_addr *) tmp->h_addr_list[0]));
  return 0;
}

void
handleResponse (const char *buffer, ssize_t bytes_read, struct Config *config,
		int *first)
{
  if (config->debug > 1)
    {
      fprintf (stderr, "Received %zu bytes\n", bytes_read);
    }
  if (*first)
    {
      *first = 0;
      fprintf (stderr, "Response: ");
      for (int i = 0; i < bytes_read; i++)
	{
	  if (buffer[i] == '\r' && buffer[i + 1] == '\n')
	    {
	      break;
	    }
	  fprintf (stderr, "%c", buffer[i]);
	}
      fprintf (stderr, "\n");
    }
  if (config->debug > 0)
    {
      fprintf (stderr, "%s", buffer);
    }
}

int
publish_metrics (struct Config *config, u8 **patterns, u8 v2,
		 stat_client_main_t *shm)
{
  printf ("Pushing metrics\n");
  // Create a memory stream to capture metrics
  char *data = NULL;
  size_t data_size = 0;
  FILE *data_stream = open_memstream (&data, &data_size);
  if (!data_stream)
    {
      fprintf (stderr, "Failed to create memory stream\n");
      return -1;
    }
  // Write metrics to memory stream
  dump_metrics (data_stream, patterns, v2, shm);
  fclose (data_stream);

  char *header = NULL;
  size_t header_size = 0;
  FILE *header_stream = open_memstream (&header, &header_size);
  if (!header_stream)
    {
      fprintf (stderr, "Failed to create memory stream\n");
      free (data);
      return -1;
    }

  // Prepare HTTP headers
  fprintf (header_stream, "POST /%s HTTP/1.1\r\n", config->url.path);
  fprintf (header_stream, "Host: %s:%d\r\n", config->url.hostname,
	   config->url.port);
  fprintf (header_stream, "User-Agent: vpp-prometheus-push\r\n");
  fprintf (header_stream, "Content-Type: text/plain\r\n");
  if (config->basic_auth)
    {
      fprintf (header_stream, "Authorization: Basic %s\r\n",
	       config->basic_auth);
    }
  fprintf (header_stream, "Content-Length: %zu\r\n", data_size);
  fprintf (header_stream, "Connection: close\r\n");
  fprintf (header_stream, "\r\n");
  fclose (header_stream);

  // Open socket and connect
  int sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      fprintf (stderr, "Socket creation failed");
      free (data);
      free (header);
      return -1;
    }

  struct sockaddr_in server_addr;
  memset (&server_addr, 0, sizeof (server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons (config->url.port);
  inet_pton (AF_INET, config->url.ipv4, &server_addr.sin_addr);

  if (connect (sock, (struct sockaddr *) &server_addr, sizeof (server_addr)) <
      0)
    {
      fprintf (stderr, "Connection to %s:%d failed\n", config->url.ipv4,
	       config->url.port);
      close (sock);
      free (data);
      free (header);
      return -1;
    }

  if (config->url.https)
    {
      const SSL_METHOD *method = TLS_client_method ();
      SSL_CTX *ctx = SSL_CTX_new (method);
      if (!ctx)
	{
	  fprintf (stderr, "Unable to create SSL context\n");
	  return -1;
	}
      // Create SSL object
      SSL *ssl = SSL_new (ctx);
      SSL_set_fd (ssl, sock);
      int ret = SSL_connect (ssl);
      if (ret <= 0)
	{
	  int err = SSL_get_error (ssl, ret);
	  const char *err_str = ERR_error_string (err, NULL);
	  fprintf (stderr, "SSL connection failed %d (%s)\n", err, err_str);
	  SSL_free (ssl);
	  SSL_CTX_free (ctx);
	  close (sock);
	  free (data);
	  free (header);
	  return -1;
	}
      if (config->debug > 0)
	{
	  fprintf (stderr, "Sending header %zu\n", header_size);
	  fprintf (stderr, "%s", header);
	}
      SSL_write (ssl, header, header_size);
      if (config->debug > 1)
	{
	  fprintf (stderr, "Sending data %zu\n", data_size);
	  fprintf (stderr, "%s", data);
	}
      SSL_write (ssl, data, data_size);

      free (data);
      free (header);

      // Receive server response
      int first = 1;
      char buffer[4096];
      while (true)
	{
	  int bytes_read = SSL_read (ssl, buffer, sizeof (buffer) - 1);
	  if (bytes_read <= 0)
	    {
	      break;
	    }
	  buffer[bytes_read] = 0;
	  handleResponse (buffer, bytes_read, config, &first);
	}

      // Cleanup
      SSL_shutdown (ssl);
      SSL_free (ssl);
      SSL_CTX_free (ctx);
    }
  else
    {
      if (config->debug > 1)
	{
	  fprintf (stderr, "Sending header %zu\n", header_size);
	  fprintf (stderr, "%s", header);
	}
      if (write (sock, header, header_size) < 0)
	{
	  fprintf (stderr, "Failed to send header\n");
	  free (data);
	  free (header);
	  close (sock);
	  return -1;
	}
      if (config->debug > 1)
	{
	  fprintf (stderr, "Sending data %zu\n", data_size);
	  fprintf (stderr, "%s", data);
	}
      if (write (sock, data, data_size) < 0)
	{
	  fprintf (stderr, "Failed to send data\n");
	  free (data);
	  free (header);
	  close (sock);
	  return -1;
	}
      free (data);
      free (header);
      // Receive server response
      int first = 1;
      char buffer[4096];
      while (true)
	{
	  ssize_t bytes_read = read (sock, buffer, sizeof (buffer) - 1);
	  if (bytes_read <= 0)
	    {
	      break;
	    }
	  buffer[bytes_read] = '\0';
	  handleResponse (buffer, bytes_read, config, &first);
	}
    }
  close (sock);
  return 0;
}

void
freeConfig (struct Config *config)
{
  if (config->basic_auth)
    {
      free (config->basic_auth);
      config->basic_auth = NULL;
    }
  if (config->url.hostname)
    {
      free (config->url.hostname);
      config->url.hostname = NULL;
    }
  if (config->url.path)
    {
      free (config->url.path);
      config->url.path = NULL;
    }
  if (config->url.ipv4)
    {
      free (config->url.ipv4);
      config->url.ipv4 = NULL;
    }
}

int
main (int argc, char **argv)
{
  unformat_input_t _argv, *a = &_argv;
  u8 *stat_segment_name, *pattern = 0, **patterns = 0;
  char *usage = "%s: usage [v2] [username=<name>] [password=<pass>] "
		"[interval=<seconds>] [debug=<level>] url=<url> <patterns> \n";
  int rv;
  u8 v2 = 0;

  SSL_library_init ();
  SSL_load_error_strings ();

  /* Allocating 256MB heap */
  clib_mem_init (0, 256 << 20);

  unformat_init_command_line (a, argv);

  stat_segment_name = (u8 *) STAT_SEGMENT_SOCKET_FILE;
  struct Config config;
  memset (&config, 0, sizeof (config));
  char *url = NULL;
  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (a, "v2"))
	{
	  v2 = 1;
	}
      else if (unformat (a, "username=%s", &config.username))
	{
	  fprintf (stderr, "Username: %s\n", config.username);
	}
      else if (unformat (a, "password=%s", &config.password))
	{
	  fprintf (stderr, "Password: *******\n");
	}
      else if (unformat (a, "url=%s", &url))
	{
	  fprintf (stderr, "URL: %s\n", url); // Optional: add debug output
	}
      else if (unformat (a, "debug=%d", &config.debug))
	{
	  fprintf (stderr, "Debug level: %d\n", config.debug);
	}
      else if (unformat (a, "interval=%d", &config.interval))
	{
	  fprintf (stderr, "Interval: %d seconds\n", config.interval);
	}
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

  if (url == NULL)
    {
      fformat (stderr, "URL is required\n");
      fformat (stderr, usage, argv[0]);
      exit (1);
    }
  if (partUrl (url, &config.url) != 0)
    {
      exit (1);
    }
  if (config.username && config.password)
    {
      config.basic_auth = base64_encode (config.username, config.password);
    }

  do
    {
      stat_client_main_t shm;
      rv = stat_segment_connect_r ((char *) stat_segment_name, &shm);
      if (rv)
	{
	  fformat (stderr, "Couldn't connect to vpp, does %s exist?\n",
		   stat_segment_name);
	}
      else
	{
	  publish_metrics (&config, patterns, v2, &shm);
	  stat_segment_disconnect_r (&shm);
	}
      if (config.interval > 0)
	{
	  sleep (config.interval);
	}
    }
  while (config.interval);
  freeConfig (&config);
  exit (0);
}
