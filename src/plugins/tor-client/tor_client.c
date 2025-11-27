/*
 * Copyright (c) 2025 Internet Mastering & Company, Inc.
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

/**
 * @file tor_client.c
 * @brief Tor Client plugin main entry point
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <tor_client/tor_client.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

tor_client_main_t tor_client_main;

/**
 * @brief Enable/disable Tor client
 */
clib_error_t *
tor_client_enable_disable(u8 enable, u16 socks_port)
{
  tor_client_main_t *tcm = &tor_client_main;
  clib_error_t *error = 0;

  if (enable == tcm->config.enabled)
    {
      return clib_error_return(0, "Tor client already %s",
                               enable ? "enabled" : "disabled");
    }

  if (enable)
    {
      /* Set default configuration */
      if (!tcm->config.config_dir)
        tcm->config.config_dir = format(0, "/var/lib/vpp/tor%c", 0);

      if (!tcm->config.cache_dir)
        tcm->config.cache_dir = format(0, "/var/cache/vpp/tor%c", 0);

      tcm->config.socks_port = socks_port ? socks_port : 9050;
      tcm->config.max_connections = 1024;

      /* Initialize Arti client */
      vlib_cli_output(tcm->vlib_main, "Initializing Arti Tor client...");
      vlib_cli_output(tcm->vlib_main, "  Config dir: %s", tcm->config.config_dir);
      vlib_cli_output(tcm->vlib_main, "  Cache dir: %s", tcm->config.cache_dir);

      tcm->arti_client = arti_init((char *)tcm->config.config_dir,
                                    (char *)tcm->config.cache_dir);

      if (!tcm->arti_client)
        {
          error = clib_error_return(0, "Failed to initialize Arti client");
          goto done;
        }

      /* Initialize stream pool and hash table */
      pool_init_fixed(tcm->stream_pool, tcm->config.max_connections);
      tcm->stream_by_session = hash_create(0, sizeof(uword));

      tcm->config.enabled = 1;

      /* Start SOCKS5 proxy */
      error = socks5_app_init(tcm->config.socks_port);
      if (error)
        {
          arti_shutdown(tcm->arti_client);
          tcm->arti_client = 0;
          tcm->config.enabled = 0;
          goto done;
        }

      vlib_cli_output(tcm->vlib_main, "Tor client enabled on SOCKS5 port %u",
                      tcm->config.socks_port);
      vlib_cli_output(tcm->vlib_main, "Arti version: %s", arti_version());
    }
  else
    {
      /* Shutdown SOCKS5 proxy */
      socks5_app_shutdown();

      /* Shutdown Arti client */
      if (tcm->arti_client)
        {
          /* Close all active streams */
          tor_stream_t *stream;
          pool_foreach(stream, tcm->stream_pool)
            {
              if (stream->arti_stream)
                arti_close_stream(stream->arti_stream);
            }

          pool_free(tcm->stream_pool);
          hash_free(tcm->stream_by_session);

          arti_shutdown(tcm->arti_client);
          tcm->arti_client = 0;
        }

      tcm->config.enabled = 0;
      tcm->active_streams = 0;
      vlib_cli_output(tcm->vlib_main, "Tor client disabled");
    }

done:
  return error;
}

/**
 * @brief Create a new Tor stream
 */
clib_error_t *
tor_client_stream_create(char *addr, u16 port, u32 *stream_index_out)
{
  tor_client_main_t *tcm = &tor_client_main;
  tor_stream_t *stream;
  void *arti_stream = 0;
  int rv;

  if (!tcm->config.enabled)
    return clib_error_return(0, "Tor client not enabled");

  if (!tcm->arti_client)
    return clib_error_return(0, "Arti client not initialized");

  /* Connect through Tor */
  rv = arti_connect(tcm->arti_client, addr, port, &arti_stream);
  if (rv != 0 || !arti_stream)
    {
      return clib_error_return(0, "Failed to connect to %s:%u (error %d)",
                               addr, port, rv);
    }

  /* Allocate stream from pool */
  pool_get_zero(tcm->stream_pool, stream);
  *stream_index_out = stream - tcm->stream_pool;

  /* Initialize stream */
  stream->arti_stream = arti_stream;
  stream->dst_port = port;
  stream->created_at = vlib_time_now(tcm->vlib_main);

  /* Get event FD from Arti stream for event loop integration */
  stream->event_fd = arti_stream_get_fd(arti_stream);
  stream->file_index = ~0; /* Will be set by SOCKS5 layer */

  tcm->active_streams++;
  tcm->total_connections++;

  return 0;
}

/**
 * @brief Close a Tor stream
 */
void
tor_client_stream_close(u32 stream_index)
{
  tor_client_main_t *tcm = &tor_client_main;
  tor_stream_t *stream;

  if (pool_is_free_index(tcm->stream_pool, stream_index))
    return;

  stream = pool_elt_at_index(tcm->stream_pool, stream_index);

  if (stream->arti_stream)
    {
      arti_close_stream(stream->arti_stream);
      stream->arti_stream = 0;
    }

  /* Update statistics */
  tcm->total_bytes_sent += stream->bytes_sent;
  tcm->total_bytes_received += stream->bytes_received;
  tcm->active_streams--;

  pool_put(tcm->stream_pool, stream);
}

/**
 * @brief Send data on Tor stream
 */
ssize_t
tor_client_stream_send(u32 stream_index, u8 *data, u32 len)
{
  tor_client_main_t *tcm = &tor_client_main;
  tor_stream_t *stream;
  ssize_t rv;

  if (pool_is_free_index(tcm->stream_pool, stream_index))
    return -1;

  stream = pool_elt_at_index(tcm->stream_pool, stream_index);

  if (!stream->arti_stream)
    return -1;

  rv = arti_send(stream->arti_stream, data, len);
  if (rv > 0)
    stream->bytes_sent += rv;

  return rv;
}

/**
 * @brief Receive data from Tor stream
 */
ssize_t
tor_client_stream_recv(u32 stream_index, u8 *buf, u32 len)
{
  tor_client_main_t *tcm = &tor_client_main;
  tor_stream_t *stream;
  ssize_t rv;

  if (pool_is_free_index(tcm->stream_pool, stream_index))
    return -1;

  stream = pool_elt_at_index(tcm->stream_pool, stream_index);

  if (!stream->arti_stream)
    return -1;

  rv = arti_recv(stream->arti_stream, buf, len);
  if (rv > 0)
    stream->bytes_received += rv;

  return rv;
}

/**
 * @brief Format Tor client statistics
 */
u8 *
format_tor_client_stats(u8 *s, va_list *args)
{
  tor_client_main_t *tcm = &tor_client_main;

  s = format(s, "Tor Client Statistics:\n");
  s = format(s, "  Status: %s\n", tcm->config.enabled ? "Enabled" : "Disabled");

  if (tcm->config.enabled)
    {
      s = format(s, "  SOCKS5 Port: %u\n", tcm->config.socks_port);
      s = format(s, "  Active Streams: %u\n", tcm->active_streams);
      s = format(s, "  Total Connections: %llu\n", tcm->total_connections);
      s = format(s, "  Total Bytes Sent: %llu\n", tcm->total_bytes_sent);
      s = format(s, "  Total Bytes Received: %llu\n", tcm->total_bytes_received);
      s = format(s, "  Arti Version: %s\n", arti_version());
    }

  return s;
}

/**
 * @brief Format Tor stream details
 */
u8 *
format_tor_stream(u8 *s, va_list *args)
{
  tor_stream_t *stream = va_arg(*args, tor_stream_t *);
  tor_client_main_t *tcm = &tor_client_main;
  f64 age = vlib_time_now(tcm->vlib_main) - stream->created_at;

  s = format(s, "port %u, age %.1fs, tx %llu, rx %llu",
             stream->dst_port, age, stream->bytes_sent, stream->bytes_received);

  return s;
}

/**
 * @brief Initialize Tor client plugin
 */
static clib_error_t *
tor_client_init(vlib_main_t *vm)
{
  tor_client_main_t *tcm = &tor_client_main;

  clib_memset(tcm, 0, sizeof(*tcm));
  tcm->vlib_main = vm;
  tcm->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION(tor_client_init);

/**
 * @brief Plugin registration
 */
VLIB_PLUGIN_REGISTER() = {
  .version = VPP_BUILD_VER,
  .description = "Arti Tor Client Plugin",
  .default_disabled = 0,
};
