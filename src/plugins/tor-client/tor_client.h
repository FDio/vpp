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
 * @file tor_client.h
 * @brief Arti Tor Client VPP Plugin
 *
 * This plugin integrates the Arti Tor client into VPP, providing
 * SOCKS5 proxy functionality to route traffic through the Tor network.
 */

#ifndef __included_tor_client_h__
#define __included_tor_client_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/plugin/plugin.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>

/* FFI functions from Rust arti-vpp-ffi library */
extern void *arti_init(const char *config_dir, const char *cache_dir);
extern int arti_connect(void *client, const char *addr, uint16_t port, void **stream_out);
extern ssize_t arti_send(void *stream, const uint8_t *data, size_t len);
extern ssize_t arti_recv(void *stream, uint8_t *buf, size_t len);
extern void arti_close_stream(void *stream);
extern void arti_shutdown(void *client);
extern const char *arti_version(void);

/**
 * @brief Tor client configuration
 */
typedef struct
{
  /** Enable/disable flag */
  u8 enabled;

  /** SOCKS5 listen port */
  u16 socks_port;

  /** Configuration directory path */
  u8 *config_dir;

  /** Cache directory path */
  u8 *cache_dir;

  /** Maximum concurrent connections */
  u32 max_connections;

} tor_client_config_t;

/**
 * @brief Tor stream state
 */
typedef struct
{
  /** Stream handle from Arti */
  void *arti_stream;

  /** VPP session index */
  u32 vpp_session_index;

  /** Destination address */
  ip46_address_t dst_addr;

  /** Destination port */
  u16 dst_port;

  /** Creation time */
  f64 created_at;

  /** Bytes sent */
  u64 bytes_sent;

  /** Bytes received */
  u64 bytes_received;

} tor_stream_t;

/**
 * @brief Tor client main structure
 */
typedef struct
{
  /** API message ID base */
  u16 msg_id_base;

  /** VNet main */
  vnet_main_t *vnet_main;

  /** Configuration */
  tor_client_config_t config;

  /** Arti client handle */
  void *arti_client;

  /** Stream pool */
  tor_stream_t *stream_pool;

  /** Stream hash by VPP session index */
  uword *stream_by_session;

  /** Number of active streams */
  u32 active_streams;

  /** Statistics */
  u64 total_connections;
  u64 total_bytes_sent;
  u64 total_bytes_received;

  /** Convenience */
  vlib_main_t *vlib_main;

} tor_client_main_t;

extern tor_client_main_t tor_client_main;

/**
 * @brief Enable/disable Tor client
 */
clib_error_t *tor_client_enable_disable(u8 enable, u16 socks_port);

/**
 * @brief Initialize/shutdown SOCKS5 application
 */
clib_error_t *socks5_app_init(u16 port);
void socks5_app_shutdown(void);

/**
 * @brief Create a new Tor stream
 */
clib_error_t *tor_client_stream_create(char *addr, u16 port, u32 *stream_index_out);

/**
 * @brief Close a Tor stream
 */
void tor_client_stream_close(u32 stream_index);

/**
 * @brief Send data on Tor stream
 */
ssize_t tor_client_stream_send(u32 stream_index, u8 *data, u32 len);

/**
 * @brief Receive data from Tor stream
 */
ssize_t tor_client_stream_recv(u32 stream_index, u8 *buf, u32 len);

/**
 * @brief Format Tor client statistics
 */
u8 *format_tor_client_stats(u8 *s, va_list *args);

/**
 * @brief Format Tor stream details
 */
u8 *format_tor_stream(u8 *s, va_list *args);

/* API support functions */
#define vl_print(handle, ...) vlib_cli_output(handle, __VA_ARGS__)
#define vl_api_version(n, v) static u32 api_version = (v);
#define vl_msg_name_crc_list
#include <tor_client/tor_client.api.h>
#undef vl_msg_name_crc_list

#endif /* __included_tor_client_h__ */
