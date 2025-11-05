/*
 * Copyright (c) 2025 AmneziaWG integration for VPP
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

#ifndef __included_wg_awg_h__
#define __included_wg_awg_h__

#include <vppinfra/types.h>
#include <wireguard/wireguard_messages.h>

/* AmneziaWG Configuration - for traffic obfuscation */

/* AWG obfuscation parameters per interface/peer */
typedef struct wg_awg_cfg_t_
{
  /* Enable AWG obfuscation */
  u8 enabled;

  /* Junk packet parameters */
  u32 junk_packet_count;	 /* Number of junk packets to send */
  u32 junk_packet_min_size;	 /* Minimum size of junk packets */
  u32 junk_packet_max_size;	 /* Maximum size of junk packets */

  /* Header junk sizes for different message types */
  u32 init_header_junk_size;	      /* Junk size for initiation messages */
  u32 response_header_junk_size;      /* Junk size for response messages */
  u32 cookie_reply_header_junk_size;  /* Junk size for cookie messages */
  u32 transport_header_junk_size;     /* Junk size for data messages */

  /* Magic headers - custom message type values for obfuscation */
  u32 magic_header[4];	/* Custom message type IDs [init, response, cookie, data] */

} wg_awg_cfg_t;

/* Default AWG configuration values */
#define WG_AWG_DEFAULT_JUNK_COUNT	     0
#define WG_AWG_DEFAULT_JUNK_MIN_SIZE	     0
#define WG_AWG_DEFAULT_JUNK_MAX_SIZE	     0
#define WG_AWG_DEFAULT_INIT_JUNK_SIZE	     0
#define WG_AWG_DEFAULT_RESPONSE_JUNK_SIZE    0
#define WG_AWG_DEFAULT_COOKIE_JUNK_SIZE	     0
#define WG_AWG_DEFAULT_TRANSPORT_JUNK_SIZE   0

/* Default magic headers match standard WireGuard */
#define WG_AWG_DEFAULT_MAGIC_HEADER_INIT     MESSAGE_HANDSHAKE_INITIATION
#define WG_AWG_DEFAULT_MAGIC_HEADER_RESPONSE MESSAGE_HANDSHAKE_RESPONSE
#define WG_AWG_DEFAULT_MAGIC_HEADER_COOKIE   MESSAGE_HANDSHAKE_COOKIE
#define WG_AWG_DEFAULT_MAGIC_HEADER_DATA     MESSAGE_DATA

/* Maximum junk sizes to prevent abuse */
#define WG_AWG_MAX_HEADER_JUNK_SIZE 1024
#define WG_AWG_MAX_JUNK_PACKET_SIZE 1280
#define WG_AWG_MAX_JUNK_PACKET_COUNT 10

/* Initialize AWG configuration with defaults */
static_always_inline void
wg_awg_cfg_init (wg_awg_cfg_t *cfg)
{
  clib_memset (cfg, 0, sizeof (*cfg));
  cfg->enabled = 0;
  cfg->junk_packet_count = WG_AWG_DEFAULT_JUNK_COUNT;
  cfg->junk_packet_min_size = WG_AWG_DEFAULT_JUNK_MIN_SIZE;
  cfg->junk_packet_max_size = WG_AWG_DEFAULT_JUNK_MAX_SIZE;
  cfg->init_header_junk_size = WG_AWG_DEFAULT_INIT_JUNK_SIZE;
  cfg->response_header_junk_size = WG_AWG_DEFAULT_RESPONSE_JUNK_SIZE;
  cfg->cookie_reply_header_junk_size = WG_AWG_DEFAULT_COOKIE_JUNK_SIZE;
  cfg->transport_header_junk_size = WG_AWG_DEFAULT_TRANSPORT_JUNK_SIZE;
  cfg->magic_header[0] = WG_AWG_DEFAULT_MAGIC_HEADER_INIT;
  cfg->magic_header[1] = WG_AWG_DEFAULT_MAGIC_HEADER_RESPONSE;
  cfg->magic_header[2] = WG_AWG_DEFAULT_MAGIC_HEADER_COOKIE;
  cfg->magic_header[3] = WG_AWG_DEFAULT_MAGIC_HEADER_DATA;
}

/* Check if AWG is enabled */
static_always_inline u8
wg_awg_is_enabled (const wg_awg_cfg_t *cfg)
{
  return cfg->enabled;
}

/* Get the actual message type from magic header value */
static_always_inline message_type_t
wg_awg_get_message_type (const wg_awg_cfg_t *cfg, u32 magic_value)
{
  if (!wg_awg_is_enabled (cfg))
    return (message_type_t) magic_value;

  /* Map custom magic header to actual message type */
  if (magic_value == cfg->magic_header[0])
    return MESSAGE_HANDSHAKE_INITIATION;
  if (magic_value == cfg->magic_header[1])
    return MESSAGE_HANDSHAKE_RESPONSE;
  if (magic_value == cfg->magic_header[2])
    return MESSAGE_HANDSHAKE_COOKIE;
  if (magic_value == cfg->magic_header[3])
    return MESSAGE_DATA;

  return MESSAGE_INVALID;
}

/* Get magic header value for a message type */
static_always_inline u32
wg_awg_get_magic_header (const wg_awg_cfg_t *cfg, message_type_t type)
{
  if (!wg_awg_is_enabled (cfg))
    return (u32) type;

  switch (type)
    {
    case MESSAGE_HANDSHAKE_INITIATION:
      return cfg->magic_header[0];
    case MESSAGE_HANDSHAKE_RESPONSE:
      return cfg->magic_header[1];
    case MESSAGE_HANDSHAKE_COOKIE:
      return cfg->magic_header[2];
    case MESSAGE_DATA:
      return cfg->magic_header[3];
    default:
      return (u32) type;
    }
}

/* Get header junk size for a message type */
static_always_inline u32
wg_awg_get_header_junk_size (const wg_awg_cfg_t *cfg, message_type_t type)
{
  if (!wg_awg_is_enabled (cfg))
    return 0;

  switch (type)
    {
    case MESSAGE_HANDSHAKE_INITIATION:
      return cfg->init_header_junk_size;
    case MESSAGE_HANDSHAKE_RESPONSE:
      return cfg->response_header_junk_size;
    case MESSAGE_HANDSHAKE_COOKIE:
      return cfg->cookie_reply_header_junk_size;
    case MESSAGE_DATA:
      return cfg->transport_header_junk_size;
    default:
      return 0;
    }
}

/* Generate random junk data */
void wg_awg_generate_junk (u8 *buffer, u32 size);

/* Create junk packets and send them */
void wg_awg_send_junk_packets (vlib_main_t *vm, const wg_awg_cfg_t *cfg,
			       const u8 *rewrite, u8 is_ip4);

#endif /* __included_wg_awg_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
