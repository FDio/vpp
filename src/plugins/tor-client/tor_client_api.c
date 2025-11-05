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
 * @file tor_client_api.c
 * @brief VPP Binary API message handlers for Tor client
 */

#include <tor_client/tor_client.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* API message handler macro */
#define vl_typedefs
#include <tor_client/tor_client.api.h>
#undef vl_typedefs

#define vl_endianfun
#include <tor_client/tor_client.api.h>
#undef vl_endianfun

#define vl_calcsizefun
#include <tor_client/tor_client.api.h>
#undef vl_calcsizefun

#define vl_printfun
#include <tor_client/tor_client.api.h>
#undef vl_printfun

#define vl_api_version(n, v) static u32 api_version = (v);
#include <tor_client/tor_client.api.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE tcm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/**
 * @brief API message handler for tor_client_enable_disable
 */
static void
vl_api_tor_client_enable_disable_t_handler(vl_api_tor_client_enable_disable_t *mp)
{
  vl_api_tor_client_enable_disable_reply_t *rmp;
  tor_client_main_t *tcm = &tor_client_main;
  int rv = 0;
  clib_error_t *error;

  error = tor_client_enable_disable(mp->enable, ntohs(mp->socks_port));

  if (error)
    {
      rv = -1;
      clib_error_free(error);
    }

  REPLY_MACRO(VL_API_TOR_CLIENT_ENABLE_DISABLE_REPLY);
}

/**
 * @brief API message handler for tor_client_get_stats
 */
static void
vl_api_tor_client_get_stats_t_handler(vl_api_tor_client_get_stats_t *mp)
{
  vl_api_tor_client_get_stats_reply_t *rmp;
  tor_client_main_t *tcm = &tor_client_main;
  int rv = 0;

  REPLY_MACRO2(VL_API_TOR_CLIENT_GET_STATS_REPLY,
  ({
    rmp->enabled = tcm->config.enabled;
    rmp->socks_port = htons(tcm->config.socks_port);
    rmp->active_streams = htonl(tcm->active_streams);
    rmp->total_connections = clib_host_to_net_u64(tcm->total_connections);
    rmp->total_bytes_sent = clib_host_to_net_u64(tcm->total_bytes_sent);
    rmp->total_bytes_received = clib_host_to_net_u64(tcm->total_bytes_received);
  }));
}

/**
 * @brief Set up the API message handlers
 */
#define vl_msg_name_crc_list
#include <tor_client/tor_client.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table(tor_client_main_t *tcm, api_main_t *am)
{
#define _(id, n, crc) \
  vl_msg_api_add_msg_name_crc(am, #n "_" #crc, id + tcm->msg_id_base);
  foreach_vl_msg_name_crc_tor_client;
#undef _
}

/**
 * @brief Plugin API hookup
 */
static clib_error_t *
tor_client_api_hookup(vlib_main_t *vm)
{
  tor_client_main_t *tcm = &tor_client_main;
  api_main_t *am = vlibapi_get_main();
  u8 *name = format(0, "tor_client_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  tcm->msg_id_base = vl_msg_api_get_msg_ids((char *)name,
                                             VL_MSG_FIRST_AVAILABLE);

#define _(N, n)                                                               \
  vl_msg_api_config(&(vl_msg_api_msg_config_t){                              \
    .id = VL_API_##N + tcm->msg_id_base,                                      \
    .name = #n,                                                               \
    .handler = vl_api_##n##_t_handler,                                        \
    .endian = vl_api_##n##_t_endian,                                          \
    .format_fn = vl_api_##n##_t_format,                                       \
    .size = sizeof(vl_api_##n##_t),                                           \
    .traced = 1,                                                              \
    .replay = 1,                                                              \
    .is_autoendian = 0,                                                       \
  });
  foreach_vl_api_msg;
#undef _

  /* Set up the API message name table */
  setup_message_id_table(tcm, am);

  vec_free(name);
  return 0;
}

VLIB_INIT_FUNCTION(tor_client_api_hookup);

#define foreach_vl_api_msg                       \
  _(TOR_CLIENT_ENABLE_DISABLE, tor_client_enable_disable) \
  _(TOR_CLIENT_GET_STATS, tor_client_get_stats)
