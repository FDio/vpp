/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
/*
 *------------------------------------------------------------------
 * udp_ping_api.c - UDP Ping related APIs to create
 *             and maintain ping flows
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <ioam/udp-ping/udp_ping.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <ioam/udp-ping/udp_ping_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ioam/udp-ping/udp_ping_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <ioam/udp-ping/udp_ping_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <ioam/udp-ping/udp_ping_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ioam/udp-ping/udp_ping_all_api_h.h>
#undef vl_api_version

/* 
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */

#define REPLY_MACRO(t)                                          \
    do {                                                            \
        unix_shared_memory_queue_t * q =                            \
        vl_api_client_index_to_input_queue (mp->client_index);      \
        if (!q)                                                     \
        return;                                                 \
        \
        rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
        rmp->_vl_msg_id = ntohs((t)+sm->msg_id_base);               \
        rmp->context = mp->context;                                 \
        rmp->retval = ntohl(rv);                                    \
        \
        vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
    } while(0);

#define REPLY_MACRO2(t, body)                                   \
    do {                                                            \
        unix_shared_memory_queue_t * q;                             \
        rv = vl_msg_api_pd_handler (mp, rv);                        \
        q = vl_api_client_index_to_input_queue (mp->client_index);  \
        if (!q)                                                     \
        return;                                                 \
        \
        rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
        rmp->_vl_msg_id = ntohs((t));                               \
        rmp->context = mp->context;                                 \
        rmp->retval = ntohl(rv);                                    \
        do {body;} while (0);                                       \
        vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
    } while(0);

/* List of message types that this plugin understands */

#define foreach_udp_ping_plugin_api_msg                                      \
    _(UDP_PING_ADD, udp_ping_add)                                     \
    _(UDP_PING_DEL, udp_ping_del)                           \
    _(UDP_PING_EXPORT, udp_ping_export)                                     \

static void vl_api_udp_ping_add_t_handler
(vl_api_udp_ping_add_mod_del_req_t *mp)
{
  ip46_address_t dst, src;
  int rv = 0;
  vl_api_udp_ping_add_mod_del_reply_t *rmp;

  if(mp->is_ipv4) {
      rv = -1; //Not supported
      goto ERROROUT;
  }

  src.ip6 = *((ip6_address_t *) mp->src_ip_address);
  dst.ip6 = *((ip6_address_t *) mp->dst_ip_address);

  ip46_udp_ping_set_flow(src, dst, mp->start_src_port, mp->end_src_port,
                         mp->start_dst_port, mp->end_dst_port, mp->interval,
                         0);
  rv = 0;//FIXME

  ERROROUT:
  REPLY_MACRO(VL_API_UDP_PING_ADD_REPLY);
}

static void vl_api_udp_ping_del_t_handler
(vl_api_udp_ping_add_mod_del_req_t *mp)
{
  ip46_address_t dst, src;
  int rv = 0;
  vl_api_udp_ping_add_mod_del_reply_t *rmp;

  if(mp->is_ipv4) {
      rv = -1; //Not supported
      goto ERROROUT;
  }

  src.ip6 = *((ip6_address_t *) mp->src_ip_address);
  dst.ip6 = *((ip6_address_t *) mp->dst_ip_address);

  ip46_udp_ping_set_flow(src, dst, mp->start_src_port, mp->end_src_port,
                         mp->start_dst_port, mp->end_dst_port, mp->interval,
                         1);
  rv = 0;//FIXME

  ERROROUT:
  REPLY_MACRO(VL_API_UDP_PING_DEL_REPLY);
}

static void vl_api_udp_ping_export_t_handler
(vl_api_udp_ping_export_req_t *mp)
{
  ip46_address_t dst, src;
  int rv = 0;
  vl_api_udp_ping_export_reply_t *rmp;

  (void)udp_ping_flow_create(!mp->enable);
  rv = 0;//FIXME

  ERROROUT:
  REPLY_MACRO(VL_API_UDP_PING_EXPORT_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
udp_ping_plugin_api_hookup (vlib_main_t *vm)
{
  udp_ping_main_t *up_main = &udp_ping_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + up_main->msg_id_base),     \
                            #n,					\
                            vl_api_##n##_t_handler,              \
                            vl_noop_handler,                     \
                            vl_api_##n##_t_endian,               \
                            vl_api_##n##_t_print,                \
                            sizeof(vl_api_##n##_t), 1);
  foreach_udp_ping_plugin_api_msg;
#undef _

  return 0;
}

static clib_error_t * udp_ping_api_init (vlib_main_t * vm)
{
  udp_ping_main_t *up_main = &udp_ping_main;
  clib_error_t *error = 0;
  u8 *name;

  name = format (0, "udp_ping_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  up_main->msg_id_base = vl_msg_api_get_msg_ids
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = udp_ping_plugin_api_hookup(vm);

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (udp_ping_api_init);
