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

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this module understands */
#define foreach_udp_ping_api_msg                                      \
    _(UDP_PING_ADD_DEL_REQ, udp_ping_add_del_req)                                     \
    _(UDP_PING_EXPORT_REQ, udp_ping_export_req)                                     \

static void vl_api_udp_ping_add_del_req_t_handler
  (vl_api_udp_ping_add_del_req_t * mp)
{
  ip46_address_t dst, src;
  int rv = 0;
  udp_ping_main_t *sm = &udp_ping_main;
  vl_api_udp_ping_add_del_reply_t *rmp;

  if (mp->is_ipv4)
    {
      rv = -1;			//Not supported
      goto ERROROUT;
    }

  clib_memcpy ((void *) &src.ip6, (void *) mp->src_ip_address,
	       sizeof (ip6_address_t));
  clib_memcpy ((void *) &dst.ip6, (void *) mp->dst_ip_address,
	       sizeof (ip6_address_t));

  ip46_udp_ping_set_flow (src, dst,
			  ntohs (mp->start_src_port),
			  ntohs (mp->end_src_port),
			  ntohs (mp->start_dst_port),
			  ntohs (mp->end_dst_port),
			  ntohs (mp->interval), mp->fault_det, mp->dis);
  rv = 0;			//FIXME

ERROROUT:
  REPLY_MACRO (VL_API_UDP_PING_ADD_DEL_REPLY);
}

static void vl_api_udp_ping_export_req_t_handler
  (vl_api_udp_ping_export_req_t * mp)
{
  udp_ping_main_t *sm = &udp_ping_main;
  int rv = 0;
  vl_api_udp_ping_export_reply_t *rmp;

  (void) udp_ping_flow_create (!mp->enable);
  rv = 0;			//FIXME

  REPLY_MACRO (VL_API_UDP_PING_EXPORT_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
udp_ping_api_hookup (vlib_main_t * vm)
{
  udp_ping_main_t *sm = &udp_ping_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                            #n,					\
                            vl_api_##n##_t_handler,              \
                            vl_noop_handler,                     \
                            vl_api_##n##_t_endian,               \
                            vl_api_##n##_t_print,                \
                            sizeof(vl_api_##n##_t), 1);
  foreach_udp_ping_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <ioam/udp-ping/udp_ping_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (udp_ping_main_t * sm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_udp_ping;
#undef _
}

static clib_error_t *
udp_ping_api_init (vlib_main_t * vm)
{
  udp_ping_main_t *sm = &udp_ping_main;
  clib_error_t *error = 0;
  u8 *name;

  name = format (0, "udp_ping_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = udp_ping_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (sm, &api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (udp_ping_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
