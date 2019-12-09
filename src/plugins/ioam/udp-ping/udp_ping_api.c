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
#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>

/* define message IDs */
#include <ioam/udp-ping/udp_ping.api_enum.h>
#include <ioam/udp-ping/udp_ping.api_types.h>

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_udp_ping_add_del_t_handler (vl_api_udp_ping_add_del_t * mp)
{
  ip46_address_t dst, src;
  int rv = 0;
  udp_ping_main_t *sm = &udp_ping_main;
  vl_api_udp_ping_add_del_reply_t *rmp;

  if (clib_net_to_host_u32 (mp->src_ip_address.af) == ADDRESS_IP4)
    {
      rv = -1;			//Not supported
      goto ERROROUT;
    }
  ip_address_decode (&mp->src_ip_address, &src);
  ip_address_decode (&mp->dst_ip_address, &dst);

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

static void
vl_api_udp_ping_export_t_handler (vl_api_udp_ping_export_t * mp)
{
  udp_ping_main_t *sm = &udp_ping_main;
  int rv = 0;
  vl_api_udp_ping_export_reply_t *rmp;

  (void) udp_ping_flow_create (!mp->enable);
  rv = 0;			//FIXME

  REPLY_MACRO (VL_API_UDP_PING_EXPORT_REPLY);
}

#include <ioam/udp-ping/udp_ping.api.c>
static clib_error_t *
udp_ping_api_init (vlib_main_t * vm)
{
  udp_ping_main_t *sm = &udp_ping_main;

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (udp_ping_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
