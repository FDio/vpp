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
 * udp_ping_test.c - test harness for udp ping plugin
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/error.h>
#include <vnet/ip/ip.h>
#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>

#define __plugin_msg_base udp_ping_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <ioam/udp-ping/udp_ping.api_enum.h>
#include <ioam/udp-ping/udp_ping.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} udp_ping_test_main_t;

udp_ping_test_main_t udp_ping_test_main;

static int
api_udp_ping_add_del (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_udp_ping_add_del_t *mp;
  int rv = 0;
  ip46_address_t dst, src;
  u32 start_src_port, end_src_port;
  u32 start_dst_port, end_dst_port;
  u32 interval;
  u8 is_disable = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "src %U", unformat_ip46_address, &src))
	;
      else if (unformat (input, "start-src-port %d", &start_src_port))
	;
      else if (unformat (input, "end-src-port %d", &end_src_port))
	;
      else if (unformat (input, "start-dst-port %d", &start_dst_port))
	;
      else if (unformat (input, "end-dst-port %d", &end_dst_port))
	;
      else if (unformat (input, "dst %U", unformat_ip46_address, &dst))
	;
      else if (unformat (input, "interval %d", &interval))
	;
      else if (unformat (input, "disable"))
	is_disable = 1;
      else
	break;
    }

  M (UDP_PING_ADD_DEL, mp);

  ip_address_encode (&src, IP46_TYPE_IP6, &mp->src_ip_address);
  ip_address_encode (&dst, IP46_TYPE_IP6, &mp->dst_ip_address);
  mp->start_src_port = (u16) start_src_port;
  mp->end_src_port = (u16) end_src_port;
  mp->start_dst_port = (u16) start_dst_port;
  mp->end_dst_port = (u16) end_dst_port;
  mp->interval = (u16) interval;
  mp->dis = is_disable;

  S (mp);
  W (rv);

  return (rv);
}

static int
api_udp_ping_export (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_udp_ping_export_t *mp;
  int rv = 0;
  int is_add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "export"))
	is_add = 1;
      else if (unformat (input, "disable"))
	is_add = 0;
      else
	break;
    }

  M (UDP_PING_EXPORT, mp);

  mp->enable = is_add;

  S (mp);
  W (rv);

  return (rv);
}

/* Override generated plugin register symbol */
#define vat_plugin_register udp_ping_vat_plugin_register
#include <ioam/udp-ping/udp_ping.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
