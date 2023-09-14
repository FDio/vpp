/*
 *------------------------------------------------------------------
 * Copyright (c) 2023 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <ping/ping.h>

/* define message IDs */
#include <ping/ping.api_enum.h>
#include <ping/ping.api_types.h>

#define REPLY_MSG_ID_BASE pm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
ping_api_send_ping_event (vl_api_want_ping_events_t *mp, u32 request_count,
			  u32 reply_count)
{
  ping_main_t *pm = &ping_main;

  vl_api_registration_t *rp;
  rp = vl_api_client_index_to_registration (mp->client_index);

  vl_api_ping_finished_event_t *e = vl_msg_api_alloc (sizeof (*e));
  clib_memset (e, 0, sizeof (*e));

  e->_vl_msg_id = htons (VL_API_PING_FINISHED_EVENT + pm->msg_id_base);
  e->request_count = htonl (request_count);
  e->reply_count = htonl (reply_count);

  vl_api_send_msg (rp, (u8 *) e);
}

void
vl_api_want_ping_events_t_handler (vl_api_want_ping_events_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  ping_main_t *pm = &ping_main;
  vl_api_want_ping_events_reply_t *rmp;

  uword curr_proc = vlib_current_process (vm);

  u16 icmp_id;
  static u32 rand_seed = 0;

  if (PREDICT_FALSE (!rand_seed))
    rand_seed = random_default_seed ();

  icmp_id = random_u32 (&rand_seed) & 0xffff;

  while (~0 != get_cli_process_id_by_icmp_id_mt (vm, icmp_id))
    icmp_id++;

  set_cli_process_id_by_icmp_id_mt (vm, icmp_id, curr_proc);

  int rv = 0;
  u32 request_count = 0;
  u32 reply_count = 0;

  u32 table_id = 0;
  ip_address_t dst_addr = { 0 };
  u32 sw_if_index = ~0;
  f64 ping_interval = clib_net_to_host_f64 (mp->interval);
  u32 ping_repeat = ntohl (mp->repeat);
  u32 data_len = PING_DEFAULT_DATA_LEN;
  u32 ping_burst = 1;
  u32 verbose = 0;
  ip_address_decode2 (&mp->address, &dst_addr);

  vl_api_registration_t *rp;
  rp = vl_api_client_index_to_registration (mp->client_index);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id =
    htons ((VL_API_WANT_PING_EVENTS_REPLY) + (REPLY_MSG_ID_BASE));
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  vl_api_send_msg (rp, (u8 *) rmp);

  int i;
  send_ip46_ping_result_t res = SEND_PING_OK;
  for (i = 1; i <= ping_repeat; i++)
    {
      f64 sleep_interval;
      f64 time_ping_sent = vlib_time_now (vm);

      if (dst_addr.version == AF_IP4)
	res = send_ip4_ping (vm, table_id, &dst_addr.ip.ip4, sw_if_index, i,
			     icmp_id, data_len, ping_burst, verbose);
      else
	res = send_ip6_ping (vm, table_id, &dst_addr.ip.ip6, sw_if_index, i,
			     icmp_id, data_len, ping_burst, verbose);

      if (SEND_PING_OK == res)
	request_count += 1;

      while ((sleep_interval =
		time_ping_sent + ping_interval - vlib_time_now (vm)) > 0.0)
	{
	  uword event_type;
	  vlib_process_wait_for_event_or_clock (vm, sleep_interval);
	  event_type = vlib_process_get_events (vm, 0);

	  if (event_type == ~0)
	    break;

	  if (event_type == PING_RESPONSE_IP4 ||
	      event_type == PING_RESPONSE_IP6)
	    reply_count += 1;
	}
    }

  ping_api_send_ping_event (mp, request_count, reply_count);

  clear_cli_process_id_by_icmp_id_mt (vm, icmp_id);
}

/* set tup the API message handling tables */
#include <ping/ping.api.c>

clib_error_t *
ping_plugin_api_hookup (vlib_main_t *vm)
{
  ping_main_t *pm = &ping_main;

  /* ask for a correctly-sized block of API message decode slots */
  pm->msg_id_base = setup_message_id_table ();

  return 0;
}