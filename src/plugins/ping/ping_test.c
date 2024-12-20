/*
 * ping.c - skeleton vpp-api-test plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vppinfra/error.h>

#define __plugin_msg_base ping_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* declare message IDs */
#include <vnet/format_fns.h>
#include <ping/ping.api_enum.h>
#include <ping/ping.api_types.h>
#include <vnet/ip/ip_types_api.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} ping_test_main_t;

ping_test_main_t ping_test_main;

int
api_want_ping_finished_events (vat_main_t *vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_want_ping_finished_events_t *mp;
  u32 repeat = 1;
  f64 interval = 1.0;
  u32 set_ip = 0;
  ip_address_t address = { 0 };
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "repeat %d", &repeat))
	;
      else if (unformat (line_input, "interval %lf", &interval))
	;
      else if (unformat (line_input, "address %U", unformat_ip_address,
			 &address))
	set_ip = 1;
      else
	break;
    }

  if (set_ip == 0)
    {
      errmsg ("missing address");
      return -99;
    }

  /* Construct the API message */
  M (WANT_PING_FINISHED_EVENTS, mp);
  ip_address_encode2 (&address, &mp->address);
  mp->repeat = htonl (repeat);
  mp->interval = clib_host_to_net_f64 (interval);

  /* send it... */
  S (mp);
  /* Wait for the reply */
  W (ret);

  return ret;
}

#include <ping/ping.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
