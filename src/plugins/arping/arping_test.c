/*
 * arping VAT support
 *
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <inttypes.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/error.h>
#include <arping/arping.h>

#define __plugin_msg_base arping_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* declare message IDs */
#include <vnet/format_fns.h>
#include <arping/arping.api_enum.h>
#include <arping/arping.api_types.h>
#include <vpp/api/vpe.api_types.h>
#include <vnet/ip/ip_types_api.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} arping_test_main_t;

arping_test_main_t arping_test_main;

/* arping request API */
static int
api_arping (vat_main_t *vam)
{
  vl_api_arping_t *mp;
  arping_args_t args = { 0 };
  int ret;
  unformat_input_t *input = vam->input;
  vnet_main_t *vnm = vnet_get_main ();
  f64 interval = ARPING_DEFAULT_INTERVAL;
  vl_api_control_ping_t *mp_ping;
  arping_test_main_t *atm = &arping_test_main;

  args.repeat = ARPING_DEFAULT_REPEAT;
  args.interval = ARPING_DEFAULT_INTERVAL;
  args.sw_if_index = ~0;

  if (unformat (input, "gratuitous"))
    args.is_garp = 1;

  if (unformat (input, "%U", unformat_ip4_address, &args.address.ip.ip4))
    args.address.version = AF_IP4;
  else if (unformat (input, "%U", unformat_ip6_address, &args.address.ip.ip6))
    args.address.version = AF_IP6;
  else
    {
      errmsg ("expecting IP4/IP6 address `%U'. Usage: arping [gratuitous] "
	      "<addr> <intf> [repeat <count>] [interval <secs>]",
	      format_unformat_error, input);
      return -99;
    }

  if (!unformat_user (input, unformat_vnet_sw_interface, vnm,
		      &args.sw_if_index))
    {
      errmsg ("unknown interface `%U'", format_unformat_error, input);
      return -99;
    }

  /* parse the rest of the parameters  in a cycle */
  while (!unformat_eof (input, NULL))
    {
      if (unformat (input, "interval"))
	{
	  if (!unformat (input, "%f", &interval))
	    {
	      errmsg ("expecting interval (floating point number) got `%U'",
		      format_unformat_error, input);
	      return -99;
	    }
	  args.interval = interval;
	}
      else if (unformat (input, "repeat"))
	{
	  if (!unformat (input, "%u", &args.repeat))
	    {
	      errmsg ("expecting repeat count but got `%U'",
		      format_unformat_error, input);
	      return -99;
	    }
	}
      else
	{
	  errmsg ("unknown input `%U'", format_unformat_error, input);
	  return -99;
	}
    }

  M (ARPING, mp);

  mp->interval = clib_host_to_net_f64 (args.interval);
  mp->repeat = clib_host_to_net_u32 (args.repeat);
  mp->is_garp = args.is_garp;
  mp->sw_if_index = clib_host_to_net_u32 (args.sw_if_index);
  ip_address_encode2 (&args.address, &mp->address);

  S (mp);

  /* Use a control ping for synchronization */
  if (!atm->ping_id)
    atm->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (atm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  fformat (vam->ofp, "Sending ping id=%d\n", atm->ping_id);

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);

  return ret;
}

/* arping-create reply handler */
static void
vl_api_arping_reply_t_handler (vl_api_arping_reply_t *mp)
{
  vat_main_t *vam = arping_test_main.vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval == 0)
    {
      fformat (vam->ofp, "arping request reply count = %d\n",
	       ntohl (mp->reply_count));
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

#include <arping/arping.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
