/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>

#include <arping/arping.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ethernet/ethernet_types_api.h>

/* define message IDs */
#include <arping/arping.api_enum.h>
#include <arping/arping.api_types.h>

#define REPLY_MSG_ID_BASE (am->msg_id_base)
#include <vlibapi/api_helper_macros.h>

static void
vl_api_arping_t_handler (vl_api_arping_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  arping_main_t *am = &arping_main;
  vl_api_arping_reply_t *rmp;
  arping_args_t args = { 0 };
  int rv;

  if (mp->sw_if_index != ~0)
    VALIDATE_SW_IF_INDEX (mp);

  ip_address_decode2 (&mp->address, &args.address);
  args.interval = clib_net_to_host_f64 (mp->interval);
  args.repeat = ntohl (mp->repeat);
  args.is_garp = mp->is_garp;
  args.sw_if_index = ntohl (mp->sw_if_index);
  args.silence = 1;

  arping_run_command (vm, &args);
  rv = args.rv;

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO2 (VL_API_ARPING_REPLY,
		({ rmp->reply_count = ntohl (args.reply_count); }));
}

static void
vl_api_arping_acd_t_handler (vl_api_arping_acd_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  arping_main_t *am = &arping_main;
  vl_api_arping_acd_reply_t *rmp;
  arping_args_t args = { 0 };
  int rv;

  if (mp->sw_if_index != ~0)
    VALIDATE_SW_IF_INDEX (mp);

  ip_address_decode2 (&mp->address, &args.address);
  args.interval = clib_net_to_host_f64 (mp->interval);
  args.repeat = ntohl (mp->repeat);
  args.is_garp = mp->is_garp;
  args.sw_if_index = ntohl (mp->sw_if_index);
  args.silence = 1;

  arping_run_command (vm, &args);
  rv = args.rv;

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO2 (VL_API_ARPING_ACD_REPLY, ({
		  rmp->reply_count = ntohl (args.reply_count);
		  mac_address_encode (&args.recv.from4.mac, rmp->mac_address);
		}));
}

/* set tup the API message handling tables */
#include <arping/arping.api.c>
clib_error_t *
arping_plugin_api_hookup (vlib_main_t *vm)
{
  arping_main_t *am = &arping_main;
  api_main_t *vam = vlibapi_get_main ();

  /* ask for a correctly-sized block of API message decode slots */
  am->msg_id_base = setup_message_id_table ();

  /* Mark API as mp safe */
  vl_api_set_msg_thread_safe (vam, am->msg_id_base + VL_API_ARPING, 1);
  vl_api_set_msg_thread_safe (vam, am->msg_id_base + VL_API_ARPING_ACD, 1);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
