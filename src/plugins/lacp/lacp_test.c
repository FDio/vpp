/*
 * lacp VAT support
 *
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

#include <inttypes.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/error.h>
#include <lacp/node.h>

#define __plugin_msg_base lacp_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* declare message IDs */
#include <lacp/lacp_msg_enum.h>

/* Get CRC codes of the messages defined outside of this plugin */
#define vl_msg_name_crc_list
#include <vpp/api/vpe_all_api_h.h>
#undef vl_msg_name_crc_list

/* define message structures */
#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#include <lacp/lacp_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <lacp/lacp_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <lacp/lacp_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <lacp/lacp_all_api_h.h>
#undef vl_api_version

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} lacp_test_main_t;

lacp_test_main_t lacp_test_main;

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                       \
_(SW_INTERFACE_LACP_DETAILS, sw_interface_lacp_details)

/* lacp-dump API */
static void vl_api_sw_interface_lacp_details_t_handler
  (vl_api_sw_interface_lacp_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  fformat (vam->ofp,
	   "%-25s %-12d %-16s %3x %3x %3x %3x %3x %3x %3x %3x "
	   "%4x %3x %3x %3x %3x %3x %3x %3x\n",
	   mp->interface_name, ntohl (mp->sw_if_index),
	   mp->bond_interface_name,
	   lacp_bit_test (mp->actor_state, 7),
	   lacp_bit_test (mp->actor_state, 6),
	   lacp_bit_test (mp->actor_state, 5),
	   lacp_bit_test (mp->actor_state, 4),
	   lacp_bit_test (mp->actor_state, 3),
	   lacp_bit_test (mp->actor_state, 2),
	   lacp_bit_test (mp->actor_state, 1),
	   lacp_bit_test (mp->actor_state, 0),
	   lacp_bit_test (mp->partner_state, 7),
	   lacp_bit_test (mp->partner_state, 6),
	   lacp_bit_test (mp->partner_state, 5),
	   lacp_bit_test (mp->partner_state, 4),
	   lacp_bit_test (mp->partner_state, 3),
	   lacp_bit_test (mp->partner_state, 2),
	   lacp_bit_test (mp->partner_state, 1),
	   lacp_bit_test (mp->partner_state, 0));
  fformat (vam->ofp,
	   "  LAG ID: [(%04x,%02x-%02x-%02x-%02x-%02x-%02x,%04x,%04x,%04x), "
	   "(%04x,%02x-%02x-%02x-%02x-%02x-%02x,%04x,%04x,%04x)]\n",
	   ntohs (mp->actor_system_priority), mp->actor_system[0],
	   mp->actor_system[1], mp->actor_system[2], mp->actor_system[3],
	   mp->actor_system[4], mp->actor_system[5], ntohs (mp->actor_key),
	   ntohs (mp->actor_port_priority), ntohs (mp->actor_port_number),
	   ntohs (mp->partner_system_priority), mp->partner_system[0],
	   mp->partner_system[1], mp->partner_system[2],
	   mp->partner_system[3], mp->partner_system[4],
	   mp->partner_system[5], ntohs (mp->partner_key),
	   ntohs (mp->partner_port_priority),
	   ntohs (mp->partner_port_number));
  fformat (vam->ofp,
	   "  RX-state: %U, TX-state: %U, MUX-state: %U, PTX-state: %U\n",
	   format_rx_sm_state, ntohl (mp->rx_state), format_tx_sm_state,
	   ntohl (mp->tx_state), format_mux_sm_state, ntohl (mp->mux_state),
	   format_ptx_sm_state, ntohl (mp->ptx_state));
}

static int
api_sw_interface_lacp_dump (vat_main_t * vam)
{
  lacp_test_main_t *lm = &lacp_test_main;
  vl_api_sw_interface_lacp_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for sw_interface_lacp_dump");
      return -99;
    }

  fformat (vam->ofp, "%-55s %-32s %-32s\n", " ", "actor state",
	   "partner state");
  fformat (vam->ofp, "%-25s %-12s %-16s %-31s  %-31s\n", "interface name",
	   "sw_if_index", "bond interface", "exp/def/dis/col/syn/agg/tim/act",
	   "exp/def/dis/col/syn/agg/tim/act");

  /* Get list of lacp interfaces */
  M (SW_INTERFACE_LACP_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (lm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  fformat (vam->ofp, "Sending ping id=%d\n", lm->ping_id);

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);
  return ret;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg					  \
_(sw_interface_lacp_dump, "")

static void
lacp_vat_api_hookup (vat_main_t * vam)
{
  lacp_test_main_t *lm __attribute__ ((unused)) = &lacp_test_main;
  /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
  vl_msg_api_set_handlers((VL_API_##N + lm->msg_id_base),       \
                          #n,                                   \
                          vl_api_##n##_t_handler,               \
                          vl_noop_handler,                      \
                          vl_api_##n##_t_endian,                \
                          vl_api_##n##_t_print,                 \
                          sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_reply_msg;
#undef _

  /* API messages we can send */
#define _(n,h)                                          \
  hash_set_mem (vam->function_by_name, #n, api_##n);
  foreach_vpe_api_msg;
#undef _

  /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
  foreach_vpe_api_msg;
#undef _
}

clib_error_t *
vat_plugin_register (vat_main_t * vam)
{
  lacp_test_main_t *lm = &lacp_test_main;
  u8 *name;

  lm->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "lacp_%08x%c", api_version, 0);
  lm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  /* Get the control ping ID */
#define _(id,n,crc) \
  const char *id ## _CRC __attribute__ ((unused)) = #n "_" #crc;
  foreach_vl_msg_name_crc_vpe;
#undef _
  lm->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));

  if (lm->msg_id_base != (u16) ~ 0)
    lacp_vat_api_hookup (vam);

  vec_free (name);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
