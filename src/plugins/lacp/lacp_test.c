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
#include <vnet/format_fns.h>
#include <lacp/lacp.api_enum.h>
#include <lacp/lacp.api_types.h>
#include <vpp/api/vpe.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} lacp_test_main_t;

lacp_test_main_t lacp_test_main;

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
  if (!lm->ping_id)
    lm->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (lm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  fformat (vam->ofp, "Sending ping id=%d\n", lm->ping_id);

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);
  return ret;
}

#include <lacp/lacp.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
