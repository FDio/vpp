/*
 *------------------------------------------------------------------
 * lacp_api.c - lacp api
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vlib/unix/unix.h>
#include <lacp/node.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>


/* define message IDs */
#include <vnet/format_fns.h>
#include <lacp/lacp.api_enum.h>
#include <lacp/lacp.api_types.h>

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

/* Macro to finish up custom dump fns */
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

#define REPLY_MSG_ID_BASE lm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
lacp_send_sw_interface_details (vl_api_registration_t * reg,
				lacp_interface_details_t * lacp_if,
				u32 context)
{
  lacp_main_t *lm = &lacp_main;
  vl_api_sw_interface_lacp_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = htons (VL_API_SW_INTERFACE_LACP_DETAILS + lm->msg_id_base);
  mp->sw_if_index = htonl (lacp_if->sw_if_index);

  /* These fields in network order already */
  mp->actor_system_priority = lacp_if->actor_system_priority;
  mp->actor_key = lacp_if->actor_key;
  mp->actor_port_priority = lacp_if->actor_port_priority;
  mp->actor_port_number = lacp_if->actor_port_number;
  mp->actor_state = lacp_if->actor_state;
  clib_memcpy (mp->actor_system, lacp_if->actor_system, 6);
  mp->partner_system_priority = lacp_if->partner_system_priority;
  mp->partner_key = lacp_if->partner_key;
  mp->partner_port_priority = lacp_if->partner_port_priority;
  mp->partner_port_number = lacp_if->partner_port_number;
  mp->partner_state = lacp_if->partner_state;

  clib_memcpy (mp->partner_system, lacp_if->partner_system, 6);
  clib_memcpy (mp->interface_name, lacp_if->interface_name,
	       MIN (ARRAY_LEN (mp->interface_name) - 1,
		    strlen ((const char *) lacp_if->interface_name)));
  clib_memcpy (mp->bond_interface_name, lacp_if->bond_interface_name,
	       MIN (ARRAY_LEN (mp->bond_interface_name) - 1,
		    strlen ((const char *) lacp_if->bond_interface_name)));
  mp->rx_state = htonl (lacp_if->rx_state);
  mp->tx_state = htonl (lacp_if->tx_state);
  mp->mux_state = htonl (lacp_if->mux_state);
  mp->ptx_state = htonl (lacp_if->ptx_state);

  mp->context = context;
  vl_api_send_msg (reg, (u8 *) mp);
}

/**
 * @brief Message handler for lacp_dump API.
 * @param mp vl_api_lacp_dump_t * mp the api message
 */
void
vl_api_sw_interface_lacp_dump_t_handler (vl_api_sw_interface_lacp_dump_t * mp)
{
  int rv;
  vl_api_registration_t *reg;
  lacp_interface_details_t *lacpifs = NULL;
  lacp_interface_details_t *lacp_if = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rv = lacp_dump_ifs (&lacpifs);
  if (rv)
    return;

  vec_foreach (lacp_if, lacpifs)
  {
    lacp_send_sw_interface_details (reg, lacp_if, mp->context);
  }

  vec_free (lacpifs);
}

/* Set up the API message handling tables */
#include <lacp/lacp.api.c>
clib_error_t *
lacp_plugin_api_hookup (vlib_main_t * vm)
{
  lacp_main_t *lm = &lacp_main;
  api_main_t *am = vlibapi_get_main ();

  /* Ask for a correctly-sized block of API message decode slots */
  lm->msg_id_base = setup_message_id_table ();

  /* Mark these APIs as mp safe */
  am->is_mp_safe[VL_API_SW_INTERFACE_LACP_DUMP] = 1;
  am->is_mp_safe[VL_API_SW_INTERFACE_LACP_DETAILS] = 1;

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
