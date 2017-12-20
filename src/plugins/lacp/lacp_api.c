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
#include <lacp/lacp_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <lacp/lacp_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <lacp/lacp_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <lacp/lacp_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <lacp/lacp_all_api_h.h>
#undef vl_api_version

/*
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */
#define REPLY_MACRO(t)                                          \
do {                                                            \
    svm_queue_t * q =                            \
    vl_api_client_index_to_input_queue (mp->client_index);      \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = htons ((t)+lm->msg_id_base);              \
    rmp->context = mp->context;                                 \
    rmp->retval = htonl (rv);                                   \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#define REPLY_MACRO2(t, body)                                   \
do {                                                            \
    svm_queue_t * q =                            \
    vl_api_client_index_to_input_queue (mp->client_index);      \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = htons ((t)+lm->msg_id_base);              \
    rmp->context = mp->context;                                 \
    rmp->retval = htonl (rv);                                   \
    do {body;} while (0);                                       \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#define foreach_lacp_plugin_api_msg				\
_(SW_INTERFACE_LACP_DUMP, sw_interface_lacp_dump)

static void
lacp_send_sw_interface_details (vl_api_registration_t * reg,
				lacp_interface_details_t * lacp_if,
				u32 context)
{
  lacp_main_t *lm = &lacp_main;
  vl_api_sw_interface_lacp_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
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

#define vl_msg_name_crc_list
#include <lacp/lacp_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (lacp_main_t * lm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + lm->msg_id_base);
  foreach_vl_msg_name_crc_lacp;
#undef _
}

/* Set up the API message handling tables */
clib_error_t *
lacp_plugin_api_hookup (vlib_main_t * vm)
{
  lacp_main_t *lm = &lacp_main;
  api_main_t *am = &api_main;
  u8 *name;

  /* Construct the API name */
  name = format (0, "lacp_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  lm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + lm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_lacp_plugin_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (lm, am);

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
