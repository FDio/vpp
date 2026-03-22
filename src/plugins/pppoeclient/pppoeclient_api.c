/* SPDX-License-Identifier: Apache-2.0 */
/*
 *------------------------------------------------------------------
 * pppoeclient_api.c - pppoe client api
 *
 * Copyright (c) 2017 RaydoNetworks.
 * Copyright (c) 2026 Hi-Jiajun.
 * Copyright (c) 2026 Adapted for latest VPP
 *------------------------------------------------------------------
 */

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>

#include <pppoeclient/pppoeclient.h>
#include <pppoeclient/pppoeclient.api_types.h>
#include <pppoeclient/pppoeclient.api_enum.h>

/* Handler for pppoe_add_del_client */
static void
vl_api_pppoe_add_del_client_t_handler (vl_api_pppoe_add_del_client_t *mp)
{
  vl_api_pppoe_add_del_client_reply_t *rmp;
  int rv = 0;
  pppoeclient_main_t *pem = &pppoeclient_main;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);

  vnet_pppoe_add_del_client_args_t a = {
    .is_add = mp->is_add,
    .sw_if_index = ntohl (mp->sw_if_index),
    .host_uniq = ntohl (mp->host_uniq),
  };

  u32 pppox_sw_if_index = ~0;
  rv = vnet_pppoe_add_del_client (&a, &pppox_sw_if_index);

  /* Create reply */
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_PPPOE_ADD_DEL_CLIENT_REPLY + pem->msg_id_base);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  rmp->pppox_sw_if_index = ntohl (pppox_sw_if_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

/* Send client details */
static void
send_pppoe_client_details (pppoe_client_t *t, vl_api_registration_t *reg, u32 context)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  vl_api_pppoe_client_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_PPPOE_CLIENT_DETAILS + pem->msg_id_base);
  rmp->context = context;
  rmp->sw_if_index = ntohl (t->sw_if_index);
  rmp->host_uniq = ntohl (t->host_uniq);

  vl_api_send_msg (reg, (u8 *) rmp);
}

/* Handler for pppoe_client_dump */
static void
vl_api_pppoe_client_dump_t_handler (vl_api_pppoe_client_dump_t *mp)
{
  vl_api_registration_t *reg;
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *t;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == 0)
    {
      return;
    }

  pool_foreach (t, pem->clients)
    {
      send_pppoe_client_details (t, reg, mp->context);
    }
}

/* Include auto-generated API code */
#include <pppoeclient/pppoeclient.api.c>

/* API setup hook */
static clib_error_t *
pppoeclient_api_hookup (vlib_main_t *vm)
{
  pppoeclient_main_t *pem = &pppoeclient_main;

  pem->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (pppoeclient_api_hookup);

/*
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
