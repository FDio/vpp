// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2023 Cisco Systems, Inc.

#include <stdbool.h>
#include <npt66/npt66.h>
#include <vnet/vnet.h>
#include <npt66/npt66.api_enum.h>
#include <npt66/npt66.api_types.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip_types_api.h>
#include <vpp/app/version.h>

npt66_main_t npt66_main;

/*
 * This file contains the API handlers for the pnat.api
 */

#define REPLY_MSG_ID_BASE npt66_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_npt66_binding_add_del_t_handler (vl_api_npt66_binding_add_del_t *mp)
{
  vl_api_npt66_binding_add_del_reply_t *rmp;
  int rv;
  clib_warning ("Interface index: %d", mp->sw_if_index);
  VALIDATE_SW_IF_INDEX_END (mp);

  rv = npt66_binding_add_del (
    mp->sw_if_index, (ip6_address_t *) &mp->internal.address, mp->internal.len,
    (ip6_address_t *) &mp->external.address, mp->external.len, mp->is_add);

bad_sw_if_index:
  REPLY_MACRO_END (VL_API_NPT66_BINDING_ADD_DEL_REPLY);
}

/* API definitions */
#include <vnet/format_fns.h>
#include <npt66/npt66.api.c>

/* Set up the API message handling tables */
clib_error_t *
npt66_plugin_api_hookup (vlib_main_t *vm)
{
  npt66_main_t *nm = &npt66_main;

  nm->msg_id_base = setup_message_id_table ();
  return 0;
}

/*
 * Register the plugin and hook up the API
 */
#include <vnet/plugin/plugin.h>
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "NPTv6",
  .default_disabled = 1,
};

clib_error_t *
npt66_init (vlib_main_t *vm)
{
  npt66_main_t *nm = &npt66_main;
  memset (nm, 0, sizeof (*nm));

  return npt66_plugin_api_hookup (vm);
}

VLIB_INIT_FUNCTION (npt66_init);
