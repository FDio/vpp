/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <ip_validate/ip_validate.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <ip_validate/ip_validate.api_enum.h>
#include <ip_validate/ip_validate.api_types.h>

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

VLIB_PLUGIN_REGISTER () = {
  .version = IP_VALIDATE_PLUGIN_BUILD_VER,
  .description = "IP Packet Validation Plugin",
  .default_disabled = 1,
};

ip_validate_main_t ip_validate_main;

/*
 * API handler — currently used only by the test suite.
 * Production behaviour is automatic: the VNET_SW_INTERFACE_ADD_DEL_FUNCTION
 * callback enables validation on every interface when it is created.
 */
static void
vl_api_ip_validate_enable_disable_t_handler (vl_api_ip_validate_enable_disable_t *mp)
{
  ip_validate_main_t *sm = &ip_validate_main;
  vl_api_ip_validate_enable_disable_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int is_enable = mp->is_enable;

  VALIDATE_SW_IF_INDEX (mp);

  rv = vnet_feature_enable_disable ("ip4-unicast", "ip4-validate", sw_if_index, is_enable, 0, 0);
  if (rv)
    goto done;

  rv = vnet_feature_enable_disable ("ip6-unicast", "ip6-validate", sw_if_index, is_enable, 0, 0);
  if (rv)
    {
      /* Rollback ip4 to avoid half-enabled state */
      vnet_feature_enable_disable ("ip4-unicast", "ip4-validate", sw_if_index, !is_enable, 0, 0);
    }

done:
  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_IP_VALIDATE_ENABLE_DISABLE_REPLY);
}

/* API definitions */
#include <ip_validate/ip_validate.api.c>

static clib_error_t *
ip_validate_init (vlib_main_t *vm)
{
  ip_validate_main_t *sm = &ip_validate_main;

  sm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (ip_validate_init);

/*
 * Auto-enable validation on every interface as it is created.
 * This is the intended production mechanism — no explicit API call is
 * needed.  The ip_validate_enable_disable API exists for testing
 * and could serve as a per-interface override in the future if needed.
 */
static clib_error_t *
ip_validate_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  vnet_feature_enable_disable ("ip4-unicast", "ip4-validate", sw_if_index, is_add, 0, 0);
  vnet_feature_enable_disable ("ip6-unicast", "ip6-validate", sw_if_index, is_add, 0, 0);
  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ip_validate_sw_interface_add_del);
