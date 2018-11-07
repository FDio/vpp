/*
 * upf.c - 3GPP TS 29.244 GTP-U UP plug-in for vpp
 *
 * Copyright (c) 2017 Travelping GmbH
 *
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

#define _LGPL_SOURCE            /* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>          /* QSBR RCU flavor */

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>

#include <upf/upf.h>
#include <upf/upf_adf.h>

/* define message IDs */
#include <upf/upf_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <upf/upf_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <upf/upf_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <upf/upf_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <upf/upf_all_api_h.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <upf/upf_all_api_h.h>
#undef vl_msg_name_crc_list

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */

static void
setup_message_id_table (upf_main_t * sm, api_main_t * am)
{
#define _(id,n,crc)   vl_msg_api_add_msg_name_crc (am, #n  #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_upf ;
#undef _
}

#define foreach_upf_plugin_api_msg        \
_(UPF_ENABLE_DISABLE, upf_enable_disable) \
_(UPF_APP_ADD_DEL, upf_app_add_del) \
_(UPF_APP_IP_RULE_ADD_DEL, upf_app_ip_rule_add_del) \
_(UPF_APP_L7_RULE_ADD_DEL, upf_app_l7_rule_add_del) \
_(UPF_APP_FLOW_TIMEOUT_SET, upf_app_flow_timeout_set)

/* API message handler */
static void vl_api_upf_enable_disable_t_handler
(vl_api_upf_enable_disable_t * mp)
{
  vl_api_upf_enable_disable_reply_t * rmp;
  upf_main_t * sm = &upf_main;
  int rv;

  rv = upf_enable_disable (sm, ntohl(mp->sw_if_index),
				      (int) (mp->enable_disable));

  REPLY_MACRO(VL_API_UPF_ENABLE_DISABLE_REPLY);
}

/* API message handler */
static void vl_api_upf_app_add_del_t_handler
(vl_api_upf_app_add_del_t * mp)
{
  vl_api_upf_app_add_del_reply_t * rmp = NULL;
  upf_main_t * sm = &upf_main;
  int rv = 0;

  rv = upf_app_add_del (sm, mp->name, (int) (mp->is_add));

  REPLY_MACRO(VL_API_UPF_APP_ADD_DEL_REPLY);
}

/* API message handler */
static void vl_api_upf_app_ip_rule_add_del_t_handler
(vl_api_upf_app_ip_rule_add_del_t * mp)
{
  vl_api_upf_app_ip_rule_add_del_reply_t * rmp = NULL;
  upf_rule_args_t args = {};
  upf_main_t * sm = &upf_main;
  int rv = 0;

  rv = upf_rule_add_del (sm, mp->app, mp->id,
                         (int) (mp->is_add), &args);

  REPLY_MACRO(VL_API_UPF_APP_IP_RULE_ADD_DEL_REPLY);
}

/* API message handler */
static void vl_api_upf_app_l7_rule_add_del_t_handler
(vl_api_upf_app_l7_rule_add_del_t * mp)
{
  vl_api_upf_app_l7_rule_add_del_reply_t * rmp = NULL;
  upf_rule_args_t args = {};
  upf_main_t * sm = &upf_main;
  int rv = 0;

  args.host = mp->host;
  args.path = mp->path;
  rv = upf_rule_add_del (sm, mp->app, mp->id, 
                         (int) (mp->is_add), &args);

  REPLY_MACRO(VL_API_UPF_APP_L7_RULE_ADD_DEL_REPLY);
}

/* API message handler */
static void vl_api_upf_app_flow_timeout_set_t_handler
(vl_api_upf_app_flow_timeout_set_t * mp)
{
  int rv = 0;
  vl_api_upf_app_flow_timeout_set_reply_t * rmp = NULL;
  upf_main_t * sm = &upf_main;

  //rv = upf_flow_timeout_update(mp->type, mp->default_value);

  REPLY_MACRO(VL_API_UPF_APP_FLOW_TIMEOUT_SET_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
upf_api_hookup (vlib_main_t *vm)
{
  upf_main_t * sm = &upf_main;

  u8 *name = format (0, "upf_%08x%c", api_version, 0);
  sm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
			   #n,					\
			   vl_api_##n##_t_handler,              \
			   vl_noop_handler,                     \
			   vl_api_##n##_t_endian,               \
			   vl_api_##n##_t_print,                \
			   sizeof(vl_api_##n##_t), 1);
    foreach_upf_plugin_api_msg;
#undef _

    /* Add our API messages to the global name_crc hash table */
    setup_message_id_table (sm, &api_main);

    return 0;
}

VLIB_API_INIT_FUNCTION (upf_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
