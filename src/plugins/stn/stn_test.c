/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>

#include <stn/stn.h>

#define __plugin_msg_base stn_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <stn/stn_msg_enum.h>

/* Get CRC codes of the messages defined outside of this plugin */
#define vl_msg_name_crc_list
#include <vpp/api/vpe_all_api_h.h>
#undef vl_msg_name_crc_list

/* define message structures */
#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#include <stn/stn_all_api_h.h>
#undef vl_typedefs

/* define message structures */
#define vl_endianfun
#include <stn/stn_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <stn/stn_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <stn/stn_all_api_h.h>
#undef vl_api_version

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} stn_test_main_t;

stn_test_main_t stn_test_main;

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_stn_api_reply_msg                       \
_(STN_RULES_DETAILS, stn_rules_details)

static int
api_stn_rules_dump (vat_main_t * vam)
{
  stn_test_main_t *sm = &stn_test_main;
  vl_api_stn_rules_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%=20s", "STN Rules");
    }

  M (STN_RULES_DUMP, mp);
  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (sm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  fformat (vam->ofp, "Sending ping id=%d\n", sm->ping_id);

  vam->result_ready = 0;
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_stn_rules_details_t_handler (vl_api_stn_rules_details_t * mp)
{
  vat_main_t *vam = stn_test_main.vat_main;
  fformat (vam->ofp, "addr: %U sw_if_index: %u\n",
	   mp->is_ip4 ? format_ip4_address : format_ip6_address,
	   mp->ip_address, clib_net_to_host_u32 (mp->sw_if_index));
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_stn_api_msg 				\
_(stn_rules_dump, "")					\

static void
stn_vat_api_hookup (vat_main_t * vam)
{
  stn_test_main_t *sm = &stn_test_main;
  /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_stn_api_reply_msg;
#undef _

  /* API messages we can send */
#define _(n,h) hash_set_mem (vam->function_by_name, #n, api_##n);
  foreach_stn_api_msg;
#undef _

  /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
  foreach_stn_api_msg;
#undef _
}

clib_error_t *
vat_plugin_register (vat_main_t * vam)
{
  stn_test_main_t *sm = &stn_test_main;
  u8 *name;

  sm->vat_main = vam;

  name = format (0, "stn_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  /* Get the control ping ID */
#define _(id,n,crc) \
  const char *id ## _CRC __attribute__ ((unused)) = #n "_" #crc;
  foreach_vl_msg_name_crc_vpe;
#undef _
  sm->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));

  if (sm->msg_id_base != (u16) ~ 0)
    stn_vat_api_hookup (vam);

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
