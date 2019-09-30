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
#include <vpp/api/vpe.api_types.h>
#include <stn/stn.api_enum.h>
#include <stn/stn.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} stn_test_main_t;

stn_test_main_t stn_test_main;

static int
api_stn_add_del_rule (vat_main_t * vam)
{
  // Not yet implemented
  return -99;
}

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

#include <stn/stn.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
