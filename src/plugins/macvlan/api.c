/* Copyright (c) 2024 Cisco and/or its affiliates.
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
 * limitations under the License. */

#include <vlib/vlib.h>
#include <vlibmemory/api.h>
#include <vlibapi/api.h>
#include <vnet/vnet.h>

#define REPLY_MSG_ID_BASE macvlan_msg_id_base
#include <vlibapi/api_helper_macros.h>

#include "macvlan.api_enum.h"
#include "macvlan.api_types.h"

#include "macvlan.h"

static u16 macvlan_msg_id_base;

void
vl_api_macvlan_add_del_t_handler (vl_api_macvlan_add_del_t *mp)
{
  vl_api_macvlan_add_del_reply_t *rmp;
  int rv = macvlan_add_del (htonl (mp->parent_sw_if_index),
			    htonl (mp->child_sw_if_index), mp->is_add);
  REPLY_MACRO (VL_API_MACVLAN_ADD_DEL_REPLY);
}

#include "macvlan.api.c"
static clib_error_t *
macvlan_api_hookup (vlib_main_t *vm)
{
  REPLY_MSG_ID_BASE = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (macvlan_api_hookup);
