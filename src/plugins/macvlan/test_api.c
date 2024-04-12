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
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#define __plugin_msg_base macvlan_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>
/* declare message IDs */
#include "macvlan.api_enum.h"
#include "macvlan.api_types.h"
#include "macvlan.h"

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} macvlan_test_main_t;

static macvlan_test_main_t macvlan_test_main;

static int
api_macvlan_add_del (vat_main_t *vam)
{
  u32 parent_sw_if_index, child_sw_if_index;
  vl_api_macvlan_add_del_t *mp;
  bool is_add;
  int rv;

  if (macvlan_parse_add_del (vam->input, &parent_sw_if_index,
			     &child_sw_if_index, &is_add))
    return -1;

  M (MACVLAN_ADD_DEL, mp);
  mp->parent_sw_if_index = htonl (parent_sw_if_index);
  mp->child_sw_if_index = htonl (child_sw_if_index);
  mp->is_add = is_add;

  S (mp);
  W (rv);

  return rv;
}

#include "macvlan.api_test.c"
