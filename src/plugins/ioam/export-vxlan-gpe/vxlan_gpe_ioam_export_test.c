/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
/*
 *------------------------------------------------------------------
 * vxlan_gpe_ioam_export_test.c - test harness plugin
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vnet/format_fns.h>

#define __plugin_msg_base vxlan_gpe_ioam_export_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <ioam/export-vxlan-gpe/vxlan_gpe_ioam_export.api_enum.h>
#include <ioam/export-vxlan-gpe/vxlan_gpe_ioam_export.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} vxlan_gpe_ioam_export_test_main_t;

vxlan_gpe_ioam_export_test_main_t vxlan_gpe_ioam_export_test_main;

static int
api_vxlan_gpe_ioam_export_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  int is_disable = 0;
  vl_api_vxlan_gpe_ioam_export_enable_disable_t *mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "disable"))
	is_disable = 1;
      else
	break;
    }

  /* Construct the API message */
  M (VXLAN_GPE_IOAM_EXPORT_ENABLE_DISABLE, mp);
  mp->is_disable = is_disable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/* Override generated plugin register symbol */
#define vat_plugin_register vxlan_gpe_ioam_export_vat_plugin_register
#include <ioam/export-vxlan-gpe/vxlan_gpe_ioam_export.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
