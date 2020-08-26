/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <stddef.h>

#include <vnet/vnet.h>
#include <vnet/feature/feature.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <calico/calico.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <calico/calico.api_enum.h>
#include <calico/calico.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 calico_base_message_id;

#define REPLY_MSG_ID_BASE calico_base_message_id

#include <vlibapi/api_helper_macros.h>

static void
  vl_api_calico_enable_disable_interface_snat_t_handler
  (vl_api_calico_enable_disable_interface_snat_t * mp)
{
  vl_api_calico_enable_disable_interface_snat_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv =
    calico_enable_disable_snat (ntohl (mp->sw_if_index), mp->is_ip6,
				mp->is_enable);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_CALICO_ENABLE_DISABLE_INTERFACE_SNAT_REPLY);
}

#include <calico/calico.api.c>

static clib_error_t *
calico_api_init (vlib_main_t * vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  calico_base_message_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (calico_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
