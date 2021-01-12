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
#include <vnet/ip/ip_types_api.h>
#include "pnat.h"
#include <pnat/pnat.api_enum.h>
#include <pnat/pnat.api_types.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vnet/ip/reass/ip6_sv_reass.h>
#include <vnet/ip/reass/ip6_full_reass.h>
#include <vnet/fib/fib_table.h>
#include <vlibmemory/api.h>

/*
 * This file contains the API handlers for the pnat.api
 */

#define REPLY_MSG_ID_BASE pm->msg_id_base
#include <vlibapi/api_helper_macros.h>

int pnat_add_translation (u32 sw_if_index, pnat_5tuple_t *match, pnat_5tuple_t *rewrite, bool input, u32 *index);
int pnat_del_translation (u32 index);

static void
vl_api_pnat_binding_add_t_handler (vl_api_pnat_binding_add_t *mp)
{
  pnat_main_t *pm = &pnat_main;
  vl_api_pnat_binding_add_reply_t *rmp;
  u32 index;
  int rv;

  /* Ensure that the interface exists */
  if (!vnet_sw_if_index_is_api_valid(mp->sw_if_index)) {
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
    goto bad_sw_if_index;
  }

  rv = pnat_add_translation(mp->sw_if_index, &mp->match, &mp->rewrite, mp->is_input, &index);

 bad_sw_if_index:
  REPLY_MACRO2_END(VL_API_PNAT_BINDING_ADD_REPLY,
  ({
    rmp->index = index;
  }));
}

static void
vl_api_pnat_binding_del_t_handler (vl_api_pnat_binding_del_t *mp)
{
  pnat_main_t *pm = &pnat_main;
  vl_api_pnat_binding_del_reply_t *rmp;
  int rv = pnat_del_translation(mp->index);
  REPLY_MACRO_END(VL_API_PNAT_BINDING_DEL_REPLY);
}

/*
 * Workaround for a bug in vppapigen that doesn't register the endian handler
 * for _details messages. When that's fixed it should be possible to use
 * REPLY_MACRO_DETAILS4_END and not have to care about endian-ness in the
 * handler itself.
 */
#define vl_endianfun
#include <pnat/pnat.api.h>
#undef vl_endianfun
static void
send_bindings_details (u32 index, vl_api_registration_t * rp, u32 context)
{
  pnat_main_t *pm = &pnat_main;
  vl_api_pnat_bindings_details_t *rmp;
  pnat_translation_t *t = pool_elt_at_index(pm->translations, index);

  /* Make sure every field is initiated (or don't skip the clib_memset()) */

  REPLY_MACRO_DETAILS4(VL_API_PNAT_BINDINGS_DETAILS, rp, context,
  ({
    rmp->match = t->match;
    rmp->rewrite = t->rewrite;
    rmp->sw_if_index = t->key.sw_if_index;

    /* Endian hack until apigen registers _details endian functions */
    vl_api_pnat_bindings_details_t_endian(rmp);
    rmp->_vl_msg_id = htons(rmp->_vl_msg_id);
    rmp->context = htonl(rmp->context);
  }));
}

static void
vl_api_pnat_bindings_get_t_handler (vl_api_pnat_bindings_get_t * mp)
{
  pnat_main_t *pm = &pnat_main;
  vl_api_pnat_bindings_get_reply_t *rmp;

  i32 rv = 0;

  if (pool_elts(pm->translations) == 0) {
    REPLY_MACRO(VL_API_PNAT_BINDINGS_GET_REPLY);
    return;
  }

  /*
   * "cursor" comes from the get call, and allows client to continue a dump
   */
  REPLY_AND_DETAILS_MACRO (VL_API_PNAT_BINDINGS_GET_REPLY, pm->translations,
  ({
    send_bindings_details (cursor, rp, mp->context);
  }));
}

/* API definitions */
#include <vnet/format_fns.h>
#include <pnat/pnat.api.c>

/* Set up the API message handling tables */
clib_error_t *
pnat_plugin_api_hookup (vlib_main_t * vm)
{
  pnat_main_t *pm = &pnat_main;

  pm->msg_id_base = setup_message_id_table ();

  api_main_t *am = vlibapi_get_main ();

  /* Let the infrastructure convert endian-ness for these messages for us */
  am->is_autoendian[pm->msg_id_base + VL_API_PNAT_BINDING_ADD] = 1;
  am->is_autoendian[pm->msg_id_base + VL_API_PNAT_BINDING_DEL] = 1;
  return 0;
}
