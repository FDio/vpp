/*
 *------------------------------------------------------------------
 * match_api.c - vnet match api
 *
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
 *------------------------------------------------------------------
 */

#include <stddef.h>

#include <vnet/ethernet/ethernet_types_api.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vnet/match/match.api_enum.h>
#include <vnet/match/match.api_types.h>

#include <vnet/match/match_set.h>
#include <vnet/match/match_set_dp.h>
#include <vnet/match/match_types_api.h>

static u16 msg_id_base;
#define REPLY_MSG_ID_BASE msg_id_base

#include <vlibapi/api_helper_macros.h>

#include <vnet/format_fns.h>


#define vl_msg_name_crc_list
#include <vnet/match/match.api.h>
#undef vl_msg_name_crc_list


static void
vl_api_match_set_add_t_handler (vl_api_match_set_add_t * mp, vlib_main_t * vm)
{
  vl_api_match_set_add_reply_t *rmp;
  match_orientation_t mo;
  ethernet_type_t etype;
  match_type_t mtype;
  index_t msi;
  u8 *name;
  int rv;

  rv = match_orientation_decode (mp->set.ms_orientation, &mo);
  rv |= match_type_decode (mp->set.ms_type, &mtype);
  rv |= ether_type_decode (mp->set.ms_ether_type, &etype);
  name = vl_api_from_api_to_new_vec (&mp->set.ms_tag);

  if (!rv)
    msi = match_set_create_and_lock (name, mtype, mo, etype, NULL);
  else
    msi = INDEX_INVALID;

  vec_free (name);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_MATCH_SET_ADD_REPLY,
  ({
    rmp->match_set_index = htonl (msi);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_match_set_delete_t_handler (vl_api_match_set_delete_t * mp,
				   vlib_main_t * vm)
{
  vl_api_match_set_delete_reply_t *rmp;
  index_t msi;
  int rv;

  rv = 0;
  msi = ntohl (mp->match_set_index);

  if (match_set_index_is_valid (msi))
    match_set_unlock (&msi);
  else
    rv = VNET_API_ERROR_NO_SUCH_ENTRY;

  REPLY_MACRO (VL_API_MATCH_SET_DELETE_REPLY);
}

static void
vl_api_match_set_list_update_t_handler (vl_api_match_set_list_update_t * mp,
					vlib_main_t * vm)
{
  vl_api_match_set_list_update_reply_t *rmp;
  match_handle_t mh;
  match_list_t ml;
  index_t msi;
  int rv;

  rv = 0;
  mh = ntohl (mp->match_list_index);
  msi = ntohl (mp->match_set_index);

  if (!match_set_index_is_valid (msi))
    rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  else
    {
      rv = match_list_decode (&mp->list, &ml);

      if (!rv)
	{
	  if (MATCH_HANDLE_INVALID == mh)
	    mh = match_set_list_add (msi, &ml, ntohl (mp->priority));
	  else
	    match_set_list_replace (msi, mh, &ml, ntohl (mp->priority));
	}
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_MATCH_SET_LIST_UPDATE_REPLY,
  ({
    rmp->match_list_index = htonl (mh);
  }));
  /* *INDENT-ON* */
}

typedef struct match_set_dump_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} match_set_dump_ctx_t;

static walk_rc_t
match_set_send_details (index_t msi, void *arg)
{
  match_set_dump_ctx_t *ctx = arg;
  vl_api_match_set_details_t *mp;
  match_set_t *ms;

  ms = match_set_get (msi);

  mp = vl_msg_api_alloc_zero (sizeof (*mp) + vec_len (ms->ms_tag));

  mp->_vl_msg_id = ntohs (VL_API_MATCH_SET_DETAILS + REPLY_MSG_ID_BASE);
  mp->context = ctx->context;


  mp->set.ms_index = clib_host_to_net_u32 (msi);
  mp->set.ms_type = match_type_encode (ms->ms_type);
  mp->set.ms_orientation = match_type_encode (ms->ms_orientation);
  mp->set.ms_ether_type = match_type_encode (ms->ms_eth_type);
  vl_api_vec_to_api_string (ms->ms_tag, &mp->set.ms_tag);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_match_set_dump_t_handler (vl_api_match_set_dump_t * mp,
				 vlib_main_t * vm)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  match_set_dump_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  match_sets_walk (match_set_send_details, &ctx);
}

static void
vl_api_match_set_list_delete_t_handler (vl_api_match_set_list_delete_t * mp,
					vlib_main_t * vm)
{
  vl_api_match_set_list_update_reply_t *rmp;
  match_handle_t mh;
  index_t msi;
  int rv;

  rv = 0;
  mh = ntohl (mp->match_list_index);
  msi = ntohl (mp->match_set_index);

  if (!match_set_index_is_valid (msi))
    rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  else
    match_set_list_del (msi, &mh);

  REPLY_MACRO (VL_API_MATCH_SET_LIST_DELETE_REPLY);
}

#include <vnet/match/match.api.c>

static clib_error_t *
match_api_init (vlib_main_t * vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (match_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
