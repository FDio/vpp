/*
 *------------------------------------------------------------------
 * teib_api.c - teib api
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/api_errno.h>
#include <vnet/teib/teib.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/fib/fib_table.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <vnet/teib/teib.api_enum.h>
#include <vnet/teib/teib.api_types.h>

static u32 teib_base_msg_id;
#define REPLY_MSG_ID_BASE teib_base_msg_id

#include <vlibapi/api_helper_macros.h>

static void
vl_api_teib_entry_add_del_t_handler (vl_api_teib_entry_add_del_t * mp)
{
  vl_api_teib_entry_add_del_reply_t *rmp;
  ip_address_t peer, nh;
  int rv;

  VALIDATE_SW_IF_INDEX ((&mp->entry));

  ip_address_decode2 (&mp->entry.peer, &peer);
  ip_address_decode2 (&mp->entry.nh, &nh);

  if (mp->is_add)
    rv = teib_entry_add (ntohl (mp->entry.sw_if_index),
			 &peer, ntohl (mp->entry.nh_table_id), &nh);
  else
    rv = teib_entry_del (ntohl (mp->entry.sw_if_index), &peer);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_TEIB_ENTRY_ADD_DEL_REPLY);
}

typedef struct vl_api_teib_send_t_
{
  vl_api_registration_t *reg;
  u32 context;
} vl_api_teib_send_t;

static walk_rc_t
vl_api_teib_send_one (index_t nei, void *arg)
{
  vl_api_teib_details_t *mp;
  vl_api_teib_send_t *ctx = arg;
  const teib_entry_t *ne;
  const fib_prefix_t *pfx;

  mp = vl_msg_api_alloc_zero (sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_TEIB_DETAILS + REPLY_MSG_ID_BASE);
  mp->context = ctx->context;

  ne = teib_entry_get (nei);
  pfx = teib_entry_get_nh (ne);

  ip_address_encode2 (teib_entry_get_peer (ne), &mp->entry.peer);
  ip_address_encode (&pfx->fp_addr, IP46_TYPE_ANY, &mp->entry.nh);
  mp->entry.nh_table_id =
    htonl (fib_table_get_table_id
	   (teib_entry_get_fib_index (ne), pfx->fp_proto));
  mp->entry.sw_if_index = htonl (teib_entry_get_sw_if_index (ne));

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_teib_dump_t_handler (vl_api_teib_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vl_api_teib_send_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  teib_walk (vl_api_teib_send_one, &ctx);
}

/*
 * teib_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#include <vnet/teib/teib.api.c>

static clib_error_t *
teib_api_hookup (vlib_main_t * vm)
{
  teib_base_msg_id = setup_message_id_table ();

  return (NULL);
}

VLIB_API_INIT_FUNCTION (teib_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
