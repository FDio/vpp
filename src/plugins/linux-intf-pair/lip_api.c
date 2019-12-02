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

#include <stddef.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <linux-intf-pair/lip.h>

#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <linux-intf-pair/lip.api_enum.h>
#include <linux-intf-pair/lip.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 lip_base_msg_id;

#include <vlibapi/api_helper_macros.h>

static void
vl_api_lip_plugin_get_version_t_handler (vl_api_lip_plugin_get_version_t * mp)
{
  vl_api_lip_plugin_get_version_reply_t *rmp;
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_LIP_PLUGIN_GET_VERSION_REPLY + lip_base_msg_id);
  rmp->context = mp->context;
  rmp->major = htonl (LIP_PLUGIN_VERSION_MAJOR);
  rmp->minor = htonl (LIP_PLUGIN_VERSION_MINOR);

  vl_api_send_msg (rp, (u8 *) rmp);
}

static void
vl_api_lip_add_del_t_handler (vl_api_lip_add_del_t * mp)
{
  u32 host_sw_if_index, phy_sw_if_index;
  vl_api_lip_add_del_reply_t *rmp;
  int rv = 0;

  host_sw_if_index = ntohl (mp->pair.host_sw_if_index);
  phy_sw_if_index = ntohl (mp->pair.phy_sw_if_index);

  if (!vnet_sw_if_index_is_api_valid (host_sw_if_index) ||
      !vnet_sw_if_index_is_api_valid (phy_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto bad_sw_if_index;
    }

  if (mp->is_add)
    rv = lip_add (host_sw_if_index, phy_sw_if_index);
  else
    rv = lip_delete (host_sw_if_index);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_LIP_ADD_DEL_REPLY + lip_base_msg_id);
}

typedef struct lip_dump_walk_ctx_t_
{
  vl_api_registration_t *rp;
  u32 context;
} lip_dump_walk_ctx_t;

static walk_rc_t
lip_send_details (index_t lipi, void *args)
{
  vl_api_lip_details_t *mp;
  lip_dump_walk_ctx_t *ctx;
  lip_t *lip;

  ctx = args;
  lip = lip_get (lipi);

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_LIP_DETAILS + lip_base_msg_id);

  /* fill in the message */
  mp->context = ctx->context;
  mp->pair.host_sw_if_index = htonl (lip->lip_host_sw_if_index);
  mp->pair.phy_sw_if_index = htonl (lip->lip_phy_sw_if_index);

  vl_api_send_msg (ctx->rp, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_lip_dump_t_handler (vl_api_lip_dump_t * mp)
{
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  lip_dump_walk_ctx_t ctx = {
    .rp = rp,
    .context = mp->context,
  };

  lip_walk (lip_send_details, &ctx);
}

#include <linux-intf-pair/lip.api.c>

static clib_error_t *
lip_api_init (vlib_main_t * vm)
{
  /* Add our API messages to the global name_crc hash table */
  lip_base_msg_id = setup_message_id_table ();

  return (NULL);
}

VLIB_INIT_FUNCTION (lip_api_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Linux Host Interface Pairing",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
