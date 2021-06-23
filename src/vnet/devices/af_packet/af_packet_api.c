/*
 *------------------------------------------------------------------
 * af_packet_api.c - af-packet api
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

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/devices/af_packet/af_packet.h>

#include <vnet/format_fns.h>
#include <vnet/devices/af_packet/af_packet.api_enum.h>
#include <vnet/devices/af_packet/af_packet.api_types.h>

#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

static u16 msg_id_base;

static void
vl_api_af_packet_create_t_handler (vl_api_af_packet_create_t * mp)
{
  af_packet_create_if_arg_t _arg, *arg = &_arg;
  vl_api_af_packet_create_reply_t *rmp;
  int rv = 0;

  clib_memset (arg, 0, sizeof (*arg));

  arg->host_if_name = format (0, "%s", mp->host_if_name);
  vec_add1 (arg->host_if_name, 0);

  arg->hw_addr = mp->use_random_hw_addr ? 0 : mp->hw_addr;
  rv = af_packet_create_if (arg);

  vec_free (arg->host_if_name);

  REPLY_MACRO2 (VL_API_AF_PACKET_CREATE_REPLY, ({
		  rmp->sw_if_index = clib_host_to_net_u32 (arg->sw_if_index);
		}));
}

static void
vl_api_af_packet_create_v2_t_handler (vl_api_af_packet_create_v2_t *mp)
{
  af_packet_create_if_arg_t _arg, *arg = &_arg;
  vl_api_af_packet_create_v2_reply_t *rmp;
  int rv = 0;

  clib_memset (arg, 0, sizeof (*arg));

  arg->host_if_name = format (0, "%s", mp->host_if_name);
  vec_add1 (arg->host_if_name, 0);

  arg->rx_frame_size = clib_net_to_host_u32 (mp->rx_frame_size);
  arg->tx_frame_size = clib_net_to_host_u32 (mp->tx_frame_size);
  arg->rx_frames_per_block = clib_net_to_host_u32 (mp->rx_frames_per_block);
  arg->tx_frames_per_block = clib_net_to_host_u32 (mp->tx_frames_per_block);
  arg->hw_addr = mp->use_random_hw_addr ? 0 : mp->hw_addr;

  if (mp->num_rx_queues > 1)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  rv = af_packet_create_if (arg);

out:
  vec_free (arg->host_if_name);
  REPLY_MACRO2 (VL_API_AF_PACKET_CREATE_V2_REPLY, ({
		  rmp->sw_if_index = clib_host_to_net_u32 (arg->sw_if_index);
		}));
}

static void
vl_api_af_packet_delete_t_handler (vl_api_af_packet_delete_t * mp)
{
  vl_api_af_packet_delete_reply_t *rmp;
  int rv = 0;
  u8 *host_if_name = NULL;

  host_if_name = format (0, "%s", mp->host_if_name);
  vec_add1 (host_if_name, 0);

  rv = af_packet_delete_if (host_if_name);

  vec_free (host_if_name);

  REPLY_MACRO (VL_API_AF_PACKET_DELETE_REPLY);
}

static void
  vl_api_af_packet_set_l4_cksum_offload_t_handler
  (vl_api_af_packet_set_l4_cksum_offload_t * mp)
{
  vl_api_af_packet_delete_reply_t *rmp;
  int rv = 0;

  rv = af_packet_set_l4_cksum_offload (ntohl (mp->sw_if_index), mp->set);
  REPLY_MACRO (VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD_REPLY);
}

static void
af_packet_send_details (vpe_api_main_t * am,
			vl_api_registration_t * reg,
			af_packet_if_detail_t * af_packet_if, u32 context)
{
  vl_api_af_packet_details_t *mp;
  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = htons (REPLY_MSG_ID_BASE + VL_API_AF_PACKET_DETAILS);
  mp->sw_if_index = htonl (af_packet_if->sw_if_index);
  clib_memcpy (mp->host_if_name, af_packet_if->host_if_name,
	       MIN (ARRAY_LEN (mp->host_if_name) - 1,
		    strlen ((const char *) af_packet_if->host_if_name)));

  mp->context = context;
  vl_api_send_msg (reg, (u8 *) mp);
}


static void
vl_api_af_packet_dump_t_handler (vl_api_af_packet_dump_t * mp)
{
  int rv;
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  af_packet_if_detail_t *out_af_packet_ifs = NULL;
  af_packet_if_detail_t *af_packet_if = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rv = af_packet_dump_ifs (&out_af_packet_ifs);
  if (rv)
    return;

  vec_foreach (af_packet_if, out_af_packet_ifs)
  {
    af_packet_send_details (am, reg, af_packet_if, mp->context);
  }

  vec_free (out_af_packet_ifs);
}

#include <vnet/devices/af_packet/af_packet.api.c>
static clib_error_t *
af_packet_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (af_packet_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
