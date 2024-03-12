/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/devices/pipe/pipe.h>

#include <vnet/format_fns.h>
#include <vnet/devices/pipe/pipe.api_enum.h>
#include <vnet/devices/pipe/pipe.api_types.h>

#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>
extern vpe_api_main_t vpe_api_main;

static u16 msg_id_base;

static void
vl_api_pipe_create_t_handler (vl_api_pipe_create_t * mp)
{
  vl_api_pipe_create_reply_t *rmp;
  u32 parent_sw_if_index;
  u32 pipe_sw_if_index[2];
  int rv;
  u8 is_specified = mp->is_specified;
  u32 user_instance = ntohl (mp->user_instance);

  rv = vnet_create_pipe_interface (is_specified, user_instance,
				   &parent_sw_if_index, pipe_sw_if_index);

  REPLY_MACRO2(VL_API_PIPE_CREATE_REPLY,
  ({
    rmp->sw_if_index = ntohl (parent_sw_if_index);
    rmp->pipe_sw_if_index[0] = ntohl (pipe_sw_if_index[0]);
    rmp->pipe_sw_if_index[1] = ntohl (pipe_sw_if_index[1]);
  }));
}

static void
vl_api_pipe_delete_t_handler (vl_api_pipe_delete_t * mp)
{
  vl_api_pipe_delete_reply_t *rmp;
  int rv;

  rv = vnet_delete_pipe_interface (ntohl (mp->sw_if_index));

  REPLY_MACRO (VL_API_PIPE_DELETE_REPLY);
}

typedef struct pipe_dump_walk_t_
{
  vl_api_registration_t *reg;
  u32 context;
} pipe_dump_walk_t;

static walk_rc_t
pipe_send_details (u32 parent_sw_if_index,
		   u32 pipe_sw_if_index[2], u32 instance, void *args)
{
  pipe_dump_walk_t *ctx = args;
  vl_api_pipe_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return (WALK_STOP);

  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_PIPE_DETAILS);
  mp->context = ctx->context;

  mp->instance = ntohl (instance);
  mp->sw_if_index = ntohl (parent_sw_if_index);
  mp->pipe_sw_if_index[0] = ntohl (pipe_sw_if_index[0]);
  mp->pipe_sw_if_index[1] = ntohl (pipe_sw_if_index[1]);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_pipe_dump_t_handler (vl_api_pipe_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pipe_dump_walk_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  pipe_walk (pipe_send_details, &ctx);
}

#include <vnet/devices/pipe/pipe.api.c>
static clib_error_t *
pipe_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (pipe_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
