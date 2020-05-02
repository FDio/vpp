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
#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>
extern vpe_api_main_t vpe_api_main;

#define foreach_vpe_api_msg                                     \
  _(PIPE_CREATE, pipe_create)                                   \
  _(PIPE_DELETE, pipe_delete)                                   \
  _(PIPE_DUMP,   pipe_dump)

static void
vl_api_pipe_create_t_handler (vl_api_pipe_create_t * mp)
{
  vl_api_pipe_create_reply_t *rmp;
  u32 parent_sw_if_index;
  u32 pipe_sw_if_index[2];
  int rv;
  bool is_specified;
  u32 user_instance = ntohl (mp->user_instance);

  is_specified = (user_instance != ~0);

  rv = vnet_create_pipe_interface (is_specified, user_instance,
				   &parent_sw_if_index, pipe_sw_if_index);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_PIPE_CREATE_REPLY,
  ({
    rmp->sw_if_index = ntohl (parent_sw_if_index);
    rmp->pipe_sw_if_index[0] = ntohl (pipe_sw_if_index[0]);
    rmp->pipe_sw_if_index[1] = ntohl (pipe_sw_if_index[1]);
  }));
  /* *INDENT-ON* */
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
  u32 scope;			/* specific sw_if_index or ~0 for all */
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

  mp->_vl_msg_id = ntohs (VL_API_PIPE_DETAILS);
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
    .scope = ntohl (mp->sw_if_index)
  };

  pipe_walk (pipe_send_details, &ctx);
}

/*
 * vpe_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/devices/pipe/pipe.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_pipe;
#undef _
}

static clib_error_t *
pipe_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

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
