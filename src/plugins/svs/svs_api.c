/*
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
 */

#include <stddef.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <svs/svs.h>
#include <vnet/fib/fib_api.h>
#include <vnet/ip/ip_types_api.h>

#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <svs/svs_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <svs/svs_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <svs/svs_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <svs/svs_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <svs/svs_all_api_h.h>
#undef vl_api_version

/**
 * Base message ID fot the plugin
 */
static u32 svs_base_msg_id;

#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */

#define foreach_svs_plugin_api_msg                    \
  _(SVS_PLUGIN_GET_VERSION, svs_plugin_get_version)   \
  _(SVS_TABLE_ADD_DEL, svs_table_add_del)             \
  _(SVS_ROUTE_ADD_DEL, svs_route_add_del)             \
  _(SVS_ENABLE_DISABLE, svs_enable_disable)           \
  _(SVS_DUMP, svs_dump)

static void
vl_api_svs_plugin_get_version_t_handler (vl_api_svs_plugin_get_version_t * mp)
{
  vl_api_svs_plugin_get_version_reply_t *rmp;
  int msg_size = sizeof (*rmp);
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  rmp = vl_msg_api_alloc (msg_size);
  memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_SVS_PLUGIN_GET_VERSION_REPLY + svs_base_msg_id);
  rmp->context = mp->context;
  rmp->major = htonl (SVS_PLUGIN_VERSION_MAJOR);
  rmp->minor = htonl (SVS_PLUGIN_VERSION_MINOR);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_svs_table_add_del_t_handler (vl_api_svs_table_add_del_t * mp)
{
  vl_api_svs_table_add_del_reply_t *rmp;
  fib_protocol_t fproto;
  int rv = 0;

  fproto = fib_proto_from_api_address_family (mp->af);

  if (mp->is_add)
    {
      rv = svs_table_add (fproto, ntohl (mp->table_id));
    }
  else
    {
      rv = svs_table_delete (fproto, ntohl (mp->table_id));
    }

  REPLY_MACRO (VL_API_SVS_TABLE_ADD_DEL_REPLY + svs_base_msg_id);
}

static void
vl_api_svs_route_add_del_t_handler (vl_api_svs_route_add_del_t * mp)
{
  vl_api_svs_route_add_del_reply_t *rmp;
  fib_prefix_t pfx;
  int rv = 0;

  ip_prefix_decode (&mp->prefix, &pfx);

  if (mp->is_add)
    {
      rv = svs_route_add (ntohl (mp->table_id), &pfx,
			  ntohl (mp->source_table_id));
    }
  else
    {
      rv = svs_route_delete (ntohl (mp->table_id), &pfx);
    }

  REPLY_MACRO (VL_API_SVS_ROUTE_ADD_DEL_REPLY + svs_base_msg_id);
}

static void
vl_api_svs_enable_disable_t_handler (vl_api_svs_enable_disable_t * mp)
{
  vl_api_svs_enable_disable_reply_t *rmp;
  fib_protocol_t fproto;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  fproto = fib_proto_from_api_address_family (mp->af);

  if (mp->is_enable)
    {
      rv = svs_enable (fproto, ntohl (mp->table_id), ntohl (mp->sw_if_index));
    }
  else
    {
      rv =
	svs_disable (fproto, ntohl (mp->table_id), ntohl (mp->sw_if_index));
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SVS_ENABLE_DISABLE_REPLY + svs_base_msg_id);
}

typedef struct svs_dump_walk_ctx_t_
{
  unix_shared_memory_queue_t *q;
  u32 context;
} svs_dump_walk_ctx_t;


static walk_rc_t
svs_send_details (fib_protocol_t fproto,
		  u32 table_id, u32 sw_if_index, void *args)
{
  vl_api_svs_details_t *mp;
  svs_dump_walk_ctx_t *ctx;

  ctx = args;

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SVS_DETAILS + svs_base_msg_id);

  mp->context = ctx->context;
  mp->sw_if_index = htonl (sw_if_index);
  mp->table_id = htonl (table_id);
  mp->af = fib_proto_to_api_address_family (fproto);

  vl_msg_api_send_shmem (ctx->q, (u8 *) & mp);

  return (WALK_CONTINUE);
}

static void
vl_api_svs_dump_t_handler (vl_api_svs_dump_t * mp)
{
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  svs_dump_walk_ctx_t ctx = {
    .q = q,
    .context = mp->context,
  };

  svs_walk (svs_send_details, &ctx);
}

#define vl_msg_name_crc_list
#include <svs/svs_all_api_h.h>
#undef vl_msg_name_crc_list

/* Set up the API message handling tables */
static clib_error_t *
svs_plugin_api_hookup (vlib_main_t * vm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + svs_base_msg_id),     \
                            #n,					\
                            vl_api_##n##_t_handler,             \
                            vl_noop_handler,                    \
                            vl_api_##n##_t_endian,              \
                            vl_api_##n##_t_print,               \
                            sizeof(vl_api_##n##_t), 1);
  foreach_svs_plugin_api_msg;
#undef _

  return 0;
}

static void
setup_message_id_table (api_main_t * apim)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (apim, #n "_" #crc, id + svs_base_msg_id);
  foreach_vl_msg_name_crc_svs;
#undef _
}

static clib_error_t *
svs_api_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  u8 *name = format (0, "svs_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  svs_base_msg_id = vl_msg_api_get_msg_ids ((char *) name,
					    VL_MSG_FIRST_AVAILABLE);

  error = svs_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (&api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (svs_api_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Source VRF Select",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
