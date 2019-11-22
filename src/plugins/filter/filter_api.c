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
#include <filter/filter_table.h>
#include <vnet/mpls/mpls_types.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_api.h>

#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <filter/filter.api_enum.h>
#include <filter/filter.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 filter_base_msg_id;

#include <vlibapi/api_helper_macros.h>


/* List of message types that this plugin understands */

#define foreach_filter_plugin_api_msg                     \
  _(FILTER_TABLE_ADD_DEL, filter_table_add_del)           \
  _(FILTER_TABLE_DUMP, filter_table_dump)                 \


static void
vl_api_filter_table_add_del_t_handler (vl_api_filter_table_add_del_t * mp)
{
  vl_api_filter_table_add_del_reply_t *rmp;
  //index_t fti;
  //u8 *name;
  int rv;

  /* name = vl_api_from_api_to_vec (&mp->table.name); */

  /* if (mp->is_add) */
  /*   rv = filter_table_update (name, ntohl (mp->table.precedence), &fti); */
  /* else */
  /*   rv = filter_table_delete (name); */
  rv = 0;

  //vec_free(name);

  REPLY_MACRO (VL_API_FILTER_TABLE_ADD_DEL_REPLY + filter_base_msg_id);
}

typedef struct filter_dump_walk_ctx_t_
{
  vl_api_registration_t *rp;
  u32 context;
} filter_dump_walk_ctx_t;

static int
filter_table_send_details (u32 api, void *args)
{
  /* fib_path_encode_ctx_t walk_ctx = { */
  /*   .rpaths = NULL, */
  /* }; */
  /* vl_api_filter_table_details_t *mp; */
  /* filter_dump_walk_ctx_t *ctx; */
  /* fib_route_path_t *rpath; */
  /* vl_api_fib_path_t *fp; */
  /* size_t msg_size; */
  /* filter_table_t *ap; */
  /* u8 n_paths; */

  /* ctx = args; */
  /* ap = filter_table_get (api); */
  /* n_paths = fib_path_list_get_n_paths (ap->ap_pl); */
  /* msg_size = sizeof (*mp) + sizeof (mp->table.paths[0]) * n_paths; */

  /* mp = vl_msg_api_alloc (msg_size); */
  /* clib_memset (mp, 0, msg_size); */
  /* mp->_vl_msg_id = ntohs (VL_API_FILTER_TABLE_DETAILS + filter_base_msg_id); */

  /* /\* fill in the message *\/ */
  /* mp->context = ctx->context; */
  /* mp->table.n_paths = n_paths; */
  /* mp->table.acl_index = htonl (ap->ap_acl); */
  /* mp->table.table_id = htonl (ap->ap_id); */

  /* fib_path_list_walk_w_ext (ap->ap_pl, NULL, fib_path_encode, &walk_ctx); */

  /* fp = mp->table.paths; */
  /* vec_foreach (rpath, walk_ctx.rpaths) */
  /* { */
  /*   fib_api_path_encode (rpath, fp); */
  /*   fp++; */
  /* } */

  /* vl_api_send_msg (ctx->rp, (u8 *) mp); */

  /* vec_free (walk_ctx.rpaths); */

  return (1);
}

static void
vl_api_filter_table_dump_t_handler (vl_api_filter_table_dump_t * mp)
{
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  filter_dump_walk_ctx_t ctx = {
    .rp = rp,
    .context = mp->context,
  };

  filter_table_walk (filter_table_send_details, &ctx);
}

#include <filter/filter.api.c>

static clib_error_t *
filter_api_init (vlib_main_t * vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  filter_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (filter_api_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "filter (nftables stylee)",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
