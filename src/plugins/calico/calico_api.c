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
#include <calico/calico.h>

#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_api.h>
#include <vnet/ip/ip_types_api.h>

#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <calico/calico.api_enum.h>
#include <calico/calico.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 calico_base_msg_id;

#define REPLY_MSG_ID_BASE calico_base_msg_id

#include <vlibapi/api_helper_macros.h>

static void
calico_endpoint_decode (const vl_api_calico_endpoint_t * in,
			calico_endpoint_t * out)
{
  ip_address_decode2 (&in->addr, &out->ce_ip);
  out->ce_port = clib_net_to_host_u16 (in->port);
}

static void
calico_endpoint_encode (const calico_endpoint_t * in,
			vl_api_calico_endpoint_t * out)
{
  ip_address_encode2 (&in->ce_ip, &out->addr);
  out->port = clib_net_to_host_u16 (in->ce_port);
}

static void
vl_api_calico_translate_update_t_handler (vl_api_calico_translate_update_t *
					  mp)
{
  vl_api_calico_translate_update_reply_t *rmp;
  calico_endpoint_t *paths = NULL, *path, vip;
  ip_protocol_t ip_proto;
  u32 id = ~0;
  int rv = 0;
  u8 pi;

  rv = ip_proto_decode (mp->translate.ip_proto, &ip_proto);

  if (rv)
    goto done;

  vec_validate (paths, mp->translate.n_paths - 1);

  for (pi = 0; pi < mp->translate.n_paths; pi++)
    {
      path = &paths[pi];
      calico_endpoint_decode (&mp->translate.paths[pi], path);
    }
  calico_endpoint_decode (&mp->translate.vip, &vip);

  id = calico_translate_update (&vip, ip_proto, paths);

  vec_free (paths);

done:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_CALICO_TRANSLATE_UPDATE_REPLY,
  ({
    rmp->id = htonl (id);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_calico_translate_del_t_handler (vl_api_calico_translate_del_t * mp)
{
  vl_api_calico_translate_del_reply_t *rmp;
  int rv;

  rv = calico_translate_delete (ntohl (mp->id));

  REPLY_MACRO (VL_API_CALICO_TRANSLATE_DEL_REPLY);
}

typedef struct calico_dump_walk_ctx_t_
{
  vl_api_registration_t *rp;
  u32 context;
} calico_dump_walk_ctx_t;

static walk_rc_t
calico_translate_send_details (u32 cti, void *args)
{
  vl_api_calico_translate_details_t *mp;
  calico_dump_walk_ctx_t *ctx;
  calico_ep_trk_t *trk;
  vl_api_calico_endpoint_t *vep;
  size_t msg_size;
  calico_translation_t *ct;
  u8 n_paths;

  ctx = args;
  ct = calico_translation_get (cti);
  n_paths = vec_len (ct->ct_paths);
  msg_size = sizeof (*mp) + sizeof (mp->translate.paths[0]) * n_paths;

  mp = vl_msg_api_alloc_zero (msg_size);
  mp->_vl_msg_id =
    ntohs (VL_API_CALICO_TRANSLATE_DETAILS + calico_base_msg_id);

  /* fill in the message */
  mp->context = ctx->context;
  mp->translate.n_paths = n_paths;
  mp->translate.id = htonl (cti);
  calico_endpoint_encode (&ct->ct_vip, &mp->translate.vip);
  mp->translate.ip_proto = ip_proto_encode (ct->ct_proto);

  vep = mp->translate.paths;
  vec_foreach (trk, ct->ct_paths)
  {
    calico_endpoint_encode (&trk->ct_ep, vep);
    vep++;
  }

  vl_api_send_msg (ctx->rp, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_calico_translate_dump_t_handler (vl_api_calico_translate_dump_t * mp)
{
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  calico_dump_walk_ctx_t ctx = {
    .rp = rp,
    .context = mp->context,
  };

  calico_translate_walk (calico_translate_send_details, &ctx);
}

static void
vl_api_calico_session_purge_t_handler (vl_api_calico_session_purge_t * mp)
{
  vl_api_calico_session_purge_reply_t *rmp;
  int rv;

  rv = calico_session_purge ();

  REPLY_MACRO (VL_API_CALICO_SESSION_PURGE_REPLY);
}

#include <calico/calico.api.c>

static clib_error_t *
calico_api_init (vlib_main_t * vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  calico_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (calico_api_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Calico Translate",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
