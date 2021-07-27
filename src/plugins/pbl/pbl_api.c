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
#include <pbl/pbl_client.h>

#include <vnet/ip/ip_types_api.h>

#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <pbl/pbl.api_enum.h>
#include <pbl/pbl.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 pbl_base_msg_id;

#define REPLY_MSG_ID_BASE pbl_base_msg_id

#include <vlibapi/api_helper_macros.h>

static void
vl_api_pbl_client_update_t_handler (vl_api_pbl_client_update_t *mp)
{
  vl_api_pbl_client_update_reply_t *rmp;
  fib_route_path_t *rpaths, *rpath;
  clib_bitmap_t *port_map;
  ip_address_t addr;
  u32 id = ~0;
  int rv = 0;
  u32 ii, n_ports, n_paths;
  u16 port_a, port_b;

  id = clib_net_to_host_u32 (mp->client.id);
  ip_address_decode2 (&mp->client.addr, &addr);

  clib_bitmap_alloc (port_map, (1 << 16) - 1);
  clib_bitmap_zero (port_map);

  n_ports = clib_net_to_host_u32 (mp->client.n_ports);
  for (ii = 0; ii < n_ports; ii++)
    {
      port_a = clib_net_to_host_u16 (mp->client.port_ranges[ii].start);
      port_b = clib_net_to_host_u16 (mp->client.port_ranges[ii].end);
      port_b = clib_max (port_a, port_b);
      clib_bitmap_set_region (port_map, port_a, 1, port_b - port_a + 1);
    }

  vec_validate (rpaths, 1);
  rpath = &rpaths[0];
  rv = fib_api_path_decode (&mp->client.paths, rpath);
  if (rv)
    goto out;

  id = pbl_client_update (id, &addr, port_map, mp->flags, rpaths);

done:
  vec_free (rpaths);

  REPLY_MACRO2 (VL_API_CNAT_TRANSLATION_UPDATE_REPLY,
		({ rmp->id = clib_host_to_net_u32 (id); }));
}

static void
vl_api_pbl_client_del_t_handler (vl_api_pbl_client_del_t *mp)
{
  vl_api_pbl_client_del_reply_t *rmp;
  int rv;

  rv = pbl_client_delete (ntohl (mp->id));

  REPLY_MACRO (VL_API_CNAT_TRANSLATION_DEL_REPLY);
}

typedef struct pbl_dump_walk_ctx_t_
{
  vl_api_registration_t *rp;
  u32 context;
} pbl_dump_walk_ctx_t;

static walk_rc_t
pbl_client_send_details (u32 cti, void *args)
{
  vl_api_pbl_client_details_t *mp;
  pbl_dump_walk_ctx_t *ctx;
  pbl_ep_trk_t *trk;
  vl_api_pbl_endpoint_tuple_t *path;
  size_t msg_size;
  pbl_client_t *ct;
  u32 n_paths;

  ctx = args;
  ct = pbl_client_get (cti);
  n_paths = vec_len (ct->ct_paths);
  msg_size = sizeof (*mp) + sizeof (mp->client.paths[0]) * n_paths;

  mp = vl_msg_api_alloc_zero (msg_size);
  mp->_vl_msg_id = ntohs (VL_API_CNAT_TRANSLATION_DETAILS + pbl_base_msg_id);

  /* fill in the message */
  mp->context = ctx->context;
  mp->client.n_paths = clib_host_to_net_u32 (n_paths);
  mp->client.id = clib_host_to_net_u32 (cti);
  pbl_endpoint_encode (&ct->ct_vip, &mp->client.vip);
  mp->client.ip_proto = ip_proto_encode (ct->ct_proto);
  mp->client.lb_type = (vl_api_pbl_lb_type_t) ct->lb_type;

  path = mp->client.paths;
  vec_foreach (trk, ct->ct_paths)
    {
      pbl_endpoint_encode (&trk->ct_ep[VLIB_TX], &path->dst_ep);
      pbl_endpoint_encode (&trk->ct_ep[VLIB_RX], &path->src_ep);
      path->flags = trk->ct_flags;
      path++;
    }

  vl_api_send_msg (ctx->rp, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_pbl_client_dump_t_handler (vl_api_pbl_client_dump_t *mp)
{
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  pbl_dump_walk_ctx_t ctx = {
    .rp = rp,
    .context = mp->context,
  };

  pbl_client_walk (pbl_client_send_details, &ctx);
}

#include <pbl/pbl.api.c>

static clib_error_t *
pbl_api_init (vlib_main_t *vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  pbl_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (pbl_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
