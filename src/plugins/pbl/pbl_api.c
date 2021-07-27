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
#include <vnet/fib/fib_api.h>

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
  pbl_client_update_args_t _args = { 0 }, *args = &_args;
  vl_api_pbl_client_update_reply_t *rmp;
  pbl_client_port_map_proto_t proto;
  fib_route_path_t *rpath;
  ip_protocol_t iproto;
  int rv = 0;
  u32 ii, n_ports;
  u16 port_a, port_b;

  args->pci = clib_net_to_host_u32 (mp->client.id);
  ip_address_decode2 (&mp->client.addr, &args->addr);

  for (ii = 0; ii < PBL_CLIENT_PORT_MAP_N_PROTOS; ii++)
    {
      clib_bitmap_alloc (args->port_maps[ii], (1 << 16) - 1);
      clib_bitmap_zero (args->port_maps[ii]);
    }

  n_ports = clib_net_to_host_u32 (mp->client.n_ports);
  for (ii = 0; ii < n_ports; ii++)
    {
      port_a = clib_net_to_host_u16 (mp->client.port_ranges[ii].start);
      port_b = clib_net_to_host_u16 (mp->client.port_ranges[ii].end);
      port_b = clib_max (port_a, port_b);

      rv = ip_proto_decode (mp->client.port_ranges[ii].iproto, &iproto);
      if (rv)
	goto done;
      proto = pbl_iproto_to_port_map_proto (iproto);

      if (proto < PBL_CLIENT_PORT_MAP_N_PROTOS)
	clib_bitmap_set_region (args->port_maps[proto], port_a, 1,
				port_b - port_a + 1);
    }
  args->flags = mp->client.flags;
  args->table_id = clib_net_to_host_u32 (mp->client.table_id);

  vec_validate (args->rpaths, 0);
  rpath = &args->rpaths[0];

  rv = fib_api_path_decode (&mp->client.paths, rpath);
  if (rv)
    goto done;

  args->pci = pbl_client_update (args);

done:
  vec_free (args->rpaths);

  REPLY_MACRO2 (VL_API_PBL_CLIENT_UPDATE_REPLY,
		({ rmp->id = clib_host_to_net_u32 (args->pci); }));
}

static void
vl_api_pbl_client_del_t_handler (vl_api_pbl_client_del_t *mp)
{
  vl_api_pbl_client_del_reply_t *rmp;
  int rv;

  rv = pbl_client_delete (ntohl (mp->id));

  REPLY_MACRO (VL_API_PBL_CLIENT_DEL_REPLY);
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
  size_t msg_size;
  pbl_client_t *pc;

  ctx = args;
  pc = pbl_client_get (cti);
  msg_size = sizeof (*mp);

  mp = vl_msg_api_alloc_zero (msg_size);
  mp->_vl_msg_id = ntohs (VL_API_PBL_CLIENT_DETAILS + pbl_base_msg_id);

  mp->client.id = clib_host_to_net_u32 (cti);
  ip_address_encode2 (&pc->pc_addr, &mp->client.addr);
  mp->client.flags = clib_host_to_net_u32 (pc->flags);

  /* TODO : we miss routes & ports */

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
