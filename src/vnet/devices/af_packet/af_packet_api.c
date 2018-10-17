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

#define foreach_vpe_api_msg                                          \
_(AF_PACKET_CREATE, af_packet_create)                                \
_(AF_PACKET_DELETE, af_packet_delete)                                \
_(AF_PACKET_SET_L4_CKSUM_OFFLOAD, af_packet_set_l4_cksum_offload)    \
_(AF_PACKET_DUMP, af_packet_dump)

static void
vl_api_af_packet_create_t_handler (vl_api_af_packet_create_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_af_packet_create_reply_t *rmp;
  int rv = 0;
  u8 *host_if_name = NULL;
  u32 sw_if_index;

  host_if_name = format (0, "%s", mp->host_if_name);
  vec_add1 (host_if_name, 0);

  rv = af_packet_create_if (vm, host_if_name,
			    mp->use_random_hw_addr ? 0 : mp->hw_addr,
			    &sw_if_index);

  vec_free (host_if_name);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_AF_PACKET_CREATE_REPLY,
  ({
    rmp->sw_if_index = clib_host_to_net_u32(sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_af_packet_delete_t_handler (vl_api_af_packet_delete_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_af_packet_delete_reply_t *rmp;
  int rv = 0;
  u8 *host_if_name = NULL;

  host_if_name = format (0, "%s", mp->host_if_name);
  vec_add1 (host_if_name, 0);

  rv = af_packet_delete_if (vm, host_if_name);

  vec_free (host_if_name);

  REPLY_MACRO (VL_API_AF_PACKET_DELETE_REPLY);
}

static void
  vl_api_af_packet_set_l4_cksum_offload_t_handler
  (vl_api_af_packet_set_l4_cksum_offload_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_af_packet_delete_reply_t *rmp;
  int rv = 0;

  rv = af_packet_set_l4_cksum_offload (vm, mp->sw_if_index, mp->set);
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
  mp->_vl_msg_id = htons (VL_API_AF_PACKET_DETAILS);
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

/*
 * af_packet_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_af_packet;
#undef _
}

static clib_error_t *
af_packet_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

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

VLIB_API_INIT_FUNCTION (af_packet_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
