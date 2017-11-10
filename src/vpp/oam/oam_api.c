/*
 *------------------------------------------------------------------
 * oam_api.c - vnet OAM api
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

#include <vpp/oam/oam.h>

#include <vpp/api/vpe_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs
#define vl_endianfun		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun
/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun
#include <vlibapi/api_helper_macros.h>

#define foreach_oam_api_msg                                             \
_(WANT_OAM_EVENTS, want_oam_events)                                     \
_(OAM_ADD_DEL, oam_add_del)

pub_sub_handler (oam_events, OAM_EVENTS);

void
send_oam_event (oam_target_t * t)
{
  vpe_api_main_t *vam = &vpe_api_main;
  unix_shared_memory_queue_t *q;
  vpe_client_registration_t *reg;
  vl_api_oam_event_t *mp;

  /* *INDENT-OFF* */
  pool_foreach(reg, vam->oam_events_registrations,
  ({
    q = vl_api_client_index_to_input_queue (reg->client_index);
    if (q)
      {
        mp = vl_msg_api_alloc (sizeof (*mp));
        mp->_vl_msg_id = ntohs (VL_API_OAM_EVENT);
        clib_memcpy (mp->dst_address, &t->dst_address,
                     sizeof (mp->dst_address));
        mp->state = t->state;
        vl_msg_api_send_shmem (q, (u8 *)&mp);
      }
  }));
  /* *INDENT-ON* */
}

static void
vl_api_oam_add_del_t_handler (vl_api_oam_add_del_t * mp)
{
  vl_api_oam_add_del_reply_t *rmp;
  int rv;

  rv = vpe_oam_add_del_target ((ip4_address_t *) mp->src_address,
			       (ip4_address_t *) mp->dst_address,
			       ntohl (mp->vrf_id), (int) (mp->is_add));

  REPLY_MACRO (VL_API_OAM_ADD_DEL_REPLY);
}

#define vl_msg_name_crc_list
#include <vpp/oam/oam.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_oam;
#undef _
}

static clib_error_t *
oam_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_oam_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (oam_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
