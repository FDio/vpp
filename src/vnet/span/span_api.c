/*
 *------------------------------------------------------------------
 * span_api.c - span mirroring api
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
#include <vnet/span/span.h>

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

#define foreach_vpe_api_msg                             \
_(SW_INTERFACE_SPAN_ENABLE_DISABLE, sw_interface_span_enable_disable)   \
_(SW_INTERFACE_SPAN_DUMP, sw_interface_span_dump)                       \

static void
  vl_api_sw_interface_span_enable_disable_t_handler
  (vl_api_sw_interface_span_enable_disable_t * mp)
{
  vl_api_sw_interface_span_enable_disable_reply_t *rmp;
  int rv;

  vlib_main_t *vm = vlib_get_main ();

  rv = span_add_delete_entry (vm, ntohl (mp->sw_if_index_from),
			      ntohl (mp->sw_if_index_to), mp->state,
			      mp->is_l2 ? SPAN_FEAT_L2 : SPAN_FEAT_DEVICE);

  REPLY_MACRO (VL_API_SW_INTERFACE_SPAN_ENABLE_DISABLE_REPLY);
}

static void
vl_api_sw_interface_span_dump_t_handler (vl_api_sw_interface_span_dump_t * mp)
{

  vl_api_registration_t *reg;
  span_interface_t *si;
  vl_api_sw_interface_span_details_t *rmp;
  span_main_t *sm = &span_main;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  span_feat_t sf = mp->is_l2 ? SPAN_FEAT_L2 : SPAN_FEAT_DEVICE;
  /* *INDENT-OFF* */
  vec_foreach (si, sm->interfaces)
  {
    span_mirror_t * rxm = &si->mirror_rxtx[sf][VLIB_RX];
    span_mirror_t * txm = &si->mirror_rxtx[sf][VLIB_TX];
    if (rxm->num_mirror_ports || txm->num_mirror_ports)
    {
      clib_bitmap_t *b;
      u32 i;
      b = clib_bitmap_dup_or (rxm->mirror_ports, txm->mirror_ports);
      clib_bitmap_foreach (i, b, (
        {
          rmp = vl_msg_api_alloc (sizeof (*rmp));
          clib_memset (rmp, 0, sizeof (*rmp));
          rmp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_SPAN_DETAILS);
          rmp->context = mp->context;

          rmp->sw_if_index_from = htonl (si - sm->interfaces);
          rmp->sw_if_index_to = htonl (i);
          rmp->state = (u8) (clib_bitmap_get (rxm->mirror_ports, i) +
                             clib_bitmap_get (txm->mirror_ports, i) * 2);
	  rmp->is_l2 = mp->is_l2;

          vl_api_send_msg (reg, (u8 *) rmp);
        }));
      clib_bitmap_free (b);
    }
    }
  /* *INDENT-ON* */
}

/*
 * vpe_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
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
  foreach_vl_msg_name_crc_span;
#undef _
}

static clib_error_t *
span_api_hookup (vlib_main_t * vm)
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

VLIB_API_INIT_FUNCTION (span_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
