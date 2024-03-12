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

#include <vnet/format_fns.h>
#include <vnet/span/span.api_enum.h>
#include <vnet/span/span.api_types.h>

#define REPLY_MSG_ID_BASE span_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
  vl_api_sw_interface_span_enable_disable_t_handler
  (vl_api_sw_interface_span_enable_disable_t * mp)
{
  vl_api_sw_interface_span_enable_disable_reply_t *rmp;
  int rv;

  vlib_main_t *vm = vlib_get_main ();

  rv = span_add_delete_entry (vm, ntohl (mp->sw_if_index_from),
			      ntohl (mp->sw_if_index_to), ntohl (mp->state),
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
  vec_foreach (si, sm->interfaces)
  {
    span_mirror_t * rxm = &si->mirror_rxtx[sf][VLIB_RX];
    span_mirror_t * txm = &si->mirror_rxtx[sf][VLIB_TX];
    if (rxm->num_mirror_ports || txm->num_mirror_ports)
    {
      clib_bitmap_t *b;
      u32 i;
      b = clib_bitmap_dup_or (rxm->mirror_ports, txm->mirror_ports);
      clib_bitmap_foreach (i, b)
        {
          rmp = vl_msg_api_alloc (sizeof (*rmp));
          clib_memset (rmp, 0, sizeof (*rmp));
	  rmp->_vl_msg_id =
	    ntohs (REPLY_MSG_ID_BASE + VL_API_SW_INTERFACE_SPAN_DETAILS);
	  rmp->context = mp->context;

	  rmp->sw_if_index_from = htonl (si - sm->interfaces);
	  rmp->sw_if_index_to = htonl (i);
	  rmp->state = htonl ((clib_bitmap_get (rxm->mirror_ports, i) +
			       clib_bitmap_get (txm->mirror_ports, i) * 2));
	  rmp->is_l2 = mp->is_l2;

          vl_api_send_msg (reg, (u8 *) rmp);
        }
      clib_bitmap_free (b);
    }
    }
}

#include <vnet/span/span.api.c>
static clib_error_t *
span_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

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
