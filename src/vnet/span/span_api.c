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
span_dump (u32 client_index, u32 context, span_feat_t sf, int is_v2)
{

  vl_api_registration_t *reg;
  span_interface_t *si;
  span_main_t *sm = &span_main;
  int size;
  int id;
  union
  {
    vl_api_sw_interface_span_details_t v1;
    vl_api_sw_interface_span_v2_details_t v2;
  } * rmp;

  reg = vl_api_client_index_to_registration (client_index);
  if (!reg)
    return;

  if (is_v2)
    {
      size = sizeof (rmp->v1);
      id = VL_API_SW_INTERFACE_SPAN_V2_DETAILS;
    }
  else
    {
      size = sizeof (rmp->v2);
      id = VL_API_SW_INTERFACE_SPAN_DETAILS;
    }

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
	  rmp = vl_msg_api_alloc (size);
	  clib_memset (rmp, 0, size);
	  rmp->v1._vl_msg_id = ntohs (REPLY_MSG_ID_BASE + id);
	  rmp->v1.context = context;

	  rmp->v1.sw_if_index_from = htonl (si - sm->interfaces);
	  rmp->v1.sw_if_index_to = htonl (i);
	  rmp->v1.state = htonl ((clib_bitmap_get (rxm->mirror_ports, i) +
				  clib_bitmap_get (txm->mirror_ports, i) * 2));
	  if (is_v2)
	    rmp->v2.type = htonl (sf);
	  else
	    rmp->v1.is_l2 = SPAN_FEAT_L2 == sf;

	  vl_api_send_msg (reg, (u8 *) rmp);
	}
      clib_bitmap_free (b);
    }
    }
}

static void
vl_api_sw_interface_span_dump_t_handler (vl_api_sw_interface_span_dump_t *mp)
{
  span_dump (mp->client_index, mp->context,
	     mp->is_l2 ? SPAN_FEAT_L2 : SPAN_FEAT_DEVICE, 0 /* is_v2 */);
}

STATIC_ASSERT ((int) SPAN_FEAT_DEVICE == (int) SPAN_TYPE_API_DEVICE,
	       "wrong value");
STATIC_ASSERT ((int) SPAN_FEAT_L2 == (int) SPAN_TYPE_API_L2, "wrong value");
STATIC_ASSERT ((int) SPAN_FEAT_IP4 == (int) SPAN_TYPE_API_IP4, "wrong value");
STATIC_ASSERT ((int) SPAN_FEAT_IP6 == (int) SPAN_TYPE_API_IP6, "wrong value");

static void
vl_api_sw_interface_span_v2_enable_disable_t_handler (
  vl_api_sw_interface_span_v2_enable_disable_t *mp)
{
  vl_api_sw_interface_span_v2_enable_disable_reply_t *rmp;
  int rv;

  vlib_main_t *vm = vlib_get_main ();

  rv = span_add_delete_entry (vm, ntohl (mp->sw_if_index_from),
			      ntohl (mp->sw_if_index_to), ntohl (mp->state),
			      ntohl (mp->type));

  REPLY_MACRO (VL_API_SW_INTERFACE_SPAN_V2_ENABLE_DISABLE_REPLY);
}

static void
vl_api_sw_interface_span_v2_dump_t_handler (
  vl_api_sw_interface_span_v2_dump_t *mp)
{
  span_dump (mp->client_index, mp->context, ntohl (mp->type), 1 /* is_v2 */);
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
