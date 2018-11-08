/*
 *------------------------------------------------------------------
 * tap_api.c - vnet tap device driver API support
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
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>
#include <vnet/unix/tuntap.h>
#include <vnet/unix/tapcli.h>

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

#define foreach_tap_api_msg                     \
_(TAP_CONNECT, tap_connect)                     \
_(TAP_MODIFY, tap_modify)                       \
_(TAP_DELETE, tap_delete)                       \
_(SW_INTERFACE_TAP_DUMP, sw_interface_tap_dump)

#define vl_msg_name_crc_list
#include <vnet/unix/tap.api.h>
#undef vl_msg_name_crc_list

/*
 * WARNING: replicated pending api refactor completion
 */
static void
send_sw_interface_event_deleted (vpe_api_main_t * am,
				 vl_api_registration_t * reg, u32 sw_if_index)
{
  vl_api_sw_interface_event_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_EVENT);
  mp->sw_if_index = ntohl (sw_if_index);

  mp->admin_up_down = 0;
  mp->link_up_down = 0;
  mp->deleted = 1;
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_tap_connect_t_handler (vl_api_tap_connect_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  int rv;
  vl_api_tap_connect_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  vl_api_registration_t *reg;
  u32 sw_if_index = (u32) ~ 0;
  u8 *tag;
  vnet_tap_connect_args_t _a, *ap = &_a;

  memset (ap, 0, sizeof (*ap));

  ap->intfc_name = mp->tap_name;
  if (!mp->use_random_mac)
    ap->hwaddr_arg = mp->mac_address;
  ap->renumber = mp->renumber;
  ap->sw_if_indexp = &sw_if_index;
  ap->custom_dev_instance = ntohl (mp->custom_dev_instance);
  if (mp->ip4_address_set)
    {
      ap->ip4_address = (ip4_address_t *) mp->ip4_address;
      ap->ip4_mask_width = mp->ip4_mask_width;
      ap->ip4_address_set = 1;
    }
  if (mp->ip6_address_set)
    {
      ap->ip6_address = (ip6_address_t *) mp->ip6_address;
      ap->ip6_mask_width = mp->ip6_mask_width;
      ap->ip6_address_set = 1;
    }

  rv = vnet_tap_connect_renumber (vm, ap);

  /* Add tag if supplied */
  if (rv == 0 && mp->tag[0])
    {
      mp->tag[ARRAY_LEN (mp->tag) - 1] = 0;
      tag = format (0, "%s%c", mp->tag, 0);
      vnet_set_sw_interface_tag (vnm, tag, sw_if_index);
    }

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_TAP_CONNECT_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  rmp->sw_if_index = ntohl (sw_if_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_tap_modify_t_handler (vl_api_tap_modify_t * mp)
{
  int rv;
  vl_api_tap_modify_reply_t *rmp;
  vl_api_registration_t *reg;
  u32 sw_if_index = (u32) ~ 0;
  vlib_main_t *vm = vlib_get_main ();
  vnet_tap_connect_args_t _a, *ap = &_a;

  memset (ap, 0, sizeof (*ap));

  ap->orig_sw_if_index = ntohl (mp->sw_if_index);
  ap->intfc_name = mp->tap_name;
  if (!mp->use_random_mac)
    ap->hwaddr_arg = mp->mac_address;
  ap->sw_if_indexp = &sw_if_index;
  ap->renumber = mp->renumber;
  ap->custom_dev_instance = ntohl (mp->custom_dev_instance);

  rv = vnet_tap_modify (vm, ap);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_TAP_MODIFY_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  rmp->sw_if_index = ntohl (sw_if_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_tap_delete_t_handler (vl_api_tap_delete_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  int rv;
  vpe_api_main_t *vam = &vpe_api_main;
  vl_api_tap_delete_reply_t *rmp;
  vl_api_registration_t *reg;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  rv = vnet_tap_delete (vm, sw_if_index);
  if (!rv)
    {
      vnet_main_t *vnm = vnet_get_main ();
      vnet_clear_sw_interface_tag (vnm, sw_if_index);
    }

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_TAP_DELETE_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);

  vl_api_send_msg (reg, (u8 *) rmp);

  if (!rv)
    send_sw_interface_event_deleted (vam, reg, sw_if_index);
}

static void
send_sw_interface_tap_details (vpe_api_main_t * am,
			       vl_api_registration_t * reg,
			       tapcli_interface_details_t * tap_if,
			       u32 context)
{
  vl_api_sw_interface_tap_details_t *mp;
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_TAP_DETAILS);
  mp->sw_if_index = ntohl (tap_if->sw_if_index);
  strncpy ((char *) mp->dev_name,
	   (char *) tap_if->dev_name, ARRAY_LEN (mp->dev_name) - 1);
  mp->context = context;

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_sw_interface_tap_dump_t_handler (vl_api_sw_interface_tap_dump_t * mp)
{
  int rv = 0;
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  tapcli_interface_details_t *tapifs = NULL;
  tapcli_interface_details_t *tap_if = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rv = vnet_tap_dump_ifs (&tapifs);
  if (rv)
    return;

  vec_foreach (tap_if, tapifs)
  {
    send_sw_interface_tap_details (am, reg, tap_if, mp->context);
  }

  vec_free (tapifs);
}

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_tap;
#undef _
}

static clib_error_t *
tap_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_tap_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (tap_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
