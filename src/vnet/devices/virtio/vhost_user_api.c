/*
 *------------------------------------------------------------------
 * vhost-user_api.c - vhost-user api
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
#include <vnet/devices/virtio/vhost_user.h>

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

#define foreach_vpe_api_msg                                             \
_(CREATE_VHOST_USER_IF, create_vhost_user_if)                           \
_(MODIFY_VHOST_USER_IF, modify_vhost_user_if)                           \
_(DELETE_VHOST_USER_IF, delete_vhost_user_if)                           \
_(SW_INTERFACE_VHOST_USER_DUMP, sw_interface_vhost_user_dump)

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
vl_api_create_vhost_user_if_t_handler (vl_api_create_vhost_user_if_t * mp)
{
  int rv = 0;
  vl_api_create_vhost_user_if_reply_t *rmp;
  u32 sw_if_index = (u32) ~ 0;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  u64 features = (u64) ~ (0ULL);
  u64 disabled_features = (u64) (0ULL);

  if (mp->disable_mrg_rxbuf)
    disabled_features = (1ULL << FEAT_VIRTIO_NET_F_MRG_RXBUF);

  if (mp->disable_indirect_desc)
    disabled_features |= (1ULL << FEAT_VIRTIO_F_INDIRECT_DESC);

  features &= ~disabled_features;

  rv = vhost_user_create_if (vnm, vm, (char *) mp->sock_filename,
			     mp->is_server, &sw_if_index, features,
			     mp->renumber, ntohl (mp->custom_dev_instance),
			     (mp->use_custom_mac) ? mp->mac_address : NULL);

  /* Remember an interface tag for the new interface */
  if (rv == 0)
    {
      /* If a tag was supplied... */
      if (mp->tag[0])
	{
	  /* Make sure it's a proper C-string */
	  mp->tag[ARRAY_LEN (mp->tag) - 1] = 0;
	  u8 *tag = format (0, "%s%c", mp->tag, 0);
	  vnet_set_sw_interface_tag (vnm, tag, sw_if_index);
	}
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_CREATE_VHOST_USER_IF_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_modify_vhost_user_if_t_handler (vl_api_modify_vhost_user_if_t * mp)
{
  int rv = 0;
  vl_api_modify_vhost_user_if_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();

  rv = vhost_user_modify_if (vnm, vm, (char *) mp->sock_filename,
			     mp->is_server, sw_if_index, (u64) ~ 0,
			     mp->renumber, ntohl (mp->custom_dev_instance));

  REPLY_MACRO (VL_API_MODIFY_VHOST_USER_IF_REPLY);
}

static void
vl_api_delete_vhost_user_if_t_handler (vl_api_delete_vhost_user_if_t * mp)
{
  int rv = 0;
  vl_api_delete_vhost_user_if_reply_t *rmp;
  vpe_api_main_t *vam = &vpe_api_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  vl_api_registration_t *reg;

  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();

  rv = vhost_user_delete_if (vnm, vm, sw_if_index);

  REPLY_MACRO (VL_API_DELETE_VHOST_USER_IF_REPLY);
  if (!rv)
    {
      reg = vl_api_client_index_to_registration (mp->client_index);
      if (!reg)
	return;

      vnet_clear_sw_interface_tag (vnm, sw_if_index);
      send_sw_interface_event_deleted (vam, reg, sw_if_index);
    }
}

static void
send_sw_interface_vhost_user_details (vpe_api_main_t * am,
				      vl_api_registration_t * reg,
				      vhost_user_intf_details_t * vui,
				      u32 context)
{
  vl_api_sw_interface_vhost_user_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_VHOST_USER_DETAILS);
  mp->sw_if_index = ntohl (vui->sw_if_index);
  mp->virtio_net_hdr_sz = ntohl (vui->virtio_net_hdr_sz);
  mp->features = clib_net_to_host_u64 (vui->features);
  mp->is_server = vui->is_server;
  mp->num_regions = ntohl (vui->num_regions);
  mp->sock_errno = ntohl (vui->sock_errno);
  mp->context = context;

  strncpy ((char *) mp->sock_filename,
	   (char *) vui->sock_filename, ARRAY_LEN (mp->sock_filename) - 1);
  strncpy ((char *) mp->interface_name,
	   (char *) vui->if_name, ARRAY_LEN (mp->interface_name) - 1);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
  vl_api_sw_interface_vhost_user_dump_t_handler
  (vl_api_sw_interface_vhost_user_dump_t * mp)
{
  int rv = 0;
  vpe_api_main_t *am = &vpe_api_main;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  vhost_user_intf_details_t *ifaces = NULL;
  vhost_user_intf_details_t *vuid = NULL;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rv = vhost_user_dump_ifs (vnm, vm, &ifaces);
  if (rv)
    return;

  vec_foreach (vuid, ifaces)
  {
    send_sw_interface_vhost_user_details (am, reg, vuid, mp->context);
  }
  vec_free (ifaces);
}

/*
 * vhost-user_api_hookup
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
  foreach_vl_msg_name_crc_vhost_user;
#undef _
}

static clib_error_t *
vhost_user_api_hookup (vlib_main_t * vm)
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

VLIB_API_INIT_FUNCTION (vhost_user_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
