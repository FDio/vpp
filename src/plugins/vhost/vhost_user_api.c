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
#include <vhost/vhost_user.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/ethernet_types_api.h>

#include <vnet/format_fns.h>
#include <vhost/vhost_user.api_enum.h>
#include <vhost/vhost_user.api_types.h>

#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

static u16 msg_id_base;

static void
vl_api_create_vhost_user_if_t_handler (vl_api_create_vhost_user_if_t * mp)
{
  int rv = 0;
  vl_api_create_vhost_user_if_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  u64 disabled_features = (u64) (0ULL);
  vhost_user_create_if_args_t args = { 0 };

  args.sw_if_index = (u32) ~ 0;
  args.feature_mask = (u64) ~ (0ULL);
  if (mp->disable_mrg_rxbuf)
    disabled_features = VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF);

  if (mp->disable_indirect_desc)
    disabled_features |= VIRTIO_FEATURE (VIRTIO_RING_F_INDIRECT_DESC);

  /*
   * GSO and PACKED are not supported by feature mask via binary API. We
   * disable GSO and PACKED feature in the feature mask. They may be enabled
   * explicitly via enable_gso and enable_packed argument
   */
  disabled_features |= FEATURE_VIRTIO_NET_F_HOST_GUEST_TSO_FEATURE_BITS |
    VIRTIO_FEATURE (VIRTIO_F_RING_PACKED);

  /* EVENT_IDX is disabled by default */
  disabled_features |= VIRTIO_FEATURE (VIRTIO_RING_F_EVENT_IDX);
  args.feature_mask &= ~disabled_features;

  if (mp->use_custom_mac)
    mac_address_decode (mp->mac_address, (mac_address_t *) args.hwaddr);

  args.use_custom_mac = mp->use_custom_mac;
  args.is_server = mp->is_server;
  args.sock_filename = (char *) mp->sock_filename;
  args.renumber = mp->renumber;
  args.custom_dev_instance = ntohl (mp->custom_dev_instance);
  args.enable_gso = mp->enable_gso;
  args.enable_packed = mp->enable_packed;
  rv = vhost_user_create_if (vnm, vm, &args);

  /* Remember an interface tag for the new interface */
  if (rv == 0)
    {
      /* If a tag was supplied... */
      if (mp->tag[0])
	{
	  /* Make sure it's a proper C-string */
	  mp->tag[ARRAY_LEN (mp->tag) - 1] = 0;
	  u8 *tag = format (0, "%s%c", mp->tag, 0);
	  vnet_set_sw_interface_tag (vnm, tag, args.sw_if_index);
	}
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_CREATE_VHOST_USER_IF_REPLY,
  ({
    rmp->sw_if_index = ntohl (args.sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_modify_vhost_user_if_t_handler (vl_api_modify_vhost_user_if_t * mp)
{
  int rv = 0;
  vl_api_modify_vhost_user_if_reply_t *rmp;
  u64 disabled_features = (u64) (0ULL);
  vhost_user_create_if_args_t args = { 0 };
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();

  args.feature_mask = (u64) ~ (0ULL);
  /*
   * GSO and PACKED are not supported by feature mask via binary API. We
   * disable GSO and PACKED feature in the feature mask. They may be enabled
   * explicitly via enable_gso and enable_packed argument
   */
  disabled_features |= FEATURE_VIRTIO_NET_F_HOST_GUEST_TSO_FEATURE_BITS |
    VIRTIO_FEATURE (VIRTIO_F_RING_PACKED);

  /* EVENT_IDX is disabled by default */
  disabled_features |= VIRTIO_FEATURE (VIRTIO_RING_F_EVENT_IDX);
  args.feature_mask &= ~disabled_features;

  args.sw_if_index = ntohl (mp->sw_if_index);
  args.sock_filename = (char *) mp->sock_filename;
  args.is_server = mp->is_server;
  args.renumber = mp->renumber;
  args.custom_dev_instance = ntohl (mp->custom_dev_instance);
  args.enable_gso = mp->enable_gso;
  args.enable_packed = mp->enable_packed;
  rv = vhost_user_modify_if (vnm, vm, &args);

  REPLY_MACRO (VL_API_MODIFY_VHOST_USER_IF_REPLY);
}

static void
vl_api_create_vhost_user_if_v2_t_handler (vl_api_create_vhost_user_if_v2_t *
					  mp)
{
  int rv = 0;
  vl_api_create_vhost_user_if_v2_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  u64 disabled_features = (u64) (0ULL);
  vhost_user_create_if_args_t args = { 0 };

  args.sw_if_index = (u32) ~ 0;
  args.feature_mask = (u64) ~ (0ULL);
  if (mp->disable_mrg_rxbuf)
    disabled_features = VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF);

  if (mp->disable_indirect_desc)
    disabled_features |= VIRTIO_FEATURE (VIRTIO_RING_F_INDIRECT_DESC);

  /*
   * GSO and PACKED are not supported by feature mask via binary API. We
   * disable GSO and PACKED feature in the feature mask. They may be enabled
   * explicitly via enable_gso and enable_packed argument
   */
  disabled_features |= FEATURE_VIRTIO_NET_F_HOST_GUEST_TSO_FEATURE_BITS |
    VIRTIO_FEATURE (VIRTIO_F_RING_PACKED);

  /* EVENT_IDX is disabled by default */
  disabled_features |= VIRTIO_FEATURE (VIRTIO_RING_F_EVENT_IDX);
  args.feature_mask &= ~disabled_features;

  if (mp->use_custom_mac)
    mac_address_decode (mp->mac_address, (mac_address_t *) args.hwaddr);

  args.use_custom_mac = mp->use_custom_mac;
  args.is_server = mp->is_server;
  args.sock_filename = (char *) mp->sock_filename;
  args.renumber = mp->renumber;
  args.custom_dev_instance = ntohl (mp->custom_dev_instance);
  args.enable_gso = mp->enable_gso;
  args.enable_packed = mp->enable_packed;
  args.enable_event_idx = mp->enable_event_idx;
  rv = vhost_user_create_if (vnm, vm, &args);

  /* Remember an interface tag for the new interface */
  if (rv == 0)
    {
      /* If a tag was supplied... */
      if (mp->tag[0])
	{
	  /* Make sure it's a proper C-string */
	  mp->tag[ARRAY_LEN (mp->tag) - 1] = 0;
	  u8 *tag = format (0, "%s%c", mp->tag, 0);
	  vnet_set_sw_interface_tag (vnm, tag, args.sw_if_index);
	}
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_CREATE_VHOST_USER_IF_V2_REPLY,
  ({
    rmp->sw_if_index = ntohl (args.sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_modify_vhost_user_if_v2_t_handler (vl_api_modify_vhost_user_if_v2_t *
					  mp)
{
  int rv = 0;
  vl_api_modify_vhost_user_if_v2_reply_t *rmp;
  u64 disabled_features = (u64) (0ULL);
  vhost_user_create_if_args_t args = { 0 };
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();

  args.feature_mask = (u64) ~ (0ULL);
  /*
   * GSO and PACKED are not supported by feature mask via binary API. We
   * disable GSO and PACKED feature in the feature mask. They may be enabled
   * explicitly via enable_gso and enable_packed argument
   */
  disabled_features |= FEATURE_VIRTIO_NET_F_HOST_GUEST_TSO_FEATURE_BITS |
    VIRTIO_FEATURE (VIRTIO_F_RING_PACKED);

  /* EVENT_IDX is disabled by default */
  disabled_features |= VIRTIO_FEATURE (VIRTIO_RING_F_EVENT_IDX);
  args.feature_mask &= ~disabled_features;

  args.sw_if_index = ntohl (mp->sw_if_index);
  args.sock_filename = (char *) mp->sock_filename;
  args.is_server = mp->is_server;
  args.renumber = mp->renumber;
  args.custom_dev_instance = ntohl (mp->custom_dev_instance);
  args.enable_gso = mp->enable_gso;
  args.enable_packed = mp->enable_packed;
  args.enable_event_idx = mp->enable_event_idx;
  rv = vhost_user_modify_if (vnm, vm, &args);

  REPLY_MACRO (VL_API_MODIFY_VHOST_USER_IF_V2_REPLY);
}

static void
vl_api_delete_vhost_user_if_t_handler (vl_api_delete_vhost_user_if_t * mp)
{
  int rv = 0;
  vl_api_delete_vhost_user_if_reply_t *rmp;
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
    }
}

static void
vhost_user_features_encode (u64 features, u32 *first, u32 *last)
{
  *first = clib_net_to_host_u32 (features);
  *last = clib_net_to_host_u32 (features >> 32);
}

static void
send_sw_interface_vhost_user_details (vpe_api_main_t * am,
				      vl_api_registration_t * reg,
				      vhost_user_intf_details_t * vui,
				      u32 context)
{
  vl_api_sw_interface_vhost_user_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id =
    ntohs (REPLY_MSG_ID_BASE + VL_API_SW_INTERFACE_VHOST_USER_DETAILS);
  mp->sw_if_index = ntohl (vui->sw_if_index);
  mp->virtio_net_hdr_sz = ntohl (vui->virtio_net_hdr_sz);
  vhost_user_features_encode (vui->features, (u32 *) &mp->features_first_32,
			      (u32 *) &mp->features_last_32);
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
  u32 filter_sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  filter_sw_if_index = htonl (mp->sw_if_index);
  if (filter_sw_if_index != ~0)
    VALIDATE_SW_IF_INDEX (mp);

  rv = vhost_user_dump_ifs (vnm, vm, &ifaces);
  if (rv)
    return;

  vec_foreach (vuid, ifaces)
  {
    if ((filter_sw_if_index == ~0) ||
	(vuid->sw_if_index == filter_sw_if_index))
      send_sw_interface_vhost_user_details (am, reg, vuid, mp->context);
  }
  BAD_SW_IF_INDEX_LABEL;
  vec_free (ifaces);
}

#include <vhost/vhost_user.api.c>
static clib_error_t *
vhost_user_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();
  /* Mark CREATE_VHOST_USER_IF as mp safe */
  vl_api_set_msg_thread_safe (am, VL_API_CREATE_VHOST_USER_IF, 1);
  vl_api_set_msg_thread_safe (am, VL_API_CREATE_VHOST_USER_IF_V2, 1);

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

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
