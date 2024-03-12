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

#include <urpf/urpf.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip_types_api.h>

#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <urpf/urpf.api_enum.h>
#include <urpf/urpf.api_types.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 urpf_base_msg_id;
#define REPLY_MSG_ID_BASE urpf_base_msg_id

#include <vlibapi/api_helper_macros.h>

static int
urpf_mode_decode (vl_api_urpf_mode_t in, urpf_mode_t * out)
{
  if (0)
    ;
#define _(a,b)                                  \
  else if (URPF_API_MODE_##a == in)             \
    {                                           \
      *out = URPF_MODE_##a;                     \
      return (0);                               \
    }
  foreach_urpf_mode
#undef _
    return (VNET_API_ERROR_INVALID_VALUE);
}

static void
vl_api_urpf_update_t_handler (vl_api_urpf_update_t * mp)
{
  vl_api_urpf_update_reply_t *rmp;
  ip_address_family_t af;
  urpf_mode_t mode;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = urpf_mode_decode (mp->mode, &mode);
  if (rv)
    goto done;

  rv = ip_address_family_decode (mp->af, &af);
  if (rv)
    goto done;

  rv = urpf_update (mode, htonl (mp->sw_if_index), af,
		    (mp->is_input ? VLIB_RX : VLIB_TX), 0);
  if (rv)
    goto done;

  BAD_SW_IF_INDEX_LABEL;
done:
  REPLY_MACRO (VL_API_URPF_UPDATE_REPLY);
}

static void
vl_api_urpf_update_v2_t_handler (vl_api_urpf_update_v2_t *mp)
{
  vl_api_urpf_update_reply_t *rmp;
  ip_address_family_t af;
  urpf_mode_t mode;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = urpf_mode_decode (mp->mode, &mode);
  if (rv)
    goto done;

  rv = ip_address_family_decode (mp->af, &af);

  if (rv)
    goto done;

  rv = urpf_update (mode, htonl (mp->sw_if_index), af,
		    (mp->is_input ? VLIB_RX : VLIB_TX), ntohl (mp->table_id));

  if (rv)
    goto done;

  BAD_SW_IF_INDEX_LABEL;
done:
  REPLY_MACRO (VL_API_URPF_UPDATE_V2_REPLY);
}

static void
send_urpf_interface_details (vpe_api_main_t *am, vl_api_registration_t *reg,
			     u32 context, const u32 sw_if_index,
			     const urpf_data_t *ud,
			     const ip_address_family_t af,
			     const vlib_dir_t dir)
{
  vl_api_urpf_interface_details_t *mp;

  mp = vl_msg_api_alloc_zero (sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_URPF_INTERFACE_DETAILS);
  mp->context = context;

  mp->sw_if_index = htonl (sw_if_index);
  mp->table_id = htonl (fib_table_get_table_id (
    ud->fib_index, (af == AF_IP4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6)));
  mp->af = (vl_api_address_family_t) af;
  mp->mode = (vl_api_urpf_mode_t) ud->mode;
  mp->is_input = (dir == VLIB_RX);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
send_urpf_interface (vpe_api_main_t *am, vl_api_registration_t *reg,
		     u32 context, const u32 sw_if_index)
{
  urpf_data_t *ud;
  vlib_dir_t dir;
  ip_address_family_t af;

  FOR_EACH_IP_ADDRESS_FAMILY (af)
  FOREACH_VLIB_DIR (dir)
  if (sw_if_index < vec_len (urpf_cfgs[af][dir]))
    {
      ud = &urpf_cfgs[af][dir][sw_if_index];
      if (ud->mode || ud->fib_index_is_custom)
	send_urpf_interface_details (am, reg, context, sw_if_index, ud, af,
				     dir);
    }
}

static void
vl_api_urpf_interface_dump_t_handler (vl_api_urpf_interface_dump_t *mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  vnet_interface_main_t *im = &vnet_main.interface_main;
  vnet_sw_interface_t *si;
  u32 sw_if_index = ~0;
  int __attribute__ ((unused)) rv = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  sw_if_index = ntohl (mp->sw_if_index);

  if (sw_if_index == ~0)
    {
      pool_foreach (si, im->sw_interfaces)
	{
	  send_urpf_interface (am, reg, mp->context, si->sw_if_index);
	}
      return;
    }
  VALIDATE_SW_IF_INDEX (mp);
  send_urpf_interface (am, reg, mp->context, sw_if_index);
  BAD_SW_IF_INDEX_LABEL;
}

#include <urpf/urpf.api.c>

static clib_error_t *
urpf_api_init (vlib_main_t * vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  urpf_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (urpf_api_init);

VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Unicast Reverse Path Forwarding (uRPF)",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
