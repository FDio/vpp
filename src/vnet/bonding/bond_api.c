/*
 *------------------------------------------------------------------
 * bond_api.c - vnet bonding device driver API support
 *
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vnet/ethernet/ethernet_types_api.h>
#include <vnet/bonding/node.h>

#include <vnet/format_fns.h>
#include <vnet/bonding/bond.api_enum.h>
#include <vnet/bonding/bond.api_types.h>

#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

static u16 msg_id_base;

static void
vl_api_bond_delete_t_handler (vl_api_bond_delete_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  int rv;
  vl_api_bond_delete_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  rv = bond_delete_if (vm, sw_if_index);

  REPLY_MACRO (VL_API_BOND_DELETE_REPLY);
}

static void
vl_api_bond_create_t_handler (vl_api_bond_create_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_bond_create_reply_t *rmp;
  bond_create_if_args_t _a, *ap = &_a;

  clib_memset (ap, 0, sizeof (*ap));

  ap->id = ntohl (mp->id);

  if (mp->use_custom_mac)
    {
      mac_address_decode (mp->mac_address, (mac_address_t *) ap->hw_addr);
      ap->hw_addr_set = 1;
    }

  ap->mode = ntohl (mp->mode);
  ap->lb = ntohl (mp->lb);
  ap->numa_only = mp->numa_only;
  bond_create_if (vm, ap);

  int rv = ap->rv;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_BOND_CREATE_REPLY,
  ({
    rmp->sw_if_index = ntohl (ap->sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_bond_create2_t_handler (vl_api_bond_create2_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_bond_create2_reply_t *rmp;
  bond_create_if_args_t _a, *ap = &_a;

  clib_memset (ap, 0, sizeof (*ap));

  ap->id = ntohl (mp->id);

  if (mp->use_custom_mac)
    {
      mac_address_decode (mp->mac_address, (mac_address_t *) ap->hw_addr);
      ap->hw_addr_set = 1;
    }

  ap->mode = ntohl (mp->mode);
  ap->lb = ntohl (mp->lb);
  ap->numa_only = mp->numa_only;
  ap->gso = mp->enable_gso;
  bond_create_if (vm, ap);

  int rv = ap->rv;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_BOND_CREATE2_REPLY,
  ({
    rmp->sw_if_index = ntohl (ap->sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_bond_add_member_t_handler (vl_api_bond_add_member_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_bond_add_member_reply_t *rmp;
  bond_add_member_args_t _a, *ap = &_a;
  int rv = 0;

  clib_memset (ap, 0, sizeof (*ap));

  ap->group = ntohl (mp->bond_sw_if_index);
  VALIDATE_SW_IF_INDEX (mp);
  ap->member = ntohl (mp->sw_if_index);
  ap->is_passive = mp->is_passive;
  ap->is_long_timeout = mp->is_long_timeout;

  bond_add_member (vm, ap);
  rv = ap->rv;

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_BOND_ADD_MEMBER_REPLY);
}

static void
vl_api_bond_enslave_t_handler (vl_api_bond_enslave_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_bond_enslave_reply_t *rmp;
  bond_add_member_args_t _a, *ap = &_a;
  int rv = 0;

  clib_memset (ap, 0, sizeof (*ap));

  ap->group = ntohl (mp->bond_sw_if_index);
  VALIDATE_SW_IF_INDEX (mp);
  ap->member = ntohl (mp->sw_if_index);
  ap->is_passive = mp->is_passive;
  ap->is_long_timeout = mp->is_long_timeout;

  bond_add_member (vm, ap);
  rv = ap->rv;

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_BOND_ENSLAVE_REPLY);
}

static void
  vl_api_sw_interface_set_bond_weight_t_handler
  (vl_api_sw_interface_set_bond_weight_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  bond_set_intf_weight_args_t _a, *ap = &_a;
  vl_api_sw_interface_set_bond_weight_reply_t *rmp;
  int rv = 0;

  clib_memset (ap, 0, sizeof (*ap));

  ap->sw_if_index = ntohl (mp->sw_if_index);
  ap->weight = ntohl (mp->weight);

  bond_set_intf_weight (vm, ap);
  rv = ap->rv;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_BOND_WEIGHT_REPLY);
}

static void
vl_api_bond_detach_slave_t_handler (vl_api_bond_detach_slave_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_bond_detach_slave_reply_t *rmp;
  bond_detach_member_args_t _a, *ap = &_a;
  int rv = 0;

  clib_memset (ap, 0, sizeof (*ap));

  ap->member = ntohl (mp->sw_if_index);
  bond_detach_member (vm, ap);
  rv = ap->rv;

  REPLY_MACRO (VL_API_BOND_DETACH_SLAVE_REPLY);
}

static void
vl_api_bond_detach_member_t_handler (vl_api_bond_detach_member_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_bond_detach_member_reply_t *rmp;
  bond_detach_member_args_t _a, *ap = &_a;
  int rv = 0;

  clib_memset (ap, 0, sizeof (*ap));

  ap->member = ntohl (mp->sw_if_index);
  bond_detach_member (vm, ap);
  rv = ap->rv;

  REPLY_MACRO (VL_API_BOND_DETACH_MEMBER_REPLY);
}

static void
bond_send_sw_interface_details (vpe_api_main_t * am,
				vl_api_registration_t * reg,
				bond_interface_details_t * bond_if,
				u32 context)
{
  vl_api_sw_interface_bond_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id =
    htons (REPLY_MSG_ID_BASE + VL_API_SW_INTERFACE_BOND_DETAILS);
  mp->sw_if_index = htonl (bond_if->sw_if_index);
  mp->id = htonl (bond_if->id);
  clib_memcpy (mp->interface_name, bond_if->interface_name,
	       MIN (ARRAY_LEN (mp->interface_name) - 1,
		    strlen ((const char *) bond_if->interface_name)));
  mp->mode = htonl (bond_if->mode);
  mp->lb = htonl (bond_if->lb);
  mp->numa_only = bond_if->numa_only;
  mp->active_slaves = htonl (bond_if->active_members);
  mp->slaves = htonl (bond_if->members);

  mp->context = context;
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_sw_interface_bond_dump_t_handler (vl_api_sw_interface_bond_dump_t * mp)
{
  int rv;
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  bond_interface_details_t *bondifs = NULL;
  bond_interface_details_t *bond_if = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rv = bond_dump_ifs (&bondifs);
  if (rv)
    return;

  vec_foreach (bond_if, bondifs)
  {
    bond_send_sw_interface_details (am, reg, bond_if, mp->context);
  }

  vec_free (bondifs);
}

static void
bond_send_sw_bond_interface_details (vpe_api_main_t * am,
				     vl_api_registration_t * reg,
				     bond_interface_details_t * bond_if,
				     u32 context)
{
  vl_api_sw_bond_interface_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id =
    htons (REPLY_MSG_ID_BASE + VL_API_SW_BOND_INTERFACE_DETAILS);
  mp->sw_if_index = htonl (bond_if->sw_if_index);
  mp->id = htonl (bond_if->id);
  clib_memcpy (mp->interface_name, bond_if->interface_name,
	       MIN (ARRAY_LEN (mp->interface_name) - 1,
		    strlen ((const char *) bond_if->interface_name)));
  mp->mode = htonl (bond_if->mode);
  mp->lb = htonl (bond_if->lb);
  mp->numa_only = bond_if->numa_only;
  mp->active_members = htonl (bond_if->active_members);
  mp->members = htonl (bond_if->members);

  mp->context = context;
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_sw_bond_interface_dump_t_handler (vl_api_sw_bond_interface_dump_t * mp)
{
  int rv;
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  bond_interface_details_t *bondifs = NULL;
  bond_interface_details_t *bond_if = NULL;
  u32 filter_sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  filter_sw_if_index = htonl (mp->sw_if_index);
  if (filter_sw_if_index != ~0)
    VALIDATE_SW_IF_INDEX (mp);

  rv = bond_dump_ifs (&bondifs);
  if (rv)
    return;

  vec_foreach (bond_if, bondifs)
  {
    if ((filter_sw_if_index == ~0) ||
	(bond_if->sw_if_index == filter_sw_if_index))
      bond_send_sw_bond_interface_details (am, reg, bond_if, mp->context);
  }

  BAD_SW_IF_INDEX_LABEL;
  vec_free (bondifs);
}

static void
bond_send_sw_member_interface_details (vpe_api_main_t * am,
				       vl_api_registration_t * reg,
				       member_interface_details_t * member_if,
				       u32 context)
{
  vl_api_sw_interface_slave_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id =
    htons (REPLY_MSG_ID_BASE + VL_API_SW_INTERFACE_SLAVE_DETAILS);
  mp->sw_if_index = htonl (member_if->sw_if_index);
  clib_memcpy (mp->interface_name, member_if->interface_name,
	       MIN (ARRAY_LEN (mp->interface_name) - 1,
		    strlen ((const char *) member_if->interface_name)));
  mp->is_passive = member_if->is_passive;
  mp->is_long_timeout = member_if->is_long_timeout;
  mp->is_local_numa = member_if->is_local_numa;
  mp->weight = htonl (member_if->weight);

  mp->context = context;
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_sw_interface_slave_dump_t_handler (vl_api_sw_interface_slave_dump_t *
					  mp)
{
  int rv;
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  member_interface_details_t *memberifs = NULL;
  member_interface_details_t *member_if = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rv = bond_dump_member_ifs (&memberifs, ntohl (mp->sw_if_index));
  if (rv)
    return;

  vec_foreach (member_if, memberifs)
  {
    bond_send_sw_member_interface_details (am, reg, member_if, mp->context);
  }

  vec_free (memberifs);
}

static void
bond_send_member_interface_details (vpe_api_main_t * am,
				    vl_api_registration_t * reg,
				    member_interface_details_t * member_if,
				    u32 context)
{
  vl_api_sw_member_interface_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id =
    htons (REPLY_MSG_ID_BASE + VL_API_SW_MEMBER_INTERFACE_DETAILS);
  mp->sw_if_index = htonl (member_if->sw_if_index);
  clib_memcpy (mp->interface_name, member_if->interface_name,
	       MIN (ARRAY_LEN (mp->interface_name) - 1,
		    strlen ((const char *) member_if->interface_name)));
  mp->is_passive = member_if->is_passive;
  mp->is_long_timeout = member_if->is_long_timeout;
  mp->is_local_numa = member_if->is_local_numa;
  mp->weight = htonl (member_if->weight);

  mp->context = context;
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_sw_member_interface_dump_t_handler (vl_api_sw_member_interface_dump_t *
					   mp)
{
  int rv;
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  member_interface_details_t *memberifs = NULL;
  member_interface_details_t *member_if = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rv = bond_dump_member_ifs (&memberifs, ntohl (mp->sw_if_index));
  if (rv)
    return;

  vec_foreach (member_if, memberifs)
  {
    bond_send_member_interface_details (am, reg, member_if, mp->context);
  }

  vec_free (memberifs);
}

#include <vnet/bonding/bond.api.c>
static clib_error_t *
bond_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (bond_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
