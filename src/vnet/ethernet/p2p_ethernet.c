/*
 * p2p_ethernet.c: p2p ethernet
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

#include <vppinfra/bihash_16_8.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/p2p_ethernet.h>
#include <vnet/l2/l2_input.h>

p2p_ethernet_main_t p2p_main;

static void
create_p2pe_key (p2p_key_t * p2pe_key, u32 parent_if_index, u8 * client_mac)
{
  clib_memcpy (p2pe_key->mac, client_mac, 6);
  p2pe_key->pad1 = 0;
  p2pe_key->hw_if_index = parent_if_index;
  p2pe_key->pad2 = 0;
}

u32
p2p_ethernet_lookup (u32 parent_if_index, u8 * client_mac)
{
  p2p_ethernet_main_t *p2pm = &p2p_main;
  p2p_key_t p2pe_key;
  uword *p;

  create_p2pe_key (&p2pe_key, parent_if_index, client_mac);
  p = hash_get_mem (p2pm->p2p_ethernet_by_key, &p2pe_key);
  if (p)
    return p[0];

  return ~0;
}

int
p2p_ethernet_add_del (vlib_main_t * vm, u32 parent_if_index,
		      u8 * client_mac, u32 p2pe_subif_id, int is_add,
		      u32 * p2pe_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  p2p_ethernet_main_t *p2pm = &p2p_main;
  vnet_interface_main_t *im = &vnm->interface_main;

  u32 p2pe_sw_if_index = ~0;
  p2pe_sw_if_index = p2p_ethernet_lookup (parent_if_index, client_mac);

  if (p2pe_if_index)
    *p2pe_if_index = ~0;

  if (is_add)
    {
      if (p2pe_sw_if_index == ~0)
	{
	  vnet_hw_interface_t *hi;

	  hi = vnet_get_hw_interface (vnm, parent_if_index);
	  if (hi->bond_info == VNET_HW_INTERFACE_BOND_INFO_SLAVE)
	    return VNET_API_ERROR_BOND_SLAVE_NOT_ALLOWED;

	  u64 sup_and_sub_key =
	    ((u64) (hi->sw_if_index) << 32) | (u64) p2pe_subif_id;
	  uword *p;
	  p = hash_get_mem (im->sw_if_index_by_sup_and_sub, &sup_and_sub_key);
	  if (p)
	    {
	      if (CLIB_DEBUG > 0)
		clib_warning
		  ("p2p ethernet sub-interface on sw_if_index %d with sub id %d already exists\n",
		   hi->sw_if_index, p2pe_subif_id);
	      return VNET_API_ERROR_SUBIF_ALREADY_EXISTS;
	    }
	  vnet_sw_interface_t template = {
	    .type = VNET_SW_INTERFACE_TYPE_P2P,
	    .flood_class = VNET_FLOOD_CLASS_NORMAL,
	    .sup_sw_if_index = hi->sw_if_index,
	    .sub.id = p2pe_subif_id
	  };

	  clib_memcpy (template.p2p.client_mac, client_mac,
		       sizeof (template.p2p.client_mac));

	  if (vnet_create_sw_interface (vnm, &template, &p2pe_sw_if_index))
	    return VNET_API_ERROR_SUBIF_CREATE_FAILED;

	  /* Allocate counters for this interface. */
	  {
	    u32 i;

	    vnet_interface_counter_lock (im);

	    for (i = 0; i < vec_len (im->sw_if_counters); i++)
	      {
		vlib_validate_simple_counter (&im->sw_if_counters[i],
					      p2pe_sw_if_index);
		vlib_zero_simple_counter (&im->sw_if_counters[i],
					  p2pe_sw_if_index);
	      }

	    for (i = 0; i < vec_len (im->combined_sw_if_counters); i++)
	      {
		vlib_validate_combined_counter (&im->combined_sw_if_counters
						[i], p2pe_sw_if_index);
		vlib_zero_combined_counter (&im->combined_sw_if_counters[i],
					    p2pe_sw_if_index);
	      }

	    vnet_interface_counter_unlock (im);
	  }

	  vnet_interface_main_t *im = &vnm->interface_main;
	  sup_and_sub_key =
	    ((u64) (hi->sw_if_index) << 32) | (u64) p2pe_subif_id;
	  u64 *kp = clib_mem_alloc (sizeof (*kp));

	  *kp = sup_and_sub_key;
	  hash_set (hi->sub_interface_sw_if_index_by_id, p2pe_subif_id,
		    p2pe_sw_if_index);
	  hash_set_mem (im->sw_if_index_by_sup_and_sub, kp, p2pe_sw_if_index);

	  p2p_key_t *p_p2pe_key;
	  p_p2pe_key = clib_mem_alloc (sizeof (*p_p2pe_key));
	  create_p2pe_key (p_p2pe_key, parent_if_index, client_mac);
	  hash_set_mem (p2pm->p2p_ethernet_by_key, p_p2pe_key,
			p2pe_sw_if_index);

	  if (p2pe_if_index)
	    *p2pe_if_index = p2pe_sw_if_index;

	  vec_validate (p2pm->p2p_ethernet_by_sw_if_index, parent_if_index);
	  if (p2pm->p2p_ethernet_by_sw_if_index[parent_if_index] == 0)
	    {
	      vnet_feature_enable_disable ("device-input",
					   "p2p-ethernet-input",
					   parent_if_index, 1, 0, 0);
	      /* Set promiscuous mode on the l2 interface */
	      ethernet_set_flags (vnm, parent_if_index,
				  ETHERNET_INTERFACE_FLAG_ACCEPT_ALL);

	    }
	  p2pm->p2p_ethernet_by_sw_if_index[parent_if_index]++;
	  /* set the interface mode */
	  set_int_l2_mode (vm, vnm, MODE_L3, p2pe_subif_id, 0, 0, 0, 0);
	  return 0;
	}
      return VNET_API_ERROR_SUBIF_ALREADY_EXISTS;
    }
  else
    {
      if (p2pe_sw_if_index == ~0)
	return VNET_API_ERROR_SUBIF_DOESNT_EXIST;
      else
	{
	  int rv = 0;
	  rv = vnet_delete_sub_interface (p2pe_sw_if_index);
	  if (!rv)
	    {
	      vec_validate (p2pm->p2p_ethernet_by_sw_if_index,
			    parent_if_index);
	      if (p2pm->p2p_ethernet_by_sw_if_index[parent_if_index] == 1)
		{
		  vnet_feature_enable_disable ("device-input",
					       "p2p-ethernet-input",
					       parent_if_index, 0, 0, 0);
		  /* Disable promiscuous mode on the l2 interface */
		  ethernet_set_flags (vnm, parent_if_index, 0);
		}
	      p2pm->p2p_ethernet_by_sw_if_index[parent_if_index]--;

	      /* Remove p2p_ethernet from hash map */
	      p2p_key_t *p_p2pe_key;
	      p_p2pe_key = clib_mem_alloc (sizeof (*p_p2pe_key));
	      create_p2pe_key (p_p2pe_key, parent_if_index, client_mac);
	      hash_unset_mem (p2pm->p2p_ethernet_by_key, p_p2pe_key);
	    }
	  return rv;
	}
    }
}

static clib_error_t *
vnet_p2p_ethernet_add_del (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();

  int is_add = 1;
  int remote_mac = 0;
  u32 hw_if_index = ~0;
  u32 sub_id = ~0;
  u8 client_mac[6];

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	;
      else if (unformat (input, "%U", unformat_ethernet_address, &client_mac))
	remote_mac = 1;
      else if (unformat (input, "sub-id %d", &sub_id))
	;
      else if (unformat (input, "del"))
	is_add = 0;
      else
	break;
    }

  if (hw_if_index == ~0)
    return clib_error_return (0, "Please specify parent interface ...");
  if (!remote_mac)
    return clib_error_return (0, "Please specify client MAC address ...");
  if (sub_id == ~0 && is_add)
    return clib_error_return (0, "Please specify sub-interface id ...");

  u32 rv;
  rv = p2p_ethernet_add_del (vm, hw_if_index, client_mac, sub_id, is_add, 0);
  switch (rv)
    {
    case VNET_API_ERROR_BOND_SLAVE_NOT_ALLOWED:
      return clib_error_return (0,
				"not allowed as parent interface belongs to a BondEthernet interface");
    case -1:
      return clib_error_return (0,
				"p2p ethernet for given parent interface and client mac already exists");
    case -2:
      return clib_error_return (0,
				"couldn't create p2p ethernet subinterface");
    case -3:
      return clib_error_return (0,
				"p2p ethernet for given parent interface and client mac doesn't exist");
    default:
      break;
    }
  return 0;
}

VLIB_CLI_COMMAND (p2p_ethernet_add_del_command, static) =
{
.path = "p2p_ethernet ",.function = vnet_p2p_ethernet_add_del,.short_help =
    "p2p_ethernet <intfc> <mac-address> [sub-id <id> | del]",};

static clib_error_t *
p2p_ethernet_init (vlib_main_t * vm)
{
  p2p_ethernet_main_t *p2pm = &p2p_main;

  p2pm->vlib_main = vm;
  p2pm->vnet_main = vnet_get_main ();
  p2pm->p2p_ethernet_by_key =
    hash_create_mem (0, sizeof (p2p_key_t), sizeof (uword));

  return 0;
}

VLIB_INIT_FUNCTION (p2p_ethernet_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
