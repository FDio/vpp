/*
 * l2_bd.c : layer 2 bridge domain
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vlib/cli.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/format.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/l2/l2_learn.h>
#include <vnet/l2/l2_fib.h>
#include <vnet/l2/l2_vtr.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/vec.h>

/**
 * @file
 * @brief Ethernet Bridge Domain.
 *
 * Code in this file manages Layer 2 bridge domains.
 *
 */

bd_main_t bd_main;

/**
  Init bridge domain if not done already.
  For feature bitmap, set all bits except ARP termination
*/
void
bd_validate (l2_bridge_domain_t * bd_config)
{
  if (bd_is_valid (bd_config))
    return;
  bd_config->feature_bitmap = ~(L2INPUT_FEAT_ARP_TERM | L2INPUT_FEAT_UU_FWD);
  bd_config->bvi_sw_if_index = ~0;
  bd_config->uu_fwd_sw_if_index = ~0;
  bd_config->members = 0;
  bd_config->flood_count = 0;
  bd_config->tun_master_count = 0;
  bd_config->tun_normal_count = 0;
  bd_config->no_flood_count = 0;
  bd_config->mac_by_ip4 = 0;
  bd_config->mac_by_ip6 = hash_create_mem (0, sizeof (ip6_address_t),
					   sizeof (uword));
}

u32
bd_find_index (bd_main_t * bdm, u32 bd_id)
{
  u32 *p = (u32 *) hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (!p)
    return ~0;
  return p[0];
}

u32
bd_add_bd_index (bd_main_t * bdm, u32 bd_id)
{
  ASSERT (!hash_get (bdm->bd_index_by_bd_id, bd_id));
  u32 rv = clib_bitmap_first_clear (bdm->bd_index_bitmap);

  /* mark this index taken */
  bdm->bd_index_bitmap = clib_bitmap_set (bdm->bd_index_bitmap, rv, 1);

  hash_set (bdm->bd_index_by_bd_id, bd_id, rv);

  vec_validate (l2input_main.bd_configs, rv);
  l2input_main.bd_configs[rv].bd_id = bd_id;

  return rv;
}

static inline void
bd_free_ip_mac_tables (l2_bridge_domain_t * bd)
{
  u64 mac_addr;
  ip6_address_t *ip6_addr_key;

  hash_free (bd->mac_by_ip4);
  /* *INDENT-OFF* */
  hash_foreach_mem (ip6_addr_key, mac_addr, bd->mac_by_ip6,
  ({
    clib_mem_free (ip6_addr_key); /* free memory used for ip6 addr key */
  }));
  /* *INDENT-ON* */
  hash_free (bd->mac_by_ip6);
}

static int
bd_delete (bd_main_t * bdm, u32 bd_index)
{
  l2_bridge_domain_t *bd = &l2input_main.bd_configs[bd_index];
  u32 bd_id = bd->bd_id;

  /* flush non-static MACs in BD and removed bd_id from hash table */
  l2fib_flush_bd_mac (vlib_get_main (), bd_index);
  hash_unset (bdm->bd_index_by_bd_id, bd_id);

  /* mark this index clear */
  bdm->bd_index_bitmap = clib_bitmap_set (bdm->bd_index_bitmap, bd_index, 0);

  /* clear BD config for reuse: bd_id to -1 and clear feature_bitmap */
  bd->bd_id = ~0;
  bd->feature_bitmap = 0;

  /* free BD tag */
  vec_free (bd->bd_tag);

  /* free memory used by BD */
  vec_free (bd->members);
  bd_free_ip_mac_tables (bd);

  return 0;
}

static void
update_flood_count (l2_bridge_domain_t * bd_config)
{
  bd_config->flood_count = (vec_len (bd_config->members) -
			    (bd_config->tun_master_count ?
			     bd_config->tun_normal_count : 0));
  bd_config->flood_count -= bd_config->no_flood_count;
}

void
bd_add_member (l2_bridge_domain_t * bd_config, l2_flood_member_t * member)
{
  u32 ix = 0;
  vnet_sw_interface_t *sw_if = vnet_get_sw_interface
    (vnet_get_main (), member->sw_if_index);

  /*
   * Add one element to the vector
   * vector is ordered [ bvi, normal/tun_masters..., tun_normals... no_flood]
   * When flooding, the bvi interface (if present) must be the last member
   * processed due to how BVI processing can change the packet. To enable
   * this order, we make the bvi interface the first in the vector and
   * flooding walks the vector in reverse. The flood-count determines where
   * in the member list to start the walk from.
   */
  switch (sw_if->flood_class)
    {
    case VNET_FLOOD_CLASS_NO_FLOOD:
      bd_config->no_flood_count++;
      ix = vec_len (bd_config->members);
      break;
    case VNET_FLOOD_CLASS_BVI:
      ix = 0;
      break;
    case VNET_FLOOD_CLASS_TUNNEL_MASTER:
      bd_config->tun_master_count++;
      /* Fall through */
    case VNET_FLOOD_CLASS_NORMAL:
      ix = (vec_len (bd_config->members) -
	    bd_config->tun_normal_count - bd_config->no_flood_count);
      break;
    case VNET_FLOOD_CLASS_TUNNEL_NORMAL:
      ix = (vec_len (bd_config->members) - bd_config->no_flood_count);
      bd_config->tun_normal_count++;
      break;
    }

  vec_insert_elts (bd_config->members, member, 1, ix);
  update_flood_count (bd_config);
}

#define BD_REMOVE_ERROR_OK        0
#define BD_REMOVE_ERROR_NOT_FOUND 1

u32
bd_remove_member (l2_bridge_domain_t * bd_config, u32 sw_if_index)
{
  u32 ix;

  /* Find and delete the member */
  vec_foreach_index (ix, bd_config->members)
  {
    l2_flood_member_t *m = vec_elt_at_index (bd_config->members, ix);
    if (m->sw_if_index == sw_if_index)
      {
	vnet_sw_interface_t *sw_if = vnet_get_sw_interface
	  (vnet_get_main (), sw_if_index);

	if (sw_if->flood_class != VNET_FLOOD_CLASS_NORMAL)
	  {
	    if (sw_if->flood_class == VNET_FLOOD_CLASS_TUNNEL_MASTER)
	      bd_config->tun_master_count--;
	    else if (sw_if->flood_class == VNET_FLOOD_CLASS_TUNNEL_NORMAL)
	      bd_config->tun_normal_count--;
	    else if (sw_if->flood_class == VNET_FLOOD_CLASS_NO_FLOOD)
	      bd_config->no_flood_count--;
	  }
	vec_delete (bd_config->members, 1, ix);
	update_flood_count (bd_config);

	return BD_REMOVE_ERROR_OK;
      }
  }

  return BD_REMOVE_ERROR_NOT_FOUND;
}


clib_error_t *
l2bd_init (vlib_main_t * vm)
{
  bd_main_t *bdm = &bd_main;
  bdm->bd_index_by_bd_id = hash_create (0, sizeof (uword));
  /*
   * create a dummy bd with bd_id of 0 and bd_index of 0 with feature set
   * to packet drop only. Thus, packets received from any L2 interface with
   * uninitialized bd_index of 0 can be dropped safely.
   */
  u32 bd_index = bd_add_bd_index (bdm, 0);
  ASSERT (bd_index == 0);
  l2input_main.bd_configs[0].feature_bitmap = L2INPUT_FEAT_DROP;

  bdm->vlib_main = vm;
  return 0;
}

VLIB_INIT_FUNCTION (l2bd_init);


/**
    Set the learn/forward/flood flags for the bridge domain.
    Return 0 if ok, non-zero if for an error.
*/
u32
bd_set_flags (vlib_main_t * vm, u32 bd_index, bd_flags_t flags, u32 enable)
{

  l2_bridge_domain_t *bd_config = l2input_bd_config (bd_index);
  bd_validate (bd_config);
  u32 feature_bitmap = 0;

  if (flags & L2_LEARN)
    {
      feature_bitmap |= L2INPUT_FEAT_LEARN;
    }
  if (flags & L2_FWD)
    {
      feature_bitmap |= L2INPUT_FEAT_FWD;
    }
  if (flags & L2_FLOOD)
    {
      feature_bitmap |= L2INPUT_FEAT_FLOOD;
    }
  if (flags & L2_UU_FLOOD)
    {
      feature_bitmap |= L2INPUT_FEAT_UU_FLOOD;
    }
  if (flags & L2_ARP_TERM)
    {
      feature_bitmap |= L2INPUT_FEAT_ARP_TERM;
    }

  if (enable)
    {
      bd_config->feature_bitmap |= feature_bitmap;
    }
  else
    {
      bd_config->feature_bitmap &= ~feature_bitmap;
    }

  return bd_config->feature_bitmap;
}

/**
    Set the mac age for the bridge domain.
*/
void
bd_set_mac_age (vlib_main_t * vm, u32 bd_index, u8 age)
{
  l2_bridge_domain_t *bd_config;
  int enable = 0;

  vec_validate (l2input_main.bd_configs, bd_index);
  bd_config = vec_elt_at_index (l2input_main.bd_configs, bd_index);
  bd_config->mac_age = age;

  /* check if there is at least one bd with mac aging enabled */
  vec_foreach (bd_config, l2input_main.bd_configs)
    enable |= bd_config->bd_id != ~0 && bd_config->mac_age != 0;

  vlib_process_signal_event (vm, l2fib_mac_age_scanner_process_node.index,
			     enable ? L2_MAC_AGE_PROCESS_EVENT_START :
			     L2_MAC_AGE_PROCESS_EVENT_STOP, 0);
}

/**
    Set the tag for the bridge domain.
*/

static void
bd_set_bd_tag (vlib_main_t * vm, u32 bd_index, u8 * bd_tag)
{
  u8 *old;
  l2_bridge_domain_t *bd_config;
  vec_validate (l2input_main.bd_configs, bd_index);
  bd_config = vec_elt_at_index (l2input_main.bd_configs, bd_index);

  old = bd_config->bd_tag;

  if (bd_tag[0])
    {
      bd_config->bd_tag = format (0, "%s%c", bd_tag, 0);
    }
  else
    {
      bd_config->bd_tag = NULL;
    }

  vec_free (old);
}

/**
   Set bridge-domain learn enable/disable.
   The CLI format is:
   set bridge-domain learn <bd_id> [disable]
*/
static clib_error_t *
bd_learn (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  bd_main_t *bdm = &bd_main;
  clib_error_t *error = 0;
  u32 bd_index, bd_id;
  u32 enable;
  uword *p;

  if (!unformat (input, "%d", &bd_id))
    {
      error = clib_error_return (0, "expecting bridge-domain id but got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (bd_id == 0)
    return clib_error_return (0,
			      "No operations on the default bridge domain are supported");

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);

  if (p == 0)
    return clib_error_return (0, "No such bridge domain %d", bd_id);

  bd_index = p[0];

  enable = 1;
  if (unformat (input, "disable"))
    {
      enable = 0;
    }

  /* set the bridge domain flag */
  bd_set_flags (vm, bd_index, L2_LEARN, enable);

done:
  return error;
}

/*?
 * Layer 2 learning can be enabled and disabled on each
 * interface and on each bridge-domain. Use this command to
 * manage bridge-domains. It is enabled by default.
 *
 * @cliexpar
 * Example of how to enable learning (where 200 is the bridge-domain-id):
 * @cliexcmd{set bridge-domain learn 200}
 * Example of how to disable learning (where 200 is the bridge-domain-id):
 * @cliexcmd{set bridge-domain learn 200 disable}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bd_learn_cli, static) = {
  .path = "set bridge-domain learn",
  .short_help = "set bridge-domain learn <bridge-domain-id> [disable]",
  .function = bd_learn,
};
/* *INDENT-ON* */

/**
    Set bridge-domain forward enable/disable.
    The CLI format is:
    set bridge-domain forward <bd_index> [disable]
*/
static clib_error_t *
bd_fwd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  bd_main_t *bdm = &bd_main;
  clib_error_t *error = 0;
  u32 bd_index, bd_id;
  u32 enable;
  uword *p;

  if (!unformat (input, "%d", &bd_id))
    {
      error = clib_error_return (0, "expecting bridge-domain id but got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (bd_id == 0)
    return clib_error_return (0,
			      "No operations on the default bridge domain are supported");

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);

  if (p == 0)
    return clib_error_return (0, "No such bridge domain %d", bd_id);

  bd_index = p[0];

  enable = 1;
  if (unformat (input, "disable"))
    {
      enable = 0;
    }

  /* set the bridge domain flag */
  bd_set_flags (vm, bd_index, L2_FWD, enable);

done:
  return error;
}


/*?
 * Layer 2 unicast forwarding can be enabled and disabled on each
 * interface and on each bridge-domain. Use this command to
 * manage bridge-domains. It is enabled by default.
 *
 * @cliexpar
 * Example of how to enable forwarding (where 200 is the bridge-domain-id):
 * @cliexcmd{set bridge-domain forward 200}
 * Example of how to disable forwarding (where 200 is the bridge-domain-id):
 * @cliexcmd{set bridge-domain forward 200 disable}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bd_fwd_cli, static) = {
  .path = "set bridge-domain forward",
  .short_help = "set bridge-domain forward <bridge-domain-id> [disable]",
  .function = bd_fwd,
};
/* *INDENT-ON* */

/**
    Set bridge-domain flood enable/disable.
    The CLI format is:
    set bridge-domain flood <bd_index> [disable]
*/
static clib_error_t *
bd_flood (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  bd_main_t *bdm = &bd_main;
  clib_error_t *error = 0;
  u32 bd_index, bd_id;
  u32 enable;
  uword *p;

  if (!unformat (input, "%d", &bd_id))
    {
      error = clib_error_return (0, "expecting bridge-domain id but got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (bd_id == 0)
    return clib_error_return (0,
			      "No operations on the default bridge domain are supported");

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);

  if (p == 0)
    return clib_error_return (0, "No such bridge domain %d", bd_id);

  bd_index = p[0];

  enable = 1;
  if (unformat (input, "disable"))
    {
      enable = 0;
    }

  /* set the bridge domain flag */
  bd_set_flags (vm, bd_index, L2_FLOOD, enable);

done:
  return error;
}

/*?
 * Layer 2 flooding can be enabled and disabled on each
 * interface and on each bridge-domain. Use this command to
 * manage bridge-domains. It is enabled by default.
 *
 * @cliexpar
 * Example of how to enable flooding (where 200 is the bridge-domain-id):
 * @cliexcmd{set bridge-domain flood 200}
 * Example of how to disable flooding (where 200 is the bridge-domain-id):
 * @cliexcmd{set bridge-domain flood 200 disable}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bd_flood_cli, static) = {
  .path = "set bridge-domain flood",
  .short_help = "set bridge-domain flood <bridge-domain-id> [disable]",
  .function = bd_flood,
};
/* *INDENT-ON* */

/**
    Set bridge-domain unknown-unicast flood enable/disable.
    The CLI format is:
    set bridge-domain uu-flood <bd_index> [disable]
*/
static clib_error_t *
bd_uu_flood (vlib_main_t * vm,
	     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  bd_main_t *bdm = &bd_main;
  clib_error_t *error = 0;
  u32 bd_index, bd_id;
  u32 enable;
  uword *p;

  if (!unformat (input, "%d", &bd_id))
    {
      error = clib_error_return (0, "expecting bridge-domain id but got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (bd_id == 0)
    return clib_error_return (0,
			      "No operations on the default bridge domain are supported");

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);

  if (p == 0)
    return clib_error_return (0, "No such bridge domain %d", bd_id);

  bd_index = p[0];

  enable = 1;
  if (unformat (input, "disable"))
    {
      enable = 0;
    }

  /* set the bridge domain flag */
  bd_set_flags (vm, bd_index, L2_UU_FLOOD, enable);

done:
  return error;
}

/*?
 * Layer 2 unknown-unicast flooding can be enabled and disabled on each
 * bridge-domain. It is enabled by default.
 *
 * @cliexpar
 * Example of how to enable unknown-unicast flooding (where 200 is the
 * bridge-domain-id):
 * @cliexcmd{set bridge-domain uu-flood 200}
 * Example of how to disable unknown-unicast flooding (where 200 is the bridge-domain-id):
 * @cliexcmd{set bridge-domain uu-flood 200 disable}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bd_uu_flood_cli, static) = {
  .path = "set bridge-domain uu-flood",
  .short_help = "set bridge-domain uu-flood <bridge-domain-id> [disable]",
  .function = bd_uu_flood,
};
/* *INDENT-ON* */

/**
    Set bridge-domain arp term enable/disable.
    The CLI format is:
    set bridge-domain arp term <bridge-domain-id> [disable]
*/
static clib_error_t *
bd_arp_term (vlib_main_t * vm,
	     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  bd_main_t *bdm = &bd_main;
  clib_error_t *error = 0;
  u32 bd_index, bd_id;
  u32 enable;
  uword *p;

  if (!unformat (input, "%d", &bd_id))
    {
      error = clib_error_return (0, "expecting bridge-domain id but got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (bd_id == 0)
    return clib_error_return (0,
			      "No operations on the default bridge domain are supported");

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (p)
    bd_index = *p;
  else
    return clib_error_return (0, "No such bridge domain %d", bd_id);

  enable = 1;
  if (unformat (input, "disable"))
    enable = 0;

  /* set the bridge domain flag */
  bd_set_flags (vm, bd_index, L2_ARP_TERM, enable);

done:
  return error;
}

static clib_error_t *
bd_mac_age (vlib_main_t * vm,
	    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  bd_main_t *bdm = &bd_main;
  clib_error_t *error = 0;
  u32 bd_index, bd_id;
  u32 age;
  uword *p;

  if (!unformat (input, "%d", &bd_id))
    {
      error = clib_error_return (0, "expecting bridge-domain id but got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (bd_id == 0)
    return clib_error_return (0,
			      "No operations on the default bridge domain are supported");

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);

  if (p == 0)
    return clib_error_return (0, "No such bridge domain %d", bd_id);

  bd_index = p[0];

  if (!unformat (input, "%u", &age))
    {
      error =
	clib_error_return (0, "expecting ageing time in minutes but got `%U'",
			   format_unformat_error, input);
      goto done;
    }

  /* set the bridge domain flag */
  if (age > 255)
    {
      error =
	clib_error_return (0, "mac aging time cannot be bigger than 255");
      goto done;
    }
  bd_set_mac_age (vm, bd_index, (u8) age);

done:
  return error;
}

/*?
 * Layer 2 mac aging can be enabled and disabled on each
 * bridge-domain. Use this command to set or disable mac aging
 * on specific bridge-domains. It is disabled by default.
 *
 * @cliexpar
 * Example of how to set mac aging (where 200 is the bridge-domain-id and
 * 5 is aging time in minutes):
 * @cliexcmd{set bridge-domain mac-age 200 5}
 * Example of how to disable mac aging (where 200 is the bridge-domain-id):
 * @cliexcmd{set bridge-domain flood 200 0}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bd_mac_age_cli, static) = {
  .path = "set bridge-domain mac-age",
  .short_help = "set bridge-domain mac-age <bridge-domain-id> <mins>",
  .function = bd_mac_age,
};
/* *INDENT-ON* */

/*?
 * Modify whether or not an existing bridge-domain should terminate and respond
 * to ARP Requests. ARP Termination is disabled by default.
 *
 * @cliexpar
 * Example of how to enable ARP termination (where 200 is the bridge-domain-id):
 * @cliexcmd{set bridge-domain arp term 200}
 * Example of how to disable ARP termination (where 200 is the bridge-domain-id):
 * @cliexcmd{set bridge-domain arp term 200 disable}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bd_arp_term_cli, static) = {
  .path = "set bridge-domain arp term",
  .short_help = "set bridge-domain arp term <bridge-domain-id> [disable]",
  .function = bd_arp_term,
};
/* *INDENT-ON* */


/**
 * Add/delete IP address to MAC address mapping.
 *
 * The clib hash implementation stores uword entries in the hash table.
 * The hash table mac_by_ip4 is keyed via IP4 address and store the
 * 6-byte MAC address directly in the hash table entry uword.
 *
 * @warning This only works for 64-bit processor with 8-byte uword;
 * which means this code *WILL NOT WORK* for a 32-bit processor with
 * 4-byte uword.
 */
u32
bd_add_del_ip_mac (u32 bd_index,
		   ip46_type_t type,
		   const ip46_address_t * ip,
		   const mac_address_t * mac, u8 is_add)
{
  l2_bridge_domain_t *bd_cfg = l2input_bd_config (bd_index);
  u64 new_mac = mac_address_as_u64 (mac);
  u64 *old_mac;

  /* make sure uword is 8 bytes */
  ASSERT (sizeof (uword) == sizeof (u64));
  ASSERT (bd_is_valid (bd_cfg));

  if (IP46_TYPE_IP6 == type)
    {
      ip6_address_t *ip6_addr_key;
      hash_pair_t *hp;
      old_mac = (u64 *) hash_get_mem (bd_cfg->mac_by_ip6, &ip->ip6);
      if (is_add)
	{
	  if (old_mac == NULL)
	    {
	      /* new entry - allocate and create ip6 address key */
	      ip6_addr_key = clib_mem_alloc (sizeof (ip6_address_t));
	      clib_memcpy (ip6_addr_key, &ip->ip6, sizeof (ip6_address_t));
	    }
	  else if (*old_mac == new_mac)
	    {
	      /* same mac entry already exist for ip6 address */
	      return 0;
	    }
	  else
	    {
	      /* update mac for ip6 address */
	      hp = hash_get_pair (bd_cfg->mac_by_ip6, &ip->ip6);
	      ip6_addr_key = (ip6_address_t *) hp->key;
	    }
	  hash_set_mem (bd_cfg->mac_by_ip6, ip6_addr_key, new_mac);
	}
      else
	{
	  if (old_mac && (*old_mac == new_mac))
	    {
	      hp = hash_get_pair (bd_cfg->mac_by_ip6, &ip->ip6);
	      ip6_addr_key = (ip6_address_t *) hp->key;
	      hash_unset_mem (bd_cfg->mac_by_ip6, &ip->ip6);
	      clib_mem_free (ip6_addr_key);
	    }
	  else
	    return 1;
	}
    }
  else
    {
      old_mac = (u64 *) hash_get (bd_cfg->mac_by_ip4, ip->ip4.as_u32);
      if (is_add)
	{
	  if (old_mac && (*old_mac == new_mac))
	    /* mac entry already exist */
	    return 0;
	  hash_set (bd_cfg->mac_by_ip4, ip->ip4.as_u32, new_mac);
	}
      else
	{
	  if (old_mac && (*old_mac == new_mac))
	    hash_unset (bd_cfg->mac_by_ip4, ip->ip4.as_u32);
	  else
	    return 1;
	}
    }
  return 0;
}

/**
 * Flush IP address to MAC address mapping tables in a BD.
 */
void
bd_flush_ip_mac (u32 bd_index)
{
  l2_bridge_domain_t *bd = l2input_bd_config (bd_index);
  ASSERT (bd_is_valid (bd));
  bd_free_ip_mac_tables (bd);
  bd->mac_by_ip4 = 0;
  bd->mac_by_ip6 =
    hash_create_mem (0, sizeof (ip6_address_t), sizeof (uword));
}

/**
    Set bridge-domain arp entry add/delete.
    The CLI format is:
    set bridge-domain arp entry <bridge-domain-id> <ip-addr> <mac-addr> [del]
*/
static clib_error_t *
bd_arp_entry (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip46_address_t ip_addr = ip46_address_initializer;
  ip46_type_t type = IP46_TYPE_IP4;
  bd_main_t *bdm = &bd_main;
  clib_error_t *error = 0;
  u32 bd_index, bd_id;
  mac_address_t mac;
  u8 is_add = 1;
  uword *p;

  if (!unformat (input, "%d", &bd_id))
    {
      error = clib_error_return (0, "expecting bridge-domain id but got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (bd_id == 0)
    return clib_error_return (0,
			      "No operations on the default bridge domain are supported");

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);

  if (p)
    bd_index = *p;
  else
    return clib_error_return (0, "No such bridge domain %d", bd_id);

  if (unformat (input, "%U", unformat_ip4_address, &ip_addr.ip4))
    {
      type = IP46_TYPE_IP4;
    }
  else if (unformat (input, "%U", unformat_ip6_address, &ip_addr.ip6))
    {
      type = IP46_TYPE_IP6;
    }
  else if (unformat (input, "del-all"))
    {
      bd_flush_ip_mac (bd_index);
      goto done;
    }
  else
    {
      error = clib_error_return (0, "expecting IP address but got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (!unformat (input, "%U", unformat_mac_address_t, &mac))
    {
      error = clib_error_return (0, "expecting MAC address but got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (unformat (input, "del"))
    {
      is_add = 0;
    }

  /* set the bridge domain flagAdd IP-MAC entry into bridge domain */
  if (bd_add_del_ip_mac (bd_index, type, &ip_addr, &mac, is_add))
    {
      error = clib_error_return (0, "MAC %s for IP %U and MAC %U failed",
				 is_add ? "add" : "del",
				 format_ip46_address, &ip_addr, IP46_TYPE_ANY,
				 format_mac_address_t, &mac);
    }

done:
  return error;
}

/*?
 * Add an ARP entry to an existing bridge-domain.
 *
 * @cliexpar
 * Example of how to add an ARP entry (where 200 is the bridge-domain-id):
 * @cliexcmd{set bridge-domain arp entry 200 192.168.72.45 52:54:00:3b:83:1a}
 * Example of how to delete an ARP entry (where 200 is the bridge-domain-id):
 * @cliexcmd{set bridge-domain arp entry 200 192.168.72.45 52:54:00:3b:83:1a del}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bd_arp_entry_cli, static) = {
  .path = "set bridge-domain arp entry",
  .short_help = "set bridge-domain arp entry <bridge-domain-id> [<ip-addr> <mac-addr> [del] | del-all]",
  .function = bd_arp_entry,
};
/* *INDENT-ON* */

static u8 *
format_vtr (u8 * s, va_list * args)
{
  u32 vtr_op = va_arg (*args, u32);
  u32 dot1q = va_arg (*args, u32);
  u32 tag1 = va_arg (*args, u32);
  u32 tag2 = va_arg (*args, u32);
  switch (vtr_op)
    {
    case L2_VTR_DISABLED:
      return format (s, "none");
    case L2_VTR_PUSH_1:
      return format (s, "push-1 %s %d", dot1q ? "dot1q" : "dot1ad", tag1);
    case L2_VTR_PUSH_2:
      return format (s, "push-2 %s %d %d", dot1q ? "dot1q" : "dot1ad", tag1,
		     tag2);
    case L2_VTR_POP_1:
      return format (s, "pop-1");
    case L2_VTR_POP_2:
      return format (s, "pop-2");
    case L2_VTR_TRANSLATE_1_1:
      return format (s, "trans-1-1 %s %d", dot1q ? "dot1q" : "dot1ad", tag1);
    case L2_VTR_TRANSLATE_1_2:
      return format (s, "trans-1-2 %s %d %d", dot1q ? "dot1q" : "dot1ad",
		     tag1, tag2);
    case L2_VTR_TRANSLATE_2_1:
      return format (s, "trans-2-1 %s %d", dot1q ? "dot1q" : "dot1ad", tag1);
    case L2_VTR_TRANSLATE_2_2:
      return format (s, "trans-2-2 %s %d %d", dot1q ? "dot1q" : "dot1ad",
		     tag1, tag2);
    default:
      return format (s, "none");
    }
}

static u8 *
format_uu_cfg (u8 * s, va_list * args)
{
  l2_bridge_domain_t *bd_config = va_arg (*args, l2_bridge_domain_t *);

  if (bd_config->feature_bitmap & L2INPUT_FEAT_UU_FWD)
    return (format (s, "%U", format_vnet_sw_if_index_name_with_NA,
		    vnet_get_main (), bd_config->uu_fwd_sw_if_index));
  else if (bd_config->feature_bitmap & L2INPUT_FEAT_UU_FLOOD)
    return (format (s, "flood"));
  else
    return (format (s, "drop"));
}

/**
   Show bridge-domain state.
   The CLI format is:
   show bridge-domain [<bd_index>]
*/
static clib_error_t *
bd_show (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  bd_main_t *bdm = &bd_main;
  clib_error_t *error = 0;
  u32 bd_index = ~0;
  l2_bridge_domain_t *bd_config;
  u32 start, end;
  u32 detail = 0;
  u32 intf = 0;
  u32 arp = 0;
  u32 bd_tag = 0;
  u32 bd_id = ~0;
  uword *p;

  start = 1;
  end = vec_len (l2input_main.bd_configs);

  if (unformat (input, "%d", &bd_id))
    {
      if (unformat (input, "detail"))
	detail = 1;
      else if (unformat (input, "det"))
	detail = 1;
      if (unformat (input, "int"))
	intf = 1;
      if (unformat (input, "arp"))
	arp = 1;
      if (unformat (input, "bd-tag"))
	bd_tag = 1;

      if (bd_id == 0)
	return clib_error_return (0,
				  "No operations on the default bridge domain are supported");

      p = hash_get (bdm->bd_index_by_bd_id, bd_id);
      if (p)
	bd_index = *p;
      else
	return clib_error_return (0, "No such bridge domain %d", bd_id);

      vec_validate (l2input_main.bd_configs, bd_index);
      bd_config = vec_elt_at_index (l2input_main.bd_configs, bd_index);
      if (bd_is_valid (bd_config))
	{
	  start = bd_index;
	  end = start + 1;
	}
      else
	{
	  vlib_cli_output (vm, "bridge-domain %d not in use", bd_id);
	  goto done;
	}
    }

  /* Show all bridge-domains that have been initialized */
  u32 printed = 0;
  u8 *as = 0;
  for (bd_index = start; bd_index < end; bd_index++)
    {
      bd_config = vec_elt_at_index (l2input_main.bd_configs, bd_index);
      if (bd_is_valid (bd_config))
	{
	  if (!printed)
	    {
	      printed = 1;
	      vlib_cli_output (vm,
			       "%=8s %=7s %=4s %=9s %=9s %=9s %=11s %=9s %=9s %=11s",
			       "BD-ID", "Index", "BSN", "Age(min)",
			       "Learning", "U-Forwrd", "UU-Flood",
			       "Flooding", "ARP-Term", "BVI-Intf");
	    }

	  if (bd_config->mac_age)
	    as = format (as, "%d", bd_config->mac_age);
	  else
	    as = format (as, "off");
	  vlib_cli_output (vm,
			   "%=8d %=7d %=4d %=9v %=9s %=9s %=11U %=9s %=9s %=11U",
			   bd_config->bd_id, bd_index, bd_config->seq_num, as,
			   bd_config->feature_bitmap & L2INPUT_FEAT_LEARN ?
			   "on" : "off",
			   bd_config->feature_bitmap & L2INPUT_FEAT_FWD ?
			   "on" : "off",
			   format_uu_cfg, bd_config,
			   bd_config->feature_bitmap & L2INPUT_FEAT_FLOOD ?
			   "on" : "off",
			   bd_config->feature_bitmap & L2INPUT_FEAT_ARP_TERM ?
			   "on" : "off",
			   format_vnet_sw_if_index_name_with_NA,
			   vnm, bd_config->bvi_sw_if_index);
	  vec_reset_length (as);

	  if (detail || intf)
	    {
	      /* Show all member interfaces */
	      int i;
	      vec_foreach_index (i, bd_config->members)
	      {
		l2_flood_member_t *member =
		  vec_elt_at_index (bd_config->members, i);
		u8 swif_seq_num = *l2fib_swif_seq_num (member->sw_if_index);
		u32 vtr_opr, dot1q, tag1, tag2;
		if (i == 0)
		  {
		    vlib_cli_output (vm, "\n%=30s%=7s%=5s%=5s%=5s%=9s%=30s",
				     "Interface", "If-idx", "ISN", "SHG",
				     "BVI", "TxFlood", "VLAN-Tag-Rewrite");
		  }
		l2vtr_get (vm, vnm, member->sw_if_index, &vtr_opr, &dot1q,
			   &tag1, &tag2);
		vlib_cli_output (vm, "%=30U%=7d%=5d%=5d%=5s%=9s%=30U",
				 format_vnet_sw_if_index_name, vnm,
				 member->sw_if_index, member->sw_if_index,
				 swif_seq_num, member->shg,
				 member->flags & L2_FLOOD_MEMBER_BVI ? "*" :
				 "-", i < bd_config->flood_count ? "*" : "-",
				 format_vtr, vtr_opr, dot1q, tag1, tag2);
	      }
	      if (~0 != bd_config->uu_fwd_sw_if_index)
		vlib_cli_output (vm, "%=30U%=7d%=5d%=5d%=5s%=9s%=30s",
				 format_vnet_sw_if_index_name, vnm,
				 bd_config->uu_fwd_sw_if_index,
				 bd_config->uu_fwd_sw_if_index,
				 0, 0, "uu", "-", "None");

	    }

	  if ((detail || arp) &&
	      (bd_config->feature_bitmap & L2INPUT_FEAT_ARP_TERM))
	    {
	      u32 ip4_addr;
	      ip6_address_t *ip6_addr;
	      u64 mac_addr;
	      vlib_cli_output (vm,
			       "\n  IP4/IP6 to MAC table for ARP Termination");

              /* *INDENT-OFF* */
              hash_foreach (ip4_addr, mac_addr, bd_config->mac_by_ip4,
              ({
                vlib_cli_output (vm, "%=40U => %=20U",
                                 format_ip4_address, &ip4_addr,
                                 format_ethernet_address, &mac_addr);
              }));

              hash_foreach_mem (ip6_addr, mac_addr, bd_config->mac_by_ip6,
              ({
		vlib_cli_output (vm, "%=40U => %=20U",
				 format_ip6_address, ip6_addr,
				 format_ethernet_address, &mac_addr);
              }));
              /* *INDENT-ON* */
	    }

	  if ((detail || bd_tag) && (bd_config->bd_tag))
	    {
	      vlib_cli_output (vm, "\n  BD-Tag: %s", bd_config->bd_tag);

	    }
	}
    }
  vec_free (as);

  if (!printed)
    {
      vlib_cli_output (vm, "no bridge-domains in use");
    }

done:
  return error;
}

/*?
 * Show a summary of all the bridge-domain instances or detailed view of a
 * single bridge-domain. Bridge-domains are created by adding an interface
 * to a bridge using the '<em>set interface l2 bridge</em>' command.
 *
 * @cliexpar
 * @parblock
 * Example of displaying all bridge-domains:
 * @cliexstart{show bridge-domain}
 *  ID   Index   Learning   U-Forwrd   UU-Flood   Flooding   ARP-Term     BVI-Intf
 *  0      0        off        off        off        off        off        local0
 * 200     1        on         on         on         on         off          N/A
 * @cliexend
 *
 * Example of displaying details of a single bridge-domains:
 * @cliexstart{show bridge-domain 200 detail}
 *  ID   Index   Learning   U-Forwrd   UU-Flood   Flooding   ARP-Term     BVI-Intf
 * 200     1        on         on         on         on         off          N/A
 *
 *          Interface           Index  SHG  BVI        VLAN-Tag-Rewrite
 *  GigabitEthernet0/8/0.200      3     0    -               none
 *  GigabitEthernet0/9/0.200      4     0    -               none
 * @cliexend
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bd_show_cli, static) = {
  .path = "show bridge-domain",
  .short_help = "show bridge-domain [bridge-domain-id [detail|int|arp|bd-tag]]",
  .function = bd_show,
};
/* *INDENT-ON* */

int
bd_add_del (l2_bridge_domain_add_del_args_t * a)
{
  bd_main_t *bdm = &bd_main;
  vlib_main_t *vm = bdm->vlib_main;
  int rv = 0;

  u32 bd_index = bd_find_index (bdm, a->bd_id);
  if (a->is_add)
    {
      if (bd_index != ~0)
	return VNET_API_ERROR_BD_ALREADY_EXISTS;
      if (a->bd_id > L2_BD_ID_MAX)
	return VNET_API_ERROR_BD_ID_EXCEED_MAX;
      bd_index = bd_add_bd_index (bdm, a->bd_id);

      bd_flags_t enable_flags = 0, disable_flags = 0;
      if (a->flood)
	enable_flags |= L2_FLOOD;
      else
	disable_flags |= L2_FLOOD;

      if (a->uu_flood)
	enable_flags |= L2_UU_FLOOD;
      else
	disable_flags |= L2_UU_FLOOD;

      if (a->forward)
	enable_flags |= L2_FWD;
      else
	disable_flags |= L2_FWD;

      if (a->learn)
	enable_flags |= L2_LEARN;
      else
	disable_flags |= L2_LEARN;

      if (a->arp_term)
	enable_flags |= L2_ARP_TERM;
      else
	disable_flags |= L2_ARP_TERM;

      if (enable_flags)
	bd_set_flags (vm, bd_index, enable_flags, 1 /* enable */ );

      if (disable_flags)
	bd_set_flags (vm, bd_index, disable_flags, 0 /* disable */ );

      bd_set_mac_age (vm, bd_index, a->mac_age);

      if (a->bd_tag)
	bd_set_bd_tag (vm, bd_index, a->bd_tag);

    }
  else
    {
      if (bd_index == ~0)
	return VNET_API_ERROR_NO_SUCH_ENTRY;
      if (bd_index == 0)
	return VNET_API_ERROR_BD_NOT_MODIFIABLE;
      if (vec_len (l2input_main.bd_configs[bd_index].members))
	return VNET_API_ERROR_BD_IN_USE;
      rv = bd_delete (bdm, bd_index);
    }

  return rv;
}

/**
   Create or delete bridge-domain.
   The CLI format:
   create bridge-domain <bd_index> [learn <0|1>] [forward <0|1>] [uu-flood <0|1>] [flood <0|1>]
					[arp-term <0|1>] [mac-age <nn>] [bd-tag <tag>] [del]
*/

static clib_error_t *
bd_add_del_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u8 is_add = 1;
  u32 bd_id = ~0;
  u32 flood = 1, forward = 1, learn = 1, uu_flood = 1, arp_term = 0;
  u32 mac_age = 0;
  u8 *bd_tag = NULL;
  l2_bridge_domain_add_del_args_t _a, *a = &_a;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%d", &bd_id))
	;
      else if (unformat (line_input, "flood %d", &flood))
	;
      else if (unformat (line_input, "uu-flood %d", &uu_flood))
	;
      else if (unformat (line_input, "forward %d", &forward))
	;
      else if (unformat (line_input, "learn %d", &learn))
	;
      else if (unformat (line_input, "arp-term %d", &arp_term))
	;
      else if (unformat (line_input, "mac-age %d", &mac_age))
	;
      else if (unformat (line_input, "bd-tag %s", &bd_tag))
	;
      else if (unformat (line_input, "del"))
	{
	  is_add = 0;
	  flood = uu_flood = forward = learn = 0;
	}
      else
	break;
    }

  if (bd_id == ~0)
    {
      error = clib_error_return (0, "bridge-domain-id not specified");
      goto done;
    }

  if (bd_id == 0)
    {
      error = clib_error_return (0, "bridge domain 0 can not be modified");
      goto done;
    }

  if (mac_age > 255)
    {
      error = clib_error_return (0, "mac age must be less than 256");
      goto done;
    }
  if ((bd_tag) && (strlen ((char *) bd_tag) > 63))
    {
      error = clib_error_return (0, "bd-tag cannot be longer than 63");
      goto done;
    }

  clib_memset (a, 0, sizeof (*a));
  a->is_add = is_add;
  a->bd_id = bd_id;
  a->flood = (u8) flood;
  a->uu_flood = (u8) uu_flood;
  a->forward = (u8) forward;
  a->learn = (u8) learn;
  a->arp_term = (u8) arp_term;
  a->mac_age = (u8) mac_age;
  a->bd_tag = bd_tag;

  rv = bd_add_del (a);

  switch (rv)
    {
    case 0:
      if (is_add)
	vlib_cli_output (vm, "bridge-domain %d", bd_id);
      break;
    case VNET_API_ERROR_BD_IN_USE:
      error = clib_error_return (0, "bridge domain in use - remove members");
      goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "bridge domain ID does not exist");
      goto done;
    case VNET_API_ERROR_BD_NOT_MODIFIABLE:
      error = clib_error_return (0, "bridge domain 0 can not be modified");
      goto done;
    case VNET_API_ERROR_BD_ID_EXCEED_MAX:
      error = clib_error_return (0, "bridge domain ID exceed 16M limit");
      goto done;
    default:
      error = clib_error_return (0, "bd_add_del returned %d", rv);
      goto done;
    }

done:
  vec_free (bd_tag);
  unformat_free (line_input);

  return error;
}


/*?
 * Create/Delete bridge-domain instance
 *
 * @cliexpar
 * @parblock
 * Example of creating bridge-domain 1:
 * @cliexstart{create bridge-domain 1}
 * bridge-domain 1
 * @cliexend
 *
 * Example of creating bridge-domain 2 with enabling arp-term, mac-age 60:
 * @cliexstart{create bridge-domain 2 arp-term 1 mac-age 60}
 * bridge-domain 2
 *
 * vpp# show bridge-domain
 *   ID   Index   BSN  Age(min)  Learning  U-Forwrd  UU-Flood  Flooding  ARP-Term  BVI-Intf
 *   0      0      0     off       off       off       off       off       off      local0
 *   1      1      0     off        on        on       off        on       off       N/A
 *   2      2      0      60        on        on       off        on        on       N/A
 *
 * @cliexend
 *
 * Example of delete bridge-domain 1:
 * @cliexstart{create bridge-domain 1 del}
 * @cliexend
 * @endparblock
?*/

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bd_create_cli, static) = {
  .path = "create bridge-domain",
  .short_help = "create bridge-domain <bridge-domain-id>"
                " [learn <0|1>] [forward <0|1>] [uu-flood <0|1>] [flood <0|1>] [arp-term <0|1>]"
                " [mac-age <nn>] [bd-tag <tag>] [del]",
  .function = bd_add_del_command_fn,
};
/* *INDENT-ON* */



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
