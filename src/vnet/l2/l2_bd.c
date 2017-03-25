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
  if (!bd_is_valid (bd_config))
    {
      bd_config->feature_bitmap = ~L2INPUT_FEAT_ARP_TERM;
      bd_config->bvi_sw_if_index = ~0;
      bd_config->members = 0;
      bd_config->flood_count = 0;
      bd_config->tun_master_count = 0;
      bd_config->tun_normal_count = 0;
      bd_config->mac_by_ip4 = 0;
      bd_config->mac_by_ip6 = hash_create_mem (0, sizeof (ip6_address_t),
					       sizeof (uword));
    }
}

u32
bd_find_or_add_bd_index (bd_main_t * bdm, u32 bd_id)
{
  uword *p;
  u32 rv;

  if (bd_id == ~0)
    {
      bd_id = 0;
      while (hash_get (bdm->bd_index_by_bd_id, bd_id))
	bd_id++;
    }
  else
    {
      p = hash_get (bdm->bd_index_by_bd_id, bd_id);
      if (p)
	return (p[0]);
    }

  rv = clib_bitmap_first_clear (bdm->bd_index_bitmap);

  /* mark this index busy */
  bdm->bd_index_bitmap = clib_bitmap_set (bdm->bd_index_bitmap, rv, 1);

  hash_set (bdm->bd_index_by_bd_id, bd_id, rv);

  vec_validate (l2input_main.bd_configs, rv);
  l2input_main.bd_configs[rv].bd_id = bd_id;

  return rv;
}

int
bd_delete_bd_index (bd_main_t * bdm, u32 bd_id)
{
  uword *p;
  u32 bd_index;

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (p == 0)
    return -1;

  bd_index = p[0];

  /* mark this index clear */
  bdm->bd_index_bitmap = clib_bitmap_set (bdm->bd_index_bitmap, bd_index, 0);
  hash_unset (bdm->bd_index_by_bd_id, bd_id);

  l2input_main.bd_configs[bd_index].bd_id = ~0;
  l2input_main.bd_configs[bd_index].feature_bitmap = 0;

  l2fib_flush_bd_mac (vlib_get_main (), bd_index);

  return 0;
}

static void
update_flood_count (l2_bridge_domain_t * bd_config)
{
  bd_config->flood_count = vec_len (bd_config->members) -
    (bd_config->tun_master_count ? bd_config->tun_normal_count : 0);
}

void
bd_add_member (l2_bridge_domain_t * bd_config, l2_flood_member_t * member)
{
  u32 ix;
  vnet_sw_interface_t *sw_if = vnet_get_sw_interface
    (vnet_get_main (), member->sw_if_index);

  /*
   * Add one element to the vector
   * vector is ordered [ bvi, normal/tun_masters..., tun_normals... ]
   * When flooding, the bvi interface (if present) must be the last member
   * processed due to how BVI processing can change the packet. To enable
   * this order, we make the bvi interface the first in the vector and
   * flooding walks the vector in reverse.
   */
  switch (sw_if->flood_class)
    {
    case VNET_FLOOD_CLASS_TUNNEL_MASTER:
      bd_config->tun_master_count++;
      /* Fall through */
    default:
      /* Fall through */
    case VNET_FLOOD_CLASS_NORMAL:
      ix = (member->flags & L2_FLOOD_MEMBER_BVI) ? 0 :
	vec_len (bd_config->members) - bd_config->tun_normal_count;
      break;
    case VNET_FLOOD_CLASS_TUNNEL_NORMAL:
      ix = vec_len (bd_config->members);
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
  u32 bd_index;
  bdm->bd_index_by_bd_id = hash_create (0, sizeof (uword));
  /*
   * create a dummy bd with bd_id of 0 and bd_index of 0 with feature set
   * to packet drop only. Thus, packets received from any L2 interface with
   * uninitialized bd_index of 0 can be dropped safely.
   */
  bd_index = bd_find_or_add_bd_index (bdm, 0);
  ASSERT (bd_index == 0);
  l2input_main.bd_configs[0].feature_bitmap = L2INPUT_FEAT_DROP;
  return 0;
}

VLIB_INIT_FUNCTION (l2bd_init);


/**
    Set the learn/forward/flood flags for the bridge domain.
    Return 0 if ok, non-zero if for an error.
*/
u32
bd_set_flags (vlib_main_t * vm, u32 bd_index, u32 flags, u32 enable)
{

  l2_bridge_domain_t *bd_config;
  u32 feature_bitmap = 0;

  vec_validate (l2input_main.bd_configs, bd_index);
  bd_config = vec_elt_at_index (l2input_main.bd_configs, bd_index);

  bd_validate (bd_config);

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

  return 0;
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
    if (bd_config->bd_id != ~0 && bd_config->mac_age != 0)
    enable = 1;

  vlib_process_signal_event (vm, l2fib_mac_age_scanner_process_node.index,
			     enable ? L2_MAC_AGE_PROCESS_EVENT_START :
			     L2_MAC_AGE_PROCESS_EVENT_STOP, 0);
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
  if (bd_set_flags (vm, bd_index, L2_LEARN, enable))
    {
      error =
	clib_error_return (0, "bridge-domain id %d out of range", bd_index);
      goto done;
    }

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
  if (bd_set_flags (vm, bd_index, L2_FWD, enable))
    {
      error =
	clib_error_return (0, "bridge-domain id %d out of range", bd_index);
      goto done;
    }

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
  if (bd_set_flags (vm, bd_index, L2_FLOOD, enable))
    {
      error =
	clib_error_return (0, "bridge-domain id %d out of range", bd_index);
      goto done;
    }

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
    Set bridge-domain unkown-unicast flood enable/disable.
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
  if (bd_set_flags (vm, bd_index, L2_UU_FLOOD, enable))
    {
      error =
	clib_error_return (0, "bridge-domain id %d out of range", bd_index);
      goto done;
    }

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

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (p)
    bd_index = *p;
  else
    return clib_error_return (0, "No such bridge domain %d", bd_id);

  enable = 1;
  if (unformat (input, "disable"))
    enable = 0;

  /* set the bridge domain flag */
  if (bd_set_flags (vm, bd_index, L2_ARP_TERM, enable))
    {
      error =
	clib_error_return (0, "bridge-domain id %d out of range", bd_index);
      goto done;
    }

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
 * which means this code *WILL NOT WORK* for a 32-bit prcessor with
 * 4-byte uword.
 */
u32
bd_add_del_ip_mac (u32 bd_index,
		   u8 * ip_addr, u8 * mac_addr, u8 is_ip6, u8 is_add)
{
  l2input_main_t *l2im = &l2input_main;
  l2_bridge_domain_t *bd_cfg = l2input_bd_config_from_index (l2im, bd_index);
  u64 new_mac = *(u64 *) mac_addr;
  u64 *old_mac;
  u16 *mac16 = (u16 *) & new_mac;

  ASSERT (sizeof (uword) == sizeof (u64));	/* make sure uword is 8 bytes */

  mac16[3] = 0;			/* Clear last 2 unsed bytes of the 8-byte MAC address */
  if (is_ip6)
    {
      ip6_address_t *ip6_addr_key;
      hash_pair_t *hp;
      old_mac = (u64 *) hash_get_mem (bd_cfg->mac_by_ip6, ip_addr);
      if (is_add)
	{
	  if (old_mac == 0)
	    {			/* new entry - allocate and craete ip6 address key */
	      ip6_addr_key = clib_mem_alloc (sizeof (ip6_address_t));
	      clib_memcpy (ip6_addr_key, ip_addr, sizeof (ip6_address_t));
	    }
	  else if (*old_mac == new_mac)
	    {			/* same mac entry already exist for ip6 address */
	      return 0;
	    }
	  else
	    {			/* updat mac for ip6 address */
	      hp = hash_get_pair (bd_cfg->mac_by_ip6, ip_addr);
	      ip6_addr_key = (ip6_address_t *) hp->key;
	    }
	  hash_set_mem (bd_cfg->mac_by_ip6, ip6_addr_key, new_mac);
	}
      else
	{
	  if (old_mac && (*old_mac == new_mac))
	    {
	      hp = hash_get_pair (bd_cfg->mac_by_ip6, ip_addr);
	      ip6_addr_key = (ip6_address_t *) hp->key;
	      hash_unset_mem (bd_cfg->mac_by_ip6, ip_addr);
	      clib_mem_free (ip6_addr_key);
	    }
	  else
	    return 1;
	}
    }
  else
    {
      ip4_address_t ip4_addr = *(ip4_address_t *) ip_addr;
      old_mac = (u64 *) hash_get (bd_cfg->mac_by_ip4, ip4_addr.as_u32);
      if (is_add)
	{
	  if (old_mac && (*old_mac == new_mac))
	    return 0;		/* mac entry already exist */
	  hash_set (bd_cfg->mac_by_ip4, ip4_addr.as_u32, new_mac);
	}
      else
	{
	  if (old_mac && (*old_mac == new_mac))
	    hash_unset (bd_cfg->mac_by_ip4, ip4_addr.as_u32);
	  else
	    return 1;
	}
    }
  return 0;
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
  bd_main_t *bdm = &bd_main;
  clib_error_t *error = 0;
  u32 bd_index, bd_id;
  u8 is_add = 1;
  u8 is_ip6 = 0;
  u8 ip_addr[16];
  u8 mac_addr[6];
  uword *p;

  if (!unformat (input, "%d", &bd_id))
    {
      error = clib_error_return (0, "expecting bridge-domain id but got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);

  if (p)
    bd_index = *p;
  else
    return clib_error_return (0, "No such bridge domain %d", bd_id);

  if (unformat (input, "%U", unformat_ip4_address, ip_addr))
    {
      is_ip6 = 0;
    }
  else if (unformat (input, "%U", unformat_ip6_address, ip_addr))
    {
      is_ip6 = 1;
    }
  else
    {
      error = clib_error_return (0, "expecting IP address but got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (!unformat (input, "%U", unformat_ethernet_address, mac_addr))
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
  if (bd_add_del_ip_mac (bd_index, ip_addr, mac_addr, is_ip6, is_add))
    {
      error = clib_error_return (0, "MAC %s for IP %U and MAC %U failed",
				 is_add ? "add" : "del",
				 is_ip6 ?
				 format_ip4_address : format_ip6_address,
				 ip_addr, format_ethernet_address, mac_addr);
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
  .short_help = "set bridge-domain arp entry <bridge-domain-id> <ip-addr> <mac-addr> [del]",
  .function = bd_arp_entry,
};
/* *INDENT-ON* */

u8 *
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
  u32 bd_id = ~0;
  uword *p;

  start = 0;
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
			       "%=5s %=7s %=4s %=9s %=9s %=9s %=9s %=9s %=9s %=9s",
			       "ID", "Index", "BSN", "Age(min)", "Learning",
			       "U-Forwrd", "UU-Flood", "Flooding", "ARP-Term",
			       "BVI-Intf");
	    }

	  if (bd_config->mac_age)
	    as = format (as, "%d", bd_config->mac_age);
	  else
	    as = format (as, "off");
	  vlib_cli_output (vm,
			   "%=5d %=7d %=4d %=9v %=9s %=9s %=9s %=9s %=9s %=9U",
			   bd_config->bd_id, bd_index, bd_config->seq_num, as,
			   bd_config->feature_bitmap & L2INPUT_FEAT_LEARN ?
			   "on" : "off",
			   bd_config->feature_bitmap & L2INPUT_FEAT_FWD ?
			   "on" : "off",
			   bd_config->feature_bitmap & L2INPUT_FEAT_UU_FLOOD ?
			   "on" : "off",
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
		l2_input_config_t *int_config =
		  l2input_intf_config (member->sw_if_index);
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
				 int_config->seq_num, member->shg,
				 member->flags & L2_FLOOD_MEMBER_BVI ? "*" :
				 "-", i < bd_config->flood_count ? "*" : "-",
				 format_vtr, vtr_opr, dot1q, tag1, tag2);
	      }
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
  .short_help = "show bridge-domain [bridge-domain-id [detail|int|arp]]",
  .function = bd_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
