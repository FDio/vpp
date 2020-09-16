/*
 * vrrp.c - vrrp plugin action functions
 *
 * Copyright 2019-2020 Rubicon Communications, LLC (Netgate)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/mfib/mfib_entry.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/adj/adj.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/igmp_packet.h>
#include <vnet/ip/ip6_link.h>

#include <vrrp/vrrp.h>
#include <vrrp/vrrp_packet.h>

#include <vpp/app/version.h>

vrrp_main_t vrrp_main;

static const mac_address_t ipv4_vmac = {
  .bytes = {0x00, 0x00, 0x5e, 0x00, 0x01, 0x00}
};

static const mac_address_t ipv6_vmac = {
  .bytes = {0x00, 0x00, 0x5e, 0x00, 0x02, 0x00}
};

typedef struct
{
  vrrp_vr_key_t key;
  u32 count;
} vrrp_hwif_vr_count_t;

typedef enum
{
  VRRP_IF_UPDATE_IP,
  VRRP_IF_UPDATE_HW_LINK,
  VRRP_IF_UPDATE_SW_ADMIN,
} vrrp_intf_update_type_t;

typedef struct
{
  vrrp_intf_update_type_t type;
  u32 sw_if_index;
  u32 hw_if_index;
  int intf_up;
} vrrp_intf_update_t;

static int vrrp_intf_is_up (u32 sw_if_index, u8 is_ipv6,
			    vrrp_intf_update_t * pending);

static walk_rc_t
vrrp_hwif_master_count_walk (vnet_main_t * vnm, u32 sw_if_index, void *arg)
{
  vrrp_hwif_vr_count_t *vr_count = arg;
  vrrp_vr_t *vr;

  vr = vrrp_vr_lookup (sw_if_index, vr_count->key.vr_id,
		       vr_count->key.is_ipv6);

  if (vr && (vr->runtime.state == VRRP_VR_STATE_MASTER))
    vr_count->count++;

  return WALK_CONTINUE;
}

/*
 * Get a count of VRs in master state on a given hardware interface with
 * the provided VR ID and AF.
 */
static u32
vrrp_vr_hwif_master_vrs_by_vrid (u32 hw_if_index, u8 vr_id, u8 is_ipv6)
{
  vnet_main_t *vnm = vnet_get_main ();
  vrrp_hwif_vr_count_t vr_count;

  clib_memset (&vr_count, 0, sizeof (vr_count));

  vr_count.key.vr_id = vr_id;
  vr_count.key.is_ipv6 = is_ipv6;

  vnet_hw_interface_walk_sw (vnm, hw_if_index,
			     vrrp_hwif_master_count_walk, &vr_count);

  return vr_count.count;
}

/*
 * Add or delete the VR virtual MAC address on the hardware interface
 * when a VR enters or leaves the master state.
 *
 * Multiple subinterfaces may host the same VR ID. We should only add or
 * delete the virtual MAC if this is the first VR being enabled on the
 * hardware interface or the last one being disabled, respectively.
 */
void
vrrp_vr_transition_vmac (vrrp_vr_t * vr, vrrp_vr_state_t new_state)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  vnet_hw_interface_t *hw;
  u8 enable = (new_state == VRRP_VR_STATE_MASTER);
  u32 n_master_vrs;

  hw = vnet_get_sup_hw_interface (vnm, vr->config.sw_if_index);
  n_master_vrs =
    vrrp_vr_hwif_master_vrs_by_vrid (hw->hw_if_index, vr->config.vr_id,
				     vrrp_vr_is_ipv6 (vr));

  /* enable only if current master vrs is 0, disable only if 0 or 1 */
  if ((enable && !n_master_vrs) || (!enable && (n_master_vrs < 2)))
    {
      clib_warning ("%s virtual MAC address %U on hardware interface %u",
		    (enable) ? "Adding" : "Deleting",
		    format_ethernet_address, vr->runtime.mac.bytes,
		    hw->hw_if_index);

      error = vnet_hw_interface_add_del_mac_address
	(vnm, hw->hw_if_index, vr->runtime.mac.bytes, enable);
    }

  if (error)
    clib_error_report (error);
}

/*
 * Manage VR interface data on transition to/from master:
 *  - enable or disable ARP/ND input feature if appropriate
 *  - update count of VRs in master state
 */
static void
vrrp_vr_transition_intf (vrrp_vr_t * vr, vrrp_vr_state_t new_state)
{
  vrrp_intf_t *intf;
  const char *arc_name = 0, *node_name = 0;
  const char *mc_arc_name = 0, *mc_node_name = 0;
  u8 is_ipv6 = vrrp_vr_is_ipv6 (vr);
  u32 *vr_index;
  int n_master_accept = 0;
  int n_started = 0;

  if (is_ipv6)
    {
      arc_name = "ip6-local";
      node_name = "vrrp6-nd-input";
      mc_arc_name = "ip6-multicast";
      mc_node_name = "vrrp6-accept-owner-input";
    }
  else
    {
      arc_name = "arp";
      node_name = "vrrp4-arp-input";
      mc_arc_name = "ip4-multicast";
      mc_node_name = "vrrp4-accept-owner-input";
    }

  intf = vrrp_intf_get (vr->config.sw_if_index);

  /* Check other VRs on this intf to see if features need to be toggled */
  vec_foreach (vr_index, intf->vr_indices[is_ipv6])
  {
    vrrp_vr_t *intf_vr = vrrp_vr_lookup_index (*vr_index);

    if (intf_vr == vr)
      continue;

    if (intf_vr->runtime.state == VRRP_VR_STATE_INIT)
      continue;

    n_started++;

    if ((intf_vr->runtime.state == VRRP_VR_STATE_MASTER) &&
	vrrp_vr_accept_mode_enabled (intf_vr))
      n_master_accept++;
  }

  /* If entering/leaving init state, start/stop ARP or ND feature if no other
   * VRs are active on the interface.
   */
  if (((vr->runtime.state == VRRP_VR_STATE_INIT) ||
       (new_state == VRRP_VR_STATE_INIT)) && (n_started == 0))
    vnet_feature_enable_disable (arc_name, node_name,
				 vr->config.sw_if_index,
				 (new_state != VRRP_VR_STATE_INIT), NULL, 0);

  /* Special housekeeping when entering/leaving master mode */
  if ((vr->runtime.state == VRRP_VR_STATE_MASTER) ||
      (new_state == VRRP_VR_STATE_MASTER))
    {
      /* Maintain count of master state VRs on interface */
      if (new_state == VRRP_VR_STATE_MASTER)
	intf->n_master_vrs[is_ipv6]++;
      else if (intf->n_master_vrs[is_ipv6] > 0)
	intf->n_master_vrs[is_ipv6]--;

      /* If accept mode is enabled and no other master on intf has accept
       * mode enabled, enable/disable feature node to avoid spurious drops by
       * spoofing check.
       */
      if (vrrp_vr_accept_mode_enabled (vr) && !n_master_accept)
	vnet_feature_enable_disable (mc_arc_name, mc_node_name,
				     vr->config.sw_if_index,
				     (new_state == VRRP_VR_STATE_MASTER),
				     NULL, 0);
    }
}

/* If accept mode enabled, add/remove VR addresses from interface */
static void
vrrp_vr_transition_addrs (vrrp_vr_t * vr, vrrp_vr_state_t new_state)
{
  vlib_main_t *vm = vlib_get_main ();
  u8 is_del;
  ip46_address_t *vr_addr;

  if (!vrrp_vr_accept_mode_enabled (vr))
    return;

  /* owner always has VR addresses configured, should never remove them */
  if (vrrp_vr_is_owner (vr))
    return;

  if (vrrp_vr_is_unicast (vr))
    return;

  /* only need to do something if entering or leaving master state */
  if ((vr->runtime.state != VRRP_VR_STATE_MASTER) &&
      (new_state != VRRP_VR_STATE_MASTER))
    return;

  is_del = (new_state != VRRP_VR_STATE_MASTER);

  clib_warning ("%s VR addresses on sw_if_index %u",
		(is_del) ? "Deleting" : "Adding", vr->config.sw_if_index);

  vec_foreach (vr_addr, vr->config.vr_addrs)
  {
    ip_interface_address_t *ia = NULL;

    /* We need to know the address length to use, find it from another
     * address on the interface. Or use a default (/24, /64).
     */
    if (!vrrp_vr_is_ipv6 (vr))
      {
	ip4_main_t *im = &ip4_main;
	ip4_address_t *intf4;

	intf4 =
	  ip4_interface_address_matching_destination
	  (im, &vr_addr->ip4, vr->config.sw_if_index, &ia);

	ip4_add_del_interface_address (vm, vr->config.sw_if_index,
				       &vr_addr->ip4,
				       (intf4 ? ia->address_length : 24),
				       is_del);
      }
    else
      {
	ip6_main_t *im = &ip6_main;
	ip6_address_t *intf6;

	intf6 =
	  ip6_interface_address_matching_destination
	  (im, &vr_addr->ip6, vr->config.sw_if_index, &ia);

	ip6_add_del_interface_address (vm, vr->config.sw_if_index,
				       &vr_addr->ip6,
				       (intf6 ? ia->address_length : 64),
				       is_del);
      }
  }
}

void
vrrp_vr_transition (vrrp_vr_t * vr, vrrp_vr_state_t new_state, void *data)
{

  clib_warning ("VR %U transitioning to %U", format_vrrp_vr_key, vr,
		format_vrrp_vr_state, new_state);

  /* Don't do anything if transitioning to the state VR is already in.
   * This should never happen, just covering our bases.
   */
  if (new_state == vr->runtime.state)
    return;

  if (new_state == VRRP_VR_STATE_MASTER)
    {
      /* RFC 5798 sec 6.4.1 (105) - startup event for VR with priority 255
       *          sec 6.4.2 (365) - master down timer fires on backup VR
       */

      vrrp_vr_multicast_group_join (vr);
      vrrp_adv_send (vr, 0);
      vrrp_garp_or_na_send (vr);

      vrrp_vr_timer_set (vr, VRRP_VR_TIMER_ADV);
    }
  else if (new_state == VRRP_VR_STATE_BACKUP)
    {
      /* RFC 5798 sec 6.4.1 (150) - startup event for VR with priority < 255
       *          sec 6.4.3 (735) - master preempted by higher priority VR
       */

      vrrp_vr_multicast_group_join (vr);

      if (vr->runtime.state == VRRP_VR_STATE_MASTER)
	{
	  vrrp_header_t *pkt = data;
	  vr->runtime.master_adv_int = vrrp_adv_int_from_packet (pkt);

	}
      else			/* INIT, INTF_DOWN */
	vr->runtime.master_adv_int = vr->config.adv_interval;

      vrrp_vr_skew_compute (vr);
      vrrp_vr_master_down_compute (vr);
      vrrp_vr_timer_set (vr, VRRP_VR_TIMER_MASTER_DOWN);

    }
  else if (new_state == VRRP_VR_STATE_INIT)
    {
      /* RFC 5798 sec 6.4.2 (345) - shutdown event for backup VR
       *          sec 6.4.3 (655) - shutdown event for master VR
       */

      vrrp_vr_timer_cancel (vr);
      if (vr->runtime.state == VRRP_VR_STATE_MASTER)
	vrrp_adv_send (vr, 1);
    }
  else if (new_state == VRRP_VR_STATE_INTF_DOWN)
    /* State is not specified by RFC. This is to avoid attempting to
     * send packets on an interface that's down and to avoid having a
     * VR believe it is already the master when an interface is brought up
     */
    vrrp_vr_timer_cancel (vr);

  /* add/delete virtual IP addrs if accept_mode is true */
  vrrp_vr_transition_addrs (vr, new_state);

  /* enable/disable input features if necessary */
  vrrp_vr_transition_intf (vr, new_state);

  /* add/delete virtual MAC address on NIC if necessary */
  vrrp_vr_transition_vmac (vr, new_state);

  vr->runtime.state = new_state;
}

#define VRRP4_MCAST_ADDR_AS_U8 { 224, 0, 0, 18 }
#define VRRP6_MCAST_ADDR_AS_U8 \
{ 0xff, 0x2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12 }

static const mfib_prefix_t all_vrrp4_routers = {
  .fp_proto = FIB_PROTOCOL_IP4,
  .fp_len = 32,
  .fp_grp_addr = {
		  .ip4 = {
			  .as_u8 = VRRP4_MCAST_ADDR_AS_U8,
			  },
		  },
};

static const mfib_prefix_t all_vrrp6_routers = {
  .fp_proto = FIB_PROTOCOL_IP6,
  .fp_len = 128,
  .fp_grp_addr = {
		  .ip6 = {
			  .as_u8 = VRRP6_MCAST_ADDR_AS_U8,
			  },
		  },
};

static int
vrrp_intf_enable_disable_mcast (u8 enable, u32 sw_if_index, u8 is_ipv6)
{
  vrrp_main_t *vrm = &vrrp_main;
  vrrp_vr_t *vr;
  vrrp_intf_t *intf;
  u32 fib_index;
  u32 n_vrs = 0;
  const mfib_prefix_t *vrrp_prefix;
  fib_protocol_t proto;
  vnet_link_t link_type;
  fib_route_path_t for_us = {
    .frp_sw_if_index = 0xffffffff,
    .frp_weight = 1,
    .frp_flags = FIB_ROUTE_PATH_LOCAL,
    .frp_mitf_flags = MFIB_ITF_FLAG_FORWARD,
  };
  fib_route_path_t via_itf = {
    .frp_sw_if_index = sw_if_index,
    .frp_weight = 1,
    .frp_mitf_flags = MFIB_ITF_FLAG_ACCEPT,
  };

  intf = vrrp_intf_get (sw_if_index);

  if (is_ipv6)
    {
      proto = FIB_PROTOCOL_IP6;
      link_type = VNET_LINK_IP6;
      vrrp_prefix = &all_vrrp6_routers;
    }
  else
    {
      proto = FIB_PROTOCOL_IP4;
      link_type = VNET_LINK_IP4;
      vrrp_prefix = &all_vrrp4_routers;
    }

  for_us.frp_proto = fib_proto_to_dpo (proto);
  via_itf.frp_proto = fib_proto_to_dpo (proto);
  fib_index = mfib_table_get_index_for_sw_if_index (proto, sw_if_index);

  /* *INDENT-OFF* */
  pool_foreach (vr, vrm->vrs,
  ({
    if (vrrp_vr_is_ipv6 (vr) == is_ipv6)
      n_vrs++;
  }));
  /* *INDENT-ON* */

  if (enable)
    {
      /* If this is the first VR configured, add the local mcast routes */
      if (n_vrs == 1)
	mfib_table_entry_path_update (fib_index, vrrp_prefix, MFIB_SOURCE_API,
				      &for_us);

      mfib_table_entry_path_update (fib_index, vrrp_prefix, MFIB_SOURCE_API,
				    &via_itf);
      intf->mcast_adj_index[! !is_ipv6] =
	adj_mcast_add_or_lock (proto, link_type, sw_if_index);
    }
  else
    {
      /* Remove mcast local routes if this is the last VR being deleted */
      if (n_vrs == 0)
	mfib_table_entry_path_remove (fib_index, vrrp_prefix, MFIB_SOURCE_API,
				      &for_us);

      mfib_table_entry_path_remove (fib_index, vrrp_prefix, MFIB_SOURCE_API,
				    &via_itf);
    }

  return 0;
}

static int
vrrp_intf_vr_add_del (u8 is_add, u32 sw_if_index, u32 vr_index, u8 is_ipv6)
{
  vrrp_intf_t *vr_intf;

  vr_intf = vrrp_intf_get (sw_if_index);
  if (!vr_intf)
    return -1;

  if (is_add)
    {
      if (!vec_len (vr_intf->vr_indices[is_ipv6]))
	vrrp_intf_enable_disable_mcast (1, sw_if_index, is_ipv6);

      vec_add1 (vr_intf->vr_indices[is_ipv6], vr_index);
    }
  else
    {
      u32 per_intf_index =
	vec_search (vr_intf->vr_indices[is_ipv6], vr_index);

      if (per_intf_index != ~0)
	vec_del1 (vr_intf->vr_indices[is_ipv6], per_intf_index);

      /* no more VRs on this interface, disable multicast */
      if (!vec_len (vr_intf->vr_indices[is_ipv6]))
	vrrp_intf_enable_disable_mcast (0, sw_if_index, is_ipv6);
    }

  return 0;
}

/* RFC 5798 section 8.3.2 says to take care not to configure more than
 * one VRRP router as the "IPvX address owner" of a VRID. Make sure that
 * all of the addresses configured for this VR are configured on the
 * interface.
 */
static int
vrrp_vr_valid_addrs_owner (vrrp_vr_config_t * vr_conf)
{
  ip46_address_t *addr;
  u8 is_ipv6 = (vr_conf->flags & VRRP_VR_IPV6) != 0;

  vec_foreach (addr, vr_conf->vr_addrs)
  {
    if (!ip_interface_has_address (vr_conf->sw_if_index, addr, !is_ipv6))
      return VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE;
  }

  return 0;
}

static int
vrrp_vr_valid_addrs_unused (vrrp_vr_config_t * vr_conf)
{
  ip46_address_t *vr_addr;
  u8 is_ipv6 = (vr_conf->flags & VRRP_VR_IPV6) != 0;

  vec_foreach (vr_addr, vr_conf->vr_addrs)
  {
    u32 vr_index;
    void *addr;

    addr = (is_ipv6) ? (void *) &vr_addr->ip6 : (void *) &vr_addr->ip4;
    vr_index = vrrp_vr_lookup_address (vr_conf->sw_if_index, is_ipv6, addr);
    if (vr_index != ~0)
      return VNET_API_ERROR_ADDRESS_IN_USE;
  }

  return 0;
}

static int
vrrp_vr_valid_addrs (vrrp_vr_config_t * vr_conf)
{
  int ret = 0;

  /* If the VR owns the addresses, make sure they are configured */
  if (vr_conf->priority == 255 &&
      (ret = vrrp_vr_valid_addrs_owner (vr_conf)) < 0)
    return ret;

  /* make sure no other VR has already configured any of the VR addresses */
  ret = vrrp_vr_valid_addrs_unused (vr_conf);

  return ret;
}

int
vrrp_vr_addr_add_del (vrrp_vr_t * vr, u8 is_add, ip46_address_t * vr_addr)
{
  vrrp_main_t *vmp = &vrrp_main;
  u32 vr_index;
  vrrp4_arp_key_t key4;
  vrrp6_nd_key_t key6;
  ip46_address_t *addr;

  if (!vr || !vr_addr)
    return VNET_API_ERROR_INVALID_ARGUMENT;

  vr_index = vr - vmp->vrs;

  if (vrrp_vr_is_ipv6 (vr))
    {
      key6.sw_if_index = vr->config.sw_if_index;
      key6.addr = vr_addr->ip6;
      if (is_add)
	{
	  hash_set_mem_alloc (&vmp->vrrp6_nd_lookup, &key6, vr_index);
	  vec_add1 (vr->config.vr_addrs, vr_addr[0]);
	}
      else
	{
	  hash_unset_mem_free (&vmp->vrrp6_nd_lookup, &key6);
	  vec_foreach (addr, vr->config.vr_addrs)
	  {
	    if (!ip46_address_cmp (addr, vr_addr))
	      {
		vec_del1 (vr->config.vr_addrs, vr->config.vr_addrs - addr);
		break;
	      }
	  }
	}
    }
  else
    {
      key4.sw_if_index = vr->config.sw_if_index;
      key4.addr = vr_addr->ip4;
      if (is_add)
	{
	  hash_set (vmp->vrrp4_arp_lookup, key4.as_u64, vr_index);
	  vec_add1 (vr->config.vr_addrs, vr_addr[0]);
	}
      else
	{
	  hash_unset (vmp->vrrp4_arp_lookup, key4.as_u64);
	  vec_foreach (addr, vr->config.vr_addrs)
	  {
	    if (!ip46_address_cmp (addr, vr_addr))
	      {
		vec_del1 (vr->config.vr_addrs, vr->config.vr_addrs - addr);
		break;
	      }
	  }
	}
    }

  return 0;
}

static void
vrrp_vr_addrs_add_del (vrrp_vr_t * vr, u8 is_add, ip46_address_t * vr_addrs)
{
  ip46_address_t *vr_addr;

  vec_foreach (vr_addr, vr_addrs)
  {
    vrrp_vr_addr_add_del (vr, is_add, vr_addr);
  }
}

/* Action function shared between message handler and debug CLI */
int
vrrp_vr_add_del (u8 is_add, vrrp_vr_config_t * vr_conf)
{
  vrrp_main_t *vrm = &vrrp_main;
  vnet_main_t *vnm = vnet_get_main ();
  vrrp_vr_key_t key;
  uword *p;
  u32 vr_index;
  vrrp_vr_t *vr = 0;
  int ret;

  if (vr_conf->sw_if_index == ~0 ||
      !vnet_sw_interface_is_valid (vnm, vr_conf->sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  clib_memset (&key, 0, sizeof (key));

  key.sw_if_index = vr_conf->sw_if_index;
  key.vr_id = vr_conf->vr_id;
  key.is_ipv6 = ((vr_conf->flags & VRRP_VR_IPV6) != 0);

  p = mhash_get (&vrm->vr_index_by_key, &key);

  if (is_add)
    {
      /* does a VR matching this key already exist ? */
      if (p)
	{
	  clib_warning ("VR %u for IPv%d already exists on sw_if_index %u",
			key.vr_id, (key.is_ipv6) ? 6 : 4, key.sw_if_index);
	  return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
	}

      /* were IPvX addresses included ? */
      if (!vec_len (vr_conf->vr_addrs))
	{
	  clib_warning ("Conf of VR %u for IPv%d on sw_if_index %u "
			" does not contain IP addresses",
			key.vr_id, (key.is_ipv6) ? 6 : 4, key.sw_if_index);
	  return VNET_API_ERROR_INVALID_SRC_ADDRESS;
	}

      /* Make sure the addresses are ok to use */
      if ((ret = vrrp_vr_valid_addrs (vr_conf)) < 0)
	return ret;

      pool_get_zero (vrm->vrs, vr);
      vr_index = vr - vrm->vrs;

      clib_memcpy (&vr->config, vr_conf, sizeof (vrrp_vr_config_t));

      vr->config.vr_addrs = 0;	/* allocate our own memory */
      vrrp_vr_addrs_add_del (vr, is_add, vr_conf->vr_addrs);

      vr->runtime.state = VRRP_VR_STATE_INIT;
      vr->runtime.timer_index = ~0;

      /* set virtual MAC based on IP version and VR ID */
      vr->runtime.mac = (key.is_ipv6) ? ipv6_vmac : ipv4_vmac;
      vr->runtime.mac.bytes[5] = vr_conf->vr_id;

      mhash_set (&vrm->vr_index_by_key, &key, vr_index, 0);
    }
  else
    {
      if (!p)
	{
	  clib_warning ("No VR %u for IPv%d exists on sw_if_index %u",
			key.vr_id, (key.is_ipv6) ? 6 : 4, key.sw_if_index);
	  return VNET_API_ERROR_NO_SUCH_ENTRY;
	}

      vr_index = p[0];
      vr = pool_elt_at_index (vrm->vrs, vr_index);

      vrrp_vr_tracking_ifs_add_del (vr, vr->tracking.interfaces, is_add);
      vrrp_vr_addrs_add_del (vr, is_add, vr->config.vr_addrs);
      mhash_unset (&vrm->vr_index_by_key, &key, 0);
      vec_free (vr->config.vr_addrs);
      vec_free (vr->tracking.interfaces);
      pool_put (vrm->vrs, vr);
    }

  vrrp_intf_vr_add_del (is_add, vr_conf->sw_if_index, vr_index, key.is_ipv6);

  return 0;
}

int
vrrp_vr_start_stop (u8 is_start, vrrp_vr_key_t * vr_key)
{
  vrrp_main_t *vmp = &vrrp_main;
  uword *p;
  vrrp_vr_t *vr = 0;

  p = mhash_get (&vmp->vr_index_by_key, vr_key);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vr = pool_elt_at_index (vmp->vrs, p[0]);

  /* return success if already in the desired state */
  switch (vr->runtime.state)
    {
    case VRRP_VR_STATE_INIT:
      if (!is_start)
	{
	  clib_warning ("Attempting to stop already stopped VR (%U)",
			format_vrrp_vr_key, vr);
	  return 0;
	}
      break;
    default:
      if (is_start)
	{
	  clib_warning ("Attempting to start already started VR (%U)",
			format_vrrp_vr_key, vr);
	  return 0;
	}
      break;
    }

  if (is_start)
    {
      if (vrrp_vr_is_unicast (vr) && vec_len (vr->config.peer_addrs) == 0)
	{
	  clib_warning ("Cannot start unicast VR without peers");
	  return VNET_API_ERROR_INIT_FAILED;
	}

      vmp->n_vrs_started++;

      if (!vrrp_intf_is_up (vr->config.sw_if_index, vrrp_vr_is_ipv6 (vr),
			    NULL))
	{
	  clib_warning ("VRRP VR started on down interface (%U)",
			format_vrrp_vr_key, vr);
	  vrrp_vr_transition (vr, VRRP_VR_STATE_INTF_DOWN, NULL);
	}
      else if (vrrp_vr_is_owner (vr))
	vrrp_vr_transition (vr, VRRP_VR_STATE_MASTER, NULL);
      else
	vrrp_vr_transition (vr, VRRP_VR_STATE_BACKUP, NULL);
    }
  else
    {
      vmp->n_vrs_started--;

      vrrp_vr_transition (vr, VRRP_VR_STATE_INIT, NULL);
    }

  clib_warning ("%d VRs configured, %d VRs running",
		pool_elts (vmp->vrs), vmp->n_vrs_started);

  return 0;
}

static int
vrrp_vr_set_peers_validate (vrrp_vr_t * vr, ip46_address_t * peers)
{
  if (!vrrp_vr_is_unicast (vr))
    {
      clib_warning ("Peers can only be set on a unicast VR");
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  if (vr->runtime.state != VRRP_VR_STATE_INIT)
    {
      clib_warning ("Cannot set peers on a running VR");
      return VNET_API_ERROR_RSRC_IN_USE;
    }

  if (vec_len (peers) == 0)
    {
      clib_warning ("No peer addresses provided");
      return VNET_API_ERROR_INVALID_DST_ADDRESS;
    }

  return 0;
}

int
vrrp_vr_set_peers (vrrp_vr_key_t * vr_key, ip46_address_t * peers)
{
  vrrp_main_t *vmp = &vrrp_main;
  uword *p;
  vrrp_vr_t *vr = 0;
  int ret = 0;

  p = mhash_get (&vmp->vr_index_by_key, vr_key);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vr = pool_elt_at_index (vmp->vrs, p[0]);

  ret = vrrp_vr_set_peers_validate (vr, peers);
  if (ret < 0)
    return ret;

  if (vr->config.peer_addrs)
    vec_free (vr->config.peer_addrs);

  vr->config.peer_addrs = vec_dup (peers);

  return 0;
}

/* Manage reference on the interface to the VRs which track that interface */
static void
vrrp_intf_tracking_vr_add_del (u32 sw_if_index, vrrp_vr_t * vr, u8 is_add)
{
  vrrp_intf_t *intf;
  u32 vr_index;
  u8 is_ipv6 = vrrp_vr_is_ipv6 (vr);
  int i;

  intf = vrrp_intf_get (sw_if_index);
  vr_index = vrrp_vr_index (vr);

  /* Try to find the VR index in the list of tracking VRs */
  vec_foreach_index (i, intf->tracking_vrs[is_ipv6])
  {
    if (vec_elt (intf->tracking_vrs[is_ipv6], i) != vr_index)
      continue;

    /* Current index matches VR index */
    if (!is_add)
      vec_delete (intf->tracking_vrs[is_ipv6], 1, i);

    /* If deleting, the job is done. If adding, it's already here */
    return;
  }

  /* vr index was not found. */
  if (is_add)
    vec_add1 (intf->tracking_vrs[is_ipv6], vr_index);
}

/* Check if sw intf admin state is up or in the process of coming up */
static int
vrrp_intf_sw_admin_up (u32 sw_if_index, vrrp_intf_update_t * pending)
{
  vnet_main_t *vnm = vnet_get_main ();
  int admin_up;

  if (pending && (pending->type == VRRP_IF_UPDATE_SW_ADMIN))
    admin_up = pending->intf_up;
  else
    admin_up = vnet_sw_interface_is_admin_up (vnm, sw_if_index);

  return admin_up;
}

/* Check if hw intf link state is up or int the process of coming up */
static int
vrrp_intf_hw_link_up (u32 sw_if_index, vrrp_intf_update_t * pending)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sup_sw;
  int link_up;

  sup_sw = vnet_get_sup_sw_interface (vnm, sw_if_index);

  if (pending && (pending->type == VRRP_IF_UPDATE_HW_LINK) &&
      (pending->hw_if_index == sup_sw->hw_if_index))
    link_up = pending->intf_up;
  else
    link_up = vnet_hw_interface_is_link_up (vnm, sup_sw->hw_if_index);

  return link_up;
}

/* Check if interface has ability to send IP packets. */
static int
vrrp_intf_ip_up (u32 sw_if_index, u8 is_ipv6, vrrp_intf_update_t * pending)
{
  int ip_up;

  if (pending && pending->type == VRRP_IF_UPDATE_IP)
    ip_up = pending->intf_up;
  else
    /* Either a unicast address has to be explicitly assigned, or
     * for IPv6 only, a link local assigned and multicast/ND enabled
     */
    ip_up =
      ((ip_interface_get_first_ip (sw_if_index, !is_ipv6) != 0) ||
       (is_ipv6 && ip6_link_is_enabled (sw_if_index)));

  return ip_up;
}

static int
vrrp_intf_is_up (u32 sw_if_index, u8 is_ipv6, vrrp_intf_update_t * pending)
{
  int admin_up, link_up, ip_up;

  admin_up = vrrp_intf_sw_admin_up (sw_if_index, pending);
  link_up = vrrp_intf_hw_link_up (sw_if_index, pending);
  ip_up = vrrp_intf_ip_up (sw_if_index, is_ipv6, pending);

  return (admin_up && link_up && ip_up);
}

/* Examine the state of interfaces tracked by a VR and compute the priority
 * adjustment that should be applied to the VR. If this is being called
 * by the hw_link_up_down callback, the pending new flags on the sup hw
 * interface have not been updated yet, so accept those as an optional
 * argument.
 */
void
vrrp_vr_tracking_ifs_compute (vrrp_vr_t * vr, vrrp_intf_update_t * pending)
{
  vrrp_vr_tracking_if_t *intf;
  u32 total_priority = 0;

  vec_foreach (intf, vr->tracking.interfaces)
  {
    if (vrrp_intf_is_up (intf->sw_if_index, vrrp_vr_is_ipv6 (vr), pending))
      continue;

    total_priority += intf->priority;
  }

  if (total_priority != vr->tracking.interfaces_dec)
    {
      clib_warning ("VR %U interface track adjustment change from %u to %u",
		    format_vrrp_vr_key, vr, vr->tracking.interfaces_dec,
		    total_priority);
      vr->tracking.interfaces_dec = total_priority;
    }
}

/* Manage tracked interfaces on a VR */
int
vrrp_vr_tracking_if_add_del (vrrp_vr_t * vr, u32 sw_if_index, u8 prio,
			     u8 is_add)
{
  vnet_main_t *vnm = vnet_get_main ();
  vrrp_vr_tracking_if_t *track_intf;

  /* VR can't track non-existent interface */
  if (!vnet_sw_interface_is_valid (vnm, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* VR can't track it's own interface */
  if (sw_if_index == vr->config.sw_if_index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX_2;

  /* update intf vector of tracking VRs */
  vrrp_intf_tracking_vr_add_del (sw_if_index, vr, is_add);

  /* update VR vector of tracked interfaces */
  vec_foreach (track_intf, vr->tracking.interfaces)
  {
    if (track_intf->sw_if_index != sw_if_index)
      continue;

    /* found it */
    if (!is_add)
      vec_delete
	(vr->tracking.interfaces, 1, track_intf - vr->tracking.interfaces);

    return 0;
  }

  if (is_add)
    {
      vec_add2 (vr->tracking.interfaces, track_intf, 1);

      track_intf->sw_if_index = sw_if_index;
      track_intf->priority = prio;
    }

  return 0;
}

int
vrrp_vr_tracking_ifs_add_del (vrrp_vr_t * vr,
			      vrrp_vr_tracking_if_t * track_ifs, u8 is_add)
{
  vrrp_vr_tracking_if_t *track_if, *ifs_copy;
  int rv = 0;

  /* if deleting & track_ifs points to the VR list of tracked intfs, the
   * vector could be modified as we iterate it. make a copy instead */
  ifs_copy = vec_dup (track_ifs);

  /* add each tracked interface in the vector */
  vec_foreach (track_if, ifs_copy)
  {
    rv = vrrp_vr_tracking_if_add_del (vr, track_if->sw_if_index,
				      track_if->priority, (is_add != 0));

    /* if operation failed, undo the previous changes */
    if (rv)
      {
	vrrp_vr_tracking_if_t *rb_if;

	for (rb_if = track_if - 1; rb_if >= track_ifs; rb_if -= 1)
	  vrrp_vr_tracking_if_add_del (vr, rb_if->sw_if_index,
				       rb_if->priority, !(is_add != 0));
	break;
      }
  }

  vec_free (ifs_copy);

  vrrp_vr_tracking_ifs_compute (vr, 0);

  return rv;
}

/* Compute priority to advertise on all VRs which track the given interface
 * and address family. The flags on an HW interface are not updated until
 * after link up/down callbacks are invoked, so if this function is called
 * by the link up/down callback, the flags about to be set will be passed
 * via the 'pending' argument. Otherwise, pending will be NULL.
 */
static void
vrrp_intf_tracking_vrs_compute (u32 sw_if_index,
				vrrp_intf_update_t * pending, u8 is_ipv6)
{
  u32 *vr_index;
  vrrp_vr_t *vr;
  vrrp_intf_t *intf = vrrp_intf_get (sw_if_index);

  vec_foreach (vr_index, intf->tracking_vrs[is_ipv6])
  {
    vr = vrrp_vr_lookup_index (*vr_index);
    if (vr)
      vrrp_vr_tracking_ifs_compute (vr, pending);
  }
}

/* Interface being brought up/down is a quasi-{startup/shutdown} event.
 * Execute an appropriate state transition for all VRs on the interface.
 * This function may be invoked by:
 *    sw interface admin up/down event
 *    hw interface link up/down event
 */
clib_error_t *
vrrp_sw_interface_up_down (vrrp_intf_update_t * pending)
{
  vrrp_intf_t *intf;
  int i;
  u32 *vr_index;
  vrrp_vr_t *vr;

  intf = vrrp_intf_get (pending->sw_if_index);
  if (!intf)
    return 0;

  /* adjust state of VR's configured on this interface */
  for (i = 0; i < 2; i++)
    {
      int is_up;

      if (!intf->vr_indices[i])
	continue;

      is_up = vrrp_intf_is_up (pending->sw_if_index, i, pending);

      vec_foreach (vr_index, intf->vr_indices[i])
      {
	vrrp_vr_state_t vr_state;

	vr = vrrp_vr_lookup_index (*vr_index);
	if (!vr)
	  continue;

	if (vr->runtime.state == VRRP_VR_STATE_INIT)
	  continue;		/* VR not started yet, no transition */

	if (!is_up)
	  vr_state = VRRP_VR_STATE_INTF_DOWN;
	else
	  {
	    if (vr->runtime.state != VRRP_VR_STATE_INTF_DOWN)
	      continue;		/* shouldn't happen */

	    vr_state = (vrrp_vr_is_owner (vr)) ?
	      VRRP_VR_STATE_MASTER : VRRP_VR_STATE_BACKUP;
	  }

	vrrp_vr_transition (vr, vr_state, NULL);
      }
    }

  /* compute adjustments on any VR's tracking this interface */
  vrrp_intf_tracking_vrs_compute (pending->sw_if_index, pending,
				  0 /* is_ipv6 */ );
  vrrp_intf_tracking_vrs_compute (pending->sw_if_index, pending,
				  1 /* is_ipv6 */ );

  return 0;
}

/* Process change in admin status on an interface */
clib_error_t *
vrrp_sw_interface_admin_up_down (vnet_main_t * vnm, u32 sw_if_index,
				 u32 flags)
{
  vrrp_intf_update_t pending = {
    .type = VRRP_IF_UPDATE_SW_ADMIN,
    .sw_if_index = sw_if_index,
    .intf_up = ((flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0),
  };

  return vrrp_sw_interface_up_down (&pending);
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (vrrp_sw_interface_admin_up_down);

static walk_rc_t
vrrp_hw_interface_link_up_down_walk (vnet_main_t * vnm,
				     u32 sw_if_index, void *arg)
{
  vrrp_intf_update_t *pending = arg;

  pending->sw_if_index = sw_if_index;
  vrrp_sw_interface_up_down (pending);

  return WALK_CONTINUE;
}

static clib_error_t *
vrrp_hw_interface_link_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vrrp_intf_update_t pending = {
    .type = VRRP_IF_UPDATE_HW_LINK,
    .hw_if_index = hw_if_index,
    .intf_up = ((flags & VNET_HW_INTERFACE_FLAG_LINK_UP) != 0),
  };

  /* walk the sw interface and sub interfaces to adjust interface tracking */
  vnet_hw_interface_walk_sw (vnm, hw_if_index,
			     vrrp_hw_interface_link_up_down_walk, &pending);

  return 0;
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (vrrp_hw_interface_link_up_down);

static void
vrrp_ip4_add_del_interface_addr (ip4_main_t * im,
				 uword opaque,
				 u32 sw_if_index,
				 ip4_address_t * address,
				 u32 address_length,
				 u32 if_address_index, u32 is_del)
{
  vrrp_intf_tracking_vrs_compute (sw_if_index, NULL, 0 /* is_ipv6 */ );
}

static ip6_link_delegate_id_t vrrp_ip6_delegate_id;

static u8 *
format_vrrp_ip6_link (u8 * s, va_list * args)
{
  index_t indi = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);
  vrrp_intf_t *intf;
  u32 *vr_index;

  intf = vrrp_intf_get ((u32) indi);

  s = format (s, "%UVRRP VRs monitoring this link:\n",
	      format_white_space, indent);

  vec_foreach (vr_index, intf->tracking_vrs[1])
  {
    vrrp_vr_t *vr = vrrp_vr_lookup_index (*vr_index);

    s = format (s, "%U%U\n", format_white_space, indent + 2,
		format_vrrp_vr_key, vr);
  }

  return s;
}

static void
vrrp_intf_ip6_enable_disable (u32 sw_if_index, int enable)
{
  vrrp_intf_update_t pending = {
    .type = VRRP_IF_UPDATE_IP,
    .sw_if_index = sw_if_index,
    .intf_up = enable,
  };

  vrrp_intf_tracking_vrs_compute (sw_if_index, &pending, 1 /* is_ipv6 */ );
}

static void
vrrp_intf_ip6_enable (u32 sw_if_index)
{
  vrrp_intf_ip6_enable_disable (sw_if_index, 1 /* enable */ );
  ip6_link_delegate_update (sw_if_index, vrrp_ip6_delegate_id, sw_if_index);
}

static void
vrrp_intf_ip6_disable (index_t indi)
{
  vrrp_intf_ip6_enable_disable (indi, 0 /* enable */ );
}

const static ip6_link_delegate_vft_t vrrp_ip6_delegate_vft = {
  .ildv_enable = vrrp_intf_ip6_enable,
  .ildv_disable = vrrp_intf_ip6_disable,
  .ildv_format = format_vrrp_ip6_link,
};

static clib_error_t *
vrrp_init (vlib_main_t * vm)
{
  vrrp_main_t *vmp = &vrrp_main;
  clib_error_t *error = 0;
  ip4_main_t *im4 = &ip4_main;
  ip4_add_del_interface_address_callback_t cb4;
  vlib_node_t *intf_output_node;

  clib_memset (vmp, 0, sizeof (*vmp));

  if ((error = vlib_call_init_function (vm, ip4_lookup_init)) ||
      (error = vlib_call_init_function (vm, ip6_lookup_init)))
    return error;

  vmp->vlib_main = vm;
  vmp->vnet_main = vnet_get_main ();

  intf_output_node = vlib_get_node_by_name (vm, (u8 *) "interface-output");
  vmp->intf_output_node_idx = intf_output_node->index;

  error = vrrp_plugin_api_hookup (vm);

  if (error)
    return error;

  mhash_init (&vmp->vr_index_by_key, sizeof (u32), sizeof (vrrp_vr_key_t));
  vmp->vrrp4_arp_lookup = hash_create (0, sizeof (uword));
  vmp->vrrp6_nd_lookup = hash_create_mem (0, sizeof (vrrp6_nd_key_t),
					  sizeof (uword));

  cb4.function = vrrp_ip4_add_del_interface_addr;
  cb4.function_opaque = 0;
  vec_add1 (im4->add_del_interface_address_callbacks, cb4);

  vrrp_ip6_delegate_id = ip6_link_delegate_register (&vrrp_ip6_delegate_vft);

  return error;
}

VLIB_INIT_FUNCTION (vrrp_init);


/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "VRRP v3 (RFC 5798)",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
