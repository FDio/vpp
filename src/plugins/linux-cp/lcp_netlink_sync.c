/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>

#include <vlib/unix/plugin.h>
#include <linux-cp/lcp_netlink.h>
#include <linux-cp/lcp_interface.h>

#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/addr.h>
#include <netlink/route/link/vlan.h>

#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/ip/ip6_ll_table.h>
#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/ip/ip6_link.h>

typedef struct lcp_netlink_table_t_
{
  uint32_t nlt_id;
  fib_protocol_t nlt_proto;
  u32 nlt_fib_index;
  u32 nlt_mfib_index;
  u32 nlt_refs;
} lcp_netlink_table_t;

static uword *lcp_netlink_table_db[FIB_PROTOCOL_MAX];
static lcp_netlink_table_t *lcp_netlink_table_pool;
static vlib_log_class_t lcp_netlink_logger;

const static fib_prefix_t pfx_all1s = {
  .fp_addr = {
    .ip4 = {
      .as_u32 = 0xffffffff,
    }
  },
  .fp_proto = FIB_PROTOCOL_IP4,
  .fp_len = 32,
};

static fib_source_t lcp_rt_fib_src;
static fib_source_t lcp_rt_fib_src_dynamic;

static const mfib_prefix_t ip4_specials[] = {
  /* ALL prefixes are in network order */
  {
   /* (*,224.0.0.0)/24 - all local subnet */
   .fp_grp_addr = {
		   .ip4.data_u32 = 0x000000e0,
		   },
   .fp_len = 24,
   .fp_proto = FIB_PROTOCOL_IP4,
   },
};

static const mfib_prefix_t ip6_specials[] = {
  /* ALL prefixes are in network order */
  {
   /* (*,ff00::)/8 - all local subnet */
   .fp_grp_addr = {
		   .ip6.as_u64[0] = 0x00000000000000ff,
		   },
   .fp_len = 8,
   .fp_proto = FIB_PROTOCOL_IP6,
   },
};

/* VIF to PHY DB of managed interfaces */
static uword *lcp_routing_itf_db;

static u32
lcp_netlink_intf_h2p (u32 host)
{
  lcp_itf_pair_t *lip;
  index_t lipi;
  uword *p;

  /*
   * first check the linux side created interface (i.e. vlans, tunnels etc)
   */
  p = hash_get (lcp_routing_itf_db, host);

  if (p)
    return p[0];

  /*
   * then check the paired phys
   */
  lipi = lcp_itf_pair_find_by_vif (host);

  if (INDEX_INVALID == lipi)
    return (~0);

  lip = lcp_itf_pair_get (lipi);

  return lip->lip_phy_sw_if_index;
}

static void
lcp_netlink_link_del (struct rtnl_link *rl, void *ctx)
{
  lcp_itf_pair_t *lip;

  NL_DBG ("link_del: netlink %U", format_nl_object, rl);

  if (!(lip = lcp_itf_pair_get (
	  lcp_itf_pair_find_by_vif (rtnl_link_get_ifindex (rl)))))
    {
      NL_WARN ("link_del: no LCP for %U ", format_nl_object, rl);
      return;
    }

  NL_NOTICE ("link_del: Removing %U", format_lcp_itf_pair, lip);
  lcp_itf_pair_delete (lip->lip_phy_sw_if_index);

  if (rtnl_link_is_vlan (rl))
    {
      NL_NOTICE ("link_del: Removing subint %U", format_vnet_sw_if_index_name,
		 vnet_get_main (), lip->lip_phy_sw_if_index);
      vnet_delete_sub_interface (lip->lip_phy_sw_if_index);
      vnet_delete_sub_interface (lip->lip_host_sw_if_index);
    }

  return;
}

static void
lcp_netlink_ip4_mroutes_add_del (u32 sw_if_index, u8 is_add)
{
  const fib_route_path_t path = {
    .frp_proto = DPO_PROTO_IP4,
    .frp_addr = zero_addr,
    .frp_sw_if_index = sw_if_index,
    .frp_fib_index = ~0,
    .frp_weight = 1,
    .frp_mitf_flags = MFIB_ITF_FLAG_ACCEPT,
  };
  u32 mfib_index;
  int ii;

  mfib_index =
    mfib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index);

  for (ii = 0; ii < ARRAY_LEN (ip4_specials); ii++)
    {
      if (is_add)
	{
	  mfib_table_entry_path_update (mfib_index, &ip4_specials[ii],
					MFIB_SOURCE_PLUGIN_LOW,
					MFIB_ENTRY_FLAG_NONE, &path);
	}
      else
	{
	  mfib_table_entry_path_remove (mfib_index, &ip4_specials[ii],
					MFIB_SOURCE_PLUGIN_LOW, &path);
	}
    }
}

static void
lcp_netlink_ip6_mroutes_add_del (u32 sw_if_index, u8 is_add)
{
  const fib_route_path_t path = {
    .frp_proto = DPO_PROTO_IP6,
    .frp_addr = zero_addr,
    .frp_sw_if_index = sw_if_index,
    .frp_fib_index = ~0,
    .frp_weight = 1,
    .frp_mitf_flags = MFIB_ITF_FLAG_ACCEPT,
  };
  u32 mfib_index;
  int ii;

  mfib_index =
    mfib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6, sw_if_index);

  for (ii = 0; ii < ARRAY_LEN (ip6_specials); ii++)
    {
      if (is_add)
	{
	  mfib_table_entry_path_update (mfib_index, &ip6_specials[ii],
					MFIB_SOURCE_PLUGIN_LOW,
					MFIB_ENTRY_FLAG_NONE, &path);
	}
      else
	{
	  mfib_table_entry_path_remove (mfib_index, &ip6_specials[ii],
					MFIB_SOURCE_PLUGIN_LOW, &path);
	}
    }
}

static void
lcp_netlink_link_set_mtu (struct rtnl_link *rl, lcp_itf_pair_t *lip)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 mtu;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;

  mtu = rtnl_link_get_mtu (rl);
  if (!mtu)
    return;

  sw = vnet_get_sw_interface (vnm, lip->lip_phy_sw_if_index);
  hw = vnet_get_sup_hw_interface (vnm, lip->lip_phy_sw_if_index);
  if (!sw || !hw)
    return;

  /* Set the MTU on the TAP and sw */
  vnet_sw_interface_set_mtu (vnm, lip->lip_host_sw_if_index, mtu);
  vnet_sw_interface_set_mtu (vnm, lip->lip_phy_sw_if_index, mtu);
}

static void
lcp_netlink_link_set_lladdr (struct rtnl_link *rl, lcp_itf_pair_t *lip)
{
  vnet_main_t *vnm = vnet_get_main ();
  struct nl_addr *mac_addr;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;
  void *mac_addr_bytes;

  mac_addr = rtnl_link_get_addr (rl);
  if (!mac_addr || (nl_addr_get_family (mac_addr) != AF_LLC))
    return;

  sw = vnet_get_sw_interface (vnm, lip->lip_phy_sw_if_index);
  hw = vnet_get_sup_hw_interface (vnm, lip->lip_phy_sw_if_index);
  if (!sw || !hw)
    return;

  /* can only change address on hw interface */
  if (sw->sw_if_index != sw->sup_sw_if_index)
    return;
  /* can only change if there's an address present */
  if (!vec_len (hw->hw_address))
    return;

  mac_addr_bytes = nl_addr_get_binary_addr (mac_addr);
  if (clib_memcmp (mac_addr_bytes, hw->hw_address, nl_addr_get_len (mac_addr)))
    vnet_hw_interface_change_mac_address (vnm, hw->hw_if_index,
					  mac_addr_bytes);

  /* mcast adjacencies need to be updated */
  vnet_update_adjacency_for_sw_interface (vnm, lip->lip_phy_sw_if_index,
					  lip->lip_phy_adjs.adj_index[AF_IP4]);
  vnet_update_adjacency_for_sw_interface (vnm, lip->lip_phy_sw_if_index,
					  lip->lip_phy_adjs.adj_index[AF_IP6]);
}

static int
vnet_sw_interface_subid_exists (vnet_main_t *vnm, u32 sw_if_index, u32 id)
{
  u64 sup_and_sub_key = ((u64) (sw_if_index) << 32) | (u64) id;
  vnet_interface_main_t *im = &vnm->interface_main;
  uword *p;

  p = hash_get_mem (im->sw_if_index_by_sup_and_sub, &sup_and_sub_key);
  if (p)
    return 1;
  return 0;
}

static int
vnet_sw_interface_get_available_subid (vnet_main_t *vnm, u32 sw_if_index,
				       u32 *id)
{
  u32 i;

  for (i = 1; i < 4096; i++)
    {
      if (!vnet_sw_interface_subid_exists (vnm, sw_if_index, i))
	{
	  *id = i;
	  return 0;
	}
    }

  *id = -1;
  return 1;
}

// Returns the LIP for a newly created sub-int pair, or
// NULL in case no sub-int could be created.
static lcp_itf_pair_t *
lcp_netlink_link_add_vlan (struct rtnl_link *rl)
{
  vnet_main_t *vnm = vnet_get_main ();
  int parent_idx, idx;
  lcp_itf_pair_t *parent_lip, *phy_lip;
  vnet_sw_interface_t *parent_sw;
  int vlan;
  u32 proto;
  u32 subid;
  u32 inner_vlan, outer_vlan, flags;
  u32 phy_sw_if_index, host_sw_if_index;
  lcp_main_t *lcpm = &lcp_main;
  u8 old_lcp_auto_subint;

  if (!rtnl_link_is_vlan (rl))
    return NULL;

  idx = rtnl_link_get_ifindex (rl);
  parent_idx = rtnl_link_get_link (rl);
  vlan = rtnl_link_vlan_get_id (rl);
  proto = rtnl_link_vlan_get_protocol (rl);

  /* Get the LIP of the parent, can be a phy Te3/0/0 or a subint Te3/0/0.1000
   */
  if (!(parent_lip = lcp_itf_pair_get (lcp_itf_pair_find_by_vif (parent_idx))))
    {
      NL_WARN ("link_add_vlan: no LCP for parent of %U", format_nl_object, rl);
      return NULL;
    }

  parent_sw = vnet_get_sw_interface (vnm, parent_lip->lip_phy_sw_if_index);
  if (!parent_sw)
    {
      NL_ERROR ("link_add_vlan: Cannot get parent of %U", format_lcp_itf_pair,
		parent_lip);
      return NULL;
    }

  /* Get the LIP of the phy, ie "phy TenGigabitEthernet3/0/0 host tap1 host-if
   * e0" */
  phy_lip =
    lcp_itf_pair_get (lcp_itf_pair_find_by_phy (parent_sw->sup_sw_if_index));

  if (vnet_sw_interface_is_sub (vnm, parent_lip->lip_phy_sw_if_index))
    {
      // QinQ or QinAD
      inner_vlan = vlan;
      outer_vlan = parent_sw->sub.eth.outer_vlan_id;
      if (ntohs (proto) == ETH_P_8021AD)
	{
	  NL_ERROR ("link_add_vlan: cannot create inner dot1ad: %U",
		    format_nl_object, rl);
	  return NULL;
	}
    }
  else
    {
      inner_vlan = 0;
      outer_vlan = vlan;
    }

  // Flags: no_tags(1), one_tag(2), two_tags(4), dot1ad(8), exact_match(16) see
  // vnet/interface.h
  flags = 16; // exact-match
  if ((parent_sw->sub.eth.flags.dot1ad) || (ntohs (proto) == ETH_P_8021AD))
    flags += 8; // dot1ad
  if (inner_vlan)
    flags += 4; // two_tags
  else
    flags += 2; // one_tag

  /* Create sub on the phy and on the tap, but avoid triggering sub-int
   * autocreation if it's enabled.
   */
  old_lcp_auto_subint = lcpm->lcp_auto_subint;
  lcpm->lcp_auto_subint = 0;

  /* Create sub on the phy and on the tap, but avoid triggering sub-int
   * autocreation if it's enabled.
   */
  old_lcp_auto_subint = lcpm->lcp_auto_subint;
  lcpm->lcp_auto_subint = 0;

  /* Generate a subid, take the first available one */
  if (vnet_sw_interface_get_available_subid (vnm, parent_sw->sup_sw_if_index,
					     &subid))
    {
      NL_ERROR ("link_add_vlan: cannot find available subid on phy %U",
		format_vnet_sw_if_index_name, vnm, parent_sw->sup_sw_if_index);
      lcpm->lcp_auto_subint = old_lcp_auto_subint;
      return NULL;
    }

  NL_INFO (
    "link_add_vlan: creating subid %u outer %u inner %u flags %u on phy %U",
    subid, outer_vlan, inner_vlan, flags, format_vnet_sw_if_index_name, vnm,
    parent_sw->sup_sw_if_index);
  if (vnet_create_sub_interface (parent_sw->sup_sw_if_index, subid, flags,
				 inner_vlan, outer_vlan, &phy_sw_if_index))
    {
      NL_ERROR ("link_add_vlan: cannot create sub-int on phy %U flags %u "
		"inner-dot1q %u dot1%s %u",
		format_vnet_sw_if_index_name, vnm, parent_sw->sup_sw_if_index,
		flags, inner_vlan,
		parent_sw->sub.eth.flags.dot1ad ? "ad" : "q", outer_vlan);
      lcpm->lcp_auto_subint = old_lcp_auto_subint;
      return NULL;
    }

  /* Try to use the same subid on the TAP, generate a unique one otherwise. */
  if (vnet_sw_interface_subid_exists (vnm, phy_lip->lip_host_sw_if_index,
				      subid) &&
      vnet_sw_interface_get_available_subid (
	vnm, phy_lip->lip_host_sw_if_index, &subid))
    {
      NL_ERROR ("link_add_vlan: cannot find available subid on host %U",
		format_vnet_sw_if_index_name, vnm,
		phy_lip->lip_host_sw_if_index);
      lcpm->lcp_auto_subint = old_lcp_auto_subint;
      return NULL;
    }
  NL_INFO ("link_add_vlan: creating subid %u outer %u inner %u flags %u on "
	   "host %U phy %U",
	   subid, outer_vlan, inner_vlan, flags, format_vnet_sw_if_index_name,
	   vnm, parent_lip->lip_host_sw_if_index, format_vnet_sw_if_index_name,
	   vnm, phy_lip->lip_host_sw_if_index);

  if (vnet_create_sub_interface (phy_lip->lip_host_sw_if_index, subid, flags,
				 inner_vlan, outer_vlan, &host_sw_if_index))
    {
      NL_ERROR ("link_add_vlan: cannot create sub-int on host %U flags %u "
		"inner-dot1q %u dot1%s %u",
		format_vnet_sw_if_index_name, vnm,
		phy_lip->lip_host_sw_if_index, flags, inner_vlan,
		parent_sw->sub.eth.flags.dot1ad ? "ad" : "q", outer_vlan);
      lcpm->lcp_auto_subint = old_lcp_auto_subint;
      return NULL;
    }
  // Always keep sub-int on the TAP up
  vnet_sw_interface_admin_up (vnm, host_sw_if_index);
  NL_NOTICE ("link_add_vlan: Creating LCP for host %U phy %U name %s idx %d",
	     format_vnet_sw_if_index_name, vnm, host_sw_if_index,
	     format_vnet_sw_if_index_name, vnm, phy_sw_if_index,
	     rtnl_link_get_name (rl), idx);
  lcpm->lcp_auto_subint = old_lcp_auto_subint;

  u8 *if_namev = 0;
  char *if_name;
  if_name = rtnl_link_get_name (rl);
  vec_validate_init_c_string (if_namev, if_name, strnlen (if_name, IFNAMSIZ));
  lcp_itf_pair_add (host_sw_if_index, phy_sw_if_index, if_namev, idx,
		    phy_lip->lip_host_type, phy_lip->lip_namespace);
  vec_free (if_namev);

  // If all went well, we just created a new LIP and added it to the index --
  // so return that new (sub-interface) LIP to the caller.
  return lcp_itf_pair_get (lcp_itf_pair_find_by_phy (phy_sw_if_index));
}

static void
lcp_netlink_link_add (struct rtnl_link *rl, void *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  lcp_itf_pair_t *lip;
  int admin_state;

  NL_DBG ("link_add: netlink %U", format_nl_object, rl);

  /* For NEWLINK messages, if this interface doesn't have a LIP, it
   * may be a request to create a sub-int; so we call add_vlan()
   * to create it and pass its new LIP so we can finish the request.
   */
  if (!(lip = lcp_itf_pair_get (
	  lcp_itf_pair_find_by_vif (rtnl_link_get_ifindex (rl)))))
    {
      if (!(lip = lcp_netlink_link_add_vlan (rl)))
	return;
    }

  admin_state = (IFF_UP & rtnl_link_get_flags (rl));
  // Note: cannot use lcp_itf_set_link_state() here because it creates a loop
  // by sending a netlink message.
  if (admin_state)
    {
      vnet_sw_interface_admin_up (vnm, lip->lip_phy_sw_if_index);
    }
  else
    {
      vnet_sw_interface_admin_down (vnm, lip->lip_phy_sw_if_index);
    }

  lcp_netlink_link_set_mtu (rl, lip);
  lcp_netlink_link_set_lladdr (rl, lip);

  NL_INFO ("link_add: %U admin %s", format_lcp_itf_pair, lip,
	   admin_state ? "up" : "down");

  return;
}

static fib_protocol_t
lcp_netlink_proto_k2f (uint32_t k)
{
  if (AF_INET6 == k)
    return (FIB_PROTOCOL_IP6);
  return (FIB_PROTOCOL_IP4);
}

static void
lcp_netlink_mk_ip_addr (const struct nl_addr *rna, ip_address_t *ia)
{
  ip_address_reset (ia);
  ip_address_set (ia, nl_addr_get_binary_addr (rna),
		  nl_addr_get_family (rna) == AF_INET6 ? AF_IP6 : AF_IP4);
}

static void
lcp_netlink_mk_mac_addr (const struct nl_addr *rna, mac_address_t *mac)
{
  mac_address_from_bytes (mac, nl_addr_get_binary_addr (rna));
}

static fib_protocol_t
lcp_netlink_mk_addr46 (const struct nl_addr *rna, ip46_address_t *ia)
{
  fib_protocol_t fproto;

  fproto = lcp_netlink_proto_k2f (nl_addr_get_family (rna));
  ip46_address_reset (ia);
  if (FIB_PROTOCOL_IP4 == fproto)
    memcpy (&ia->ip4, nl_addr_get_binary_addr (rna), nl_addr_get_len (rna));
  else
    memcpy (&ia->ip6, nl_addr_get_binary_addr (rna), nl_addr_get_len (rna));

  return (fproto);
}

static void
lcp_netlink_mk_route_prefix (struct rtnl_route *r, fib_prefix_t *p)
{
  const struct nl_addr *addr = rtnl_route_get_dst (r);

  p->fp_len = nl_addr_get_prefixlen (addr);
  p->fp_proto = lcp_netlink_mk_addr46 (addr, &p->fp_addr);
}

static void
lcp_netlink_mk_route_mprefix (struct rtnl_route *r, mfib_prefix_t *p)
{
  const struct nl_addr *addr;

  addr = rtnl_route_get_dst (r);

  p->fp_len = nl_addr_get_prefixlen (addr);
  p->fp_proto = lcp_netlink_mk_addr46 (addr, &p->fp_grp_addr);

  addr = rtnl_route_get_src (r);
  if (addr)
    p->fp_proto = lcp_netlink_mk_addr46 (addr, &p->fp_src_addr);
}

static void
lcp_netlink_addr_add_del (struct rtnl_addr *ra, int is_del)
{
  lcp_itf_pair_t *lip;
  ip_address_t nh;

  NL_DBG ("addr_%s: netlink %U", is_del ? "del" : "add", format_nl_object, ra);

  if (!(lip = lcp_itf_pair_get (
	  lcp_itf_pair_find_by_vif (rtnl_addr_get_ifindex (ra)))))
    {
      NL_WARN ("addr_%s: no LCP for %U ", is_del ? "del" : "add",
	       format_nl_object, ra);
      return;
    }

  lcp_netlink_mk_ip_addr (rtnl_addr_get_local (ra), &nh);

  if (AF_IP4 == ip_addr_version (&nh))
    {
      ip4_add_del_interface_address (
	vlib_get_main (), lip->lip_phy_sw_if_index, &ip_addr_v4 (&nh),
	rtnl_addr_get_prefixlen (ra), is_del);
      lcp_netlink_ip4_mroutes_add_del (lip->lip_phy_sw_if_index, !is_del);
    }
  else if (AF_IP6 == ip_addr_version (&nh))
    {
      if (ip6_address_is_link_local_unicast (&ip_addr_v6 (&nh)))
	if (is_del)
	  ip6_link_disable (lip->lip_phy_sw_if_index);
	else
	  {
	    ip6_link_enable (lip->lip_phy_sw_if_index, NULL);
	    ip6_link_set_local_address (lip->lip_phy_sw_if_index,
					&ip_addr_v6 (&nh));
	  }
      else
	ip6_add_del_interface_address (
	  vlib_get_main (), lip->lip_phy_sw_if_index, &ip_addr_v6 (&nh),
	  rtnl_addr_get_prefixlen (ra), is_del);
      lcp_netlink_ip6_mroutes_add_del (lip->lip_phy_sw_if_index, !is_del);
    }

  NL_NOTICE ("addr_%s %U/%d iface %U", is_del ? "del: Deleted" : "add: Added",
	     format_ip_address, &nh, rtnl_addr_get_prefixlen (ra),
	     format_vnet_sw_if_index_name, vnet_get_main (),
	     lip->lip_phy_sw_if_index);
}

static void
lcp_netlink_addr_del (struct rtnl_addr *la)
{
  lcp_netlink_addr_add_del (la, 1);
}

static void
lcp_netlink_addr_add (struct rtnl_addr *la)
{
  lcp_netlink_addr_add_del (la, 0);
}

#ifndef NUD_VALID
#define NUD_VALID                                                             \
  (NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE | NUD_PROBE | NUD_STALE |        \
   NUD_DELAY)
#endif

static void
lcp_netlink_neigh_del (struct rtnl_neigh *rn)
{
  ip_address_t nh;
  int rv;
  NL_DBG ("neigh_del: netlink %U", format_nl_object, rn);

  lcp_itf_pair_t *lip;
  if (!(lip = lcp_itf_pair_get (
	  lcp_itf_pair_find_by_vif (rtnl_neigh_get_ifindex (rn)))))
    {
      NL_WARN ("neigh_del: no LCP for %U ", format_nl_object, rn);
      return;
    }

  lcp_netlink_mk_ip_addr (rtnl_neigh_get_dst (rn), &nh);
  rv = ip_neighbor_del (&nh, lip->lip_phy_sw_if_index);

  if (rv == 0 || rv == VNET_API_ERROR_NO_SUCH_ENTRY)
    {
      NL_INFO ("neigh_del: Deleted %U iface %U", format_ip_address, &nh,
	       format_vnet_sw_if_index_name, vnet_get_main (),
	       lip->lip_phy_sw_if_index);
    }
  else
    {
      NL_ERROR ("neigh_del: Failed %U iface %U", format_ip_address, &nh,
		format_vnet_sw_if_index_name, vnet_get_main (),
		lip->lip_phy_sw_if_index);
    }
}

static void
lcp_netlink_neigh_add (struct rtnl_neigh *rn)
{
  lcp_itf_pair_t *lip;
  struct nl_addr *ll;
  ip_address_t nh;
  int state;

  NL_DBG ("neigh_add: netlink %U", format_nl_object, rn);

  if (!(lip = lcp_itf_pair_get (
	  lcp_itf_pair_find_by_vif (rtnl_neigh_get_ifindex (rn)))))
    {
      NL_WARN ("neigh_add: no LCP for %U ", format_nl_object, rn);
      return;
    }

  lcp_netlink_mk_ip_addr (rtnl_neigh_get_dst (rn), &nh);
  ll = rtnl_neigh_get_lladdr (rn);
  state = rtnl_neigh_get_state (rn);

  if (ll && (state & NUD_VALID))
    {
      mac_address_t mac;
      ip_neighbor_flags_t flags;
      int rv;

      lcp_netlink_mk_mac_addr (ll, &mac);

      if (state & (NUD_NOARP | NUD_PERMANENT))
	flags = IP_NEIGHBOR_FLAG_STATIC;
      else
	flags = IP_NEIGHBOR_FLAG_DYNAMIC;

      rv = ip_neighbor_add (&nh, &mac, lip->lip_phy_sw_if_index, flags, NULL);

      if (rv)
	{
	  NL_ERROR ("neigh_add: Failed %U lladdr %U iface %U",
		    format_ip_address, &nh, format_mac_address, &mac,
		    format_vnet_sw_if_index_name, vnet_get_main (),
		    lip->lip_phy_sw_if_index);
	}
      else
	{
	  NL_INFO ("neigh_add: Added %U lladdr %U iface %U", format_ip_address,
		   &nh, format_mac_address, &mac, format_vnet_sw_if_index_name,
		   vnet_get_main (), lip->lip_phy_sw_if_index);
	}
    }
}

static lcp_netlink_table_t *
lcp_netlink_table_find (uint32_t id, fib_protocol_t fproto)
{
  uword *p;

  p = hash_get (lcp_netlink_table_db[fproto], id);

  if (p)
    return pool_elt_at_index (lcp_netlink_table_pool, p[0]);

  return (NULL);
}

static uint32_t
lcp_netlink_table_k2f (uint32_t k)
{
  // the kernel's table ID 255 is the default table
  if (k == 255 || k == 254)
    return 0;
  return k;
}

static lcp_netlink_table_t *
lcp_netlink_table_add_or_lock (uint32_t id, fib_protocol_t fproto)
{
  lcp_netlink_table_t *nlt;

  id = lcp_netlink_table_k2f (id);
  nlt = lcp_netlink_table_find (id, fproto);

  if (NULL == nlt)
    {
      pool_get_zero (lcp_netlink_table_pool, nlt);

      nlt->nlt_id = id;
      nlt->nlt_proto = fproto;

      nlt->nlt_fib_index = fib_table_find_or_create_and_lock (
	nlt->nlt_proto, nlt->nlt_id, lcp_rt_fib_src);
      nlt->nlt_mfib_index = mfib_table_find_or_create_and_lock (
	nlt->nlt_proto, nlt->nlt_id, MFIB_SOURCE_PLUGIN_LOW);

      hash_set (lcp_netlink_table_db[fproto], nlt->nlt_id,
		nlt - lcp_netlink_table_pool);

      if (FIB_PROTOCOL_IP4 == fproto)
	{
	  /* Set the all 1s address in this table to punt */
	  fib_table_entry_special_add (nlt->nlt_fib_index, &pfx_all1s,
				       lcp_rt_fib_src, FIB_ENTRY_FLAG_LOCAL);

	  const fib_route_path_t path = {
	    .frp_proto = DPO_PROTO_IP4,
	    .frp_addr = zero_addr,
	    .frp_sw_if_index = ~0,
	    .frp_fib_index = ~0,
	    .frp_weight = 1,
	    .frp_mitf_flags = MFIB_ITF_FLAG_FORWARD,
	    .frp_flags = FIB_ROUTE_PATH_LOCAL,
	  };
	  int ii;

	  for (ii = 0; ii < ARRAY_LEN (ip4_specials); ii++)
	    {
	      mfib_table_entry_path_update (
		nlt->nlt_mfib_index, &ip4_specials[ii], MFIB_SOURCE_PLUGIN_LOW,
		MFIB_ENTRY_FLAG_NONE, &path);
	    }
	}
      else if (FIB_PROTOCOL_IP6 == fproto)
	{
	  const fib_route_path_t path = {
	    .frp_proto = DPO_PROTO_IP6,
	    .frp_addr = zero_addr,
	    .frp_sw_if_index = ~0,
	    .frp_fib_index = ~0,
	    .frp_weight = 1,
	    .frp_mitf_flags = MFIB_ITF_FLAG_FORWARD,
	    .frp_flags = FIB_ROUTE_PATH_LOCAL,
	  };
	  int ii;

	  for (ii = 0; ii < ARRAY_LEN (ip6_specials); ii++)
	    {
	      mfib_table_entry_path_update (
		nlt->nlt_mfib_index, &ip6_specials[ii], MFIB_SOURCE_PLUGIN_LOW,
		MFIB_ENTRY_FLAG_NONE, &path);
	    }
	}
    }

  nlt->nlt_refs++;

  return (nlt);
}

static void
lcp_netlink_table_unlock (lcp_netlink_table_t *nlt)
{
  nlt->nlt_refs--;

  if (0 == nlt->nlt_refs)
    {
      if (FIB_PROTOCOL_IP4 == nlt->nlt_proto)
	{
	  /* Set the all 1s address in this table to punt */
	  fib_table_entry_special_remove (nlt->nlt_fib_index, &pfx_all1s,
					  lcp_rt_fib_src);
	}

      fib_table_unlock (nlt->nlt_fib_index, nlt->nlt_proto, lcp_rt_fib_src);

      hash_unset (lcp_netlink_table_db[nlt->nlt_proto], nlt->nlt_id);
      pool_put (lcp_netlink_table_pool, nlt);
    }
}

typedef struct lcp_netlink_route_path_parse_t_
{
  fib_route_path_t *paths;
  fib_protocol_t route_proto;
  bool is_mcast;
  fib_route_path_flags_t type_flags;
  u8 preference;
} lcp_netlink_route_path_parse_t;

static void
lcp_netlink_route_path_parse (struct rtnl_nexthop *rnh, void *arg)
{
  lcp_netlink_route_path_parse_t *ctx = arg;
  fib_route_path_t *path;
  u32 sw_if_index;

  sw_if_index = lcp_netlink_intf_h2p (rtnl_route_nh_get_ifindex (rnh));

  if (~0 != sw_if_index)
    {
      fib_protocol_t fproto;
      struct nl_addr *addr;

      vec_add2 (ctx->paths, path, 1);

      path->frp_flags = FIB_ROUTE_PATH_FLAG_NONE | ctx->type_flags;
      path->frp_sw_if_index = sw_if_index;
      path->frp_weight = rtnl_route_nh_get_weight (rnh);
      path->frp_preference = ctx->preference;

      addr = rtnl_route_nh_get_gateway (rnh);

      if (addr)
	fproto = lcp_netlink_mk_addr46 (rtnl_route_nh_get_gateway (rnh),
					&path->frp_addr);
      else
	fproto = ctx->route_proto;

      path->frp_proto = fib_proto_to_dpo (fproto);

      if (ctx->is_mcast)
	path->frp_mitf_flags = MFIB_ITF_FLAG_FORWARD;

      NL_DBG (" path:[%U]", format_fib_route_path, path);
    }
}

/*
 * blackhole, unreachable, prohibit will not have a next hop in an
 * RTM_NEWROUTE. Add a path for them.
 */
static void
lcp_netlink_route_path_add_special (struct rtnl_route *rr,
				    lcp_netlink_route_path_parse_t *ctx)
{
  fib_route_path_t *path;

  if (rtnl_route_get_type (rr) < RTN_BLACKHOLE)
    return;

  /* if it already has a path, it does not need us to add one */
  if (vec_len (ctx->paths) > 0)
    return;

  vec_add2 (ctx->paths, path, 1);

  path->frp_flags = FIB_ROUTE_PATH_FLAG_NONE | ctx->type_flags;
  path->frp_sw_if_index = ~0;
  path->frp_proto = fib_proto_to_dpo (ctx->route_proto);
  path->frp_preference = ctx->preference;

  NL_DBG (" path:[%U]", format_fib_route_path, path);
}

/*
 * Map of supported route types. Some types are omitted:
 * RTN_LOCAL - interface address addition creates these automatically
 * RTN_BROADCAST - same as RTN_LOCAL
 * RTN_UNSPEC, RTN_ANYCAST, RTN_THROW, RTN_NAT, RTN_XRESOLVE -
 *   There's not a VPP equivalent for these currently.
 */
static const u8 lcp_netlink_route_type_valid[__RTN_MAX] = {
  [RTN_UNICAST] = 1,	 [RTN_MULTICAST] = 1, [RTN_BLACKHOLE] = 1,
  [RTN_UNREACHABLE] = 1, [RTN_PROHIBIT] = 1,
};

/* Map of fib entry flags by route type */
static const fib_entry_flag_t lcp_netlink_route_type_feflags[__RTN_MAX] = {
  [RTN_LOCAL] = FIB_ENTRY_FLAG_LOCAL | FIB_ENTRY_FLAG_CONNECTED,
  [RTN_BROADCAST] = FIB_ENTRY_FLAG_DROP | FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT,
  [RTN_BLACKHOLE] = FIB_ENTRY_FLAG_DROP,
};

/* Map of fib route path flags by route type */
static const fib_route_path_flags_t
  lcp_netlink_route_type_frpflags[__RTN_MAX] = {
    [RTN_UNREACHABLE] = FIB_ROUTE_PATH_ICMP_UNREACH,
    [RTN_PROHIBIT] = FIB_ROUTE_PATH_ICMP_PROHIBIT,
    [RTN_BLACKHOLE] = FIB_ROUTE_PATH_DROP,
  };

static inline fib_source_t
lcp_netlink_proto_fib_source (u8 rt_proto)
{
  return (rt_proto <= RTPROT_STATIC) ? lcp_rt_fib_src : lcp_rt_fib_src_dynamic;
}

static fib_entry_flag_t
lcp_netlink_mk_route_entry_flags (uint8_t rtype, int table_id, uint8_t rproto)
{
  fib_entry_flag_t fef = FIB_ENTRY_FLAG_NONE;

  fef |= lcp_netlink_route_type_feflags[rtype];
  if ((rproto == RTPROT_KERNEL) || PREDICT_FALSE (255 == table_id))
    /* kernel proto is interface prefixes, 255 is linux's 'local' table */
    fef |= FIB_ENTRY_FLAG_ATTACHED | FIB_ENTRY_FLAG_CONNECTED;

  return (fef);
}

static void
lcp_netlink_route_del (struct rtnl_route *rr)
{
  uint32_t table_id;
  fib_prefix_t pfx;
  lcp_netlink_table_t *nlt;
  uint8_t rtype, rproto;

  NL_DBG ("route_del: netlink %U", format_nl_object, rr);

  rtype = rtnl_route_get_type (rr);
  table_id = rtnl_route_get_table (rr);
  rproto = rtnl_route_get_protocol (rr);

  /* skip unsupported route types and local table */
  if (!lcp_netlink_route_type_valid[rtype] || (table_id == 255))
    return;

  lcp_netlink_mk_route_prefix (rr, &pfx);
  nlt =
    lcp_netlink_table_find (lcp_netlink_table_k2f (table_id), pfx.fp_proto);

  if (NULL == nlt)
    {
      return;
    }

  lcp_netlink_route_path_parse_t np = {
    .route_proto = pfx.fp_proto,
    .type_flags = lcp_netlink_route_type_frpflags[rtype],
  };

  rtnl_route_foreach_nexthop (rr, lcp_netlink_route_path_parse, &np);
  lcp_netlink_route_path_add_special (rr, &np);

  if (0 != vec_len (np.paths))
    {
      fib_source_t fib_src = lcp_netlink_proto_fib_source (rproto);
      fib_entry_flag_t entry_flags;

      entry_flags = lcp_netlink_mk_route_entry_flags (rtype, table_id, rproto);
      NL_INFO ("route_del: table %d prefix %U flags %U",
	       rtnl_route_get_table (rr), format_fib_prefix, &pfx,
	       format_fib_entry_flags, entry_flags);
      if (pfx.fp_proto == FIB_PROTOCOL_IP6)
	fib_table_entry_delete (nlt->nlt_fib_index, &pfx, fib_src);
      else
	fib_table_entry_path_remove2 (nlt->nlt_fib_index, &pfx, fib_src,
				      np.paths);
    }

  vec_free (np.paths);

  lcp_netlink_table_unlock (nlt);
}

static void
lcp_netlink_route_add (struct rtnl_route *rr)
{
  fib_entry_flag_t entry_flags;
  uint32_t table_id;
  fib_prefix_t pfx;
  lcp_netlink_table_t *nlt;
  uint8_t rtype, rproto;

  NL_DBG ("route_add: netlink %U", format_nl_object, rr);

  rtype = rtnl_route_get_type (rr);
  table_id = rtnl_route_get_table (rr);
  rproto = rtnl_route_get_protocol (rr);

  /* skip unsupported route types and local table */
  if (!lcp_netlink_route_type_valid[rtype] || (table_id == 255))
    return;

  lcp_netlink_mk_route_prefix (rr, &pfx);
  entry_flags = lcp_netlink_mk_route_entry_flags (rtype, table_id, rproto);

  /* link local IPv6 */
  if (FIB_PROTOCOL_IP6 == pfx.fp_proto &&
      (ip6_address_is_multicast (&pfx.fp_addr.ip6) ||
       ip6_address_is_link_local_unicast (&pfx.fp_addr.ip6)))
    {
      NL_DBG ("route_add: skip linklocal table %d prefix %U flags %U",
	      rtnl_route_get_table (rr), format_fib_prefix, &pfx,
	      format_fib_entry_flags, entry_flags);
      return;
    }
  lcp_netlink_route_path_parse_t np = {
    .route_proto = pfx.fp_proto,
    .is_mcast = (rtype == RTN_MULTICAST),
    .type_flags = lcp_netlink_route_type_frpflags[rtype],
    .preference = (u8) rtnl_route_get_priority (rr),
  };

  rtnl_route_foreach_nexthop (rr, lcp_netlink_route_path_parse, &np);
  lcp_netlink_route_path_add_special (rr, &np);

  if (0 != vec_len (np.paths))
    {
      nlt = lcp_netlink_table_add_or_lock (table_id, pfx.fp_proto);
      if (rtype == RTN_MULTICAST)
	{
	  /* it's not clear to me how linux expresses the RPF paramters
	   * so we'll allow from all interfaces and hope for the best */
	  mfib_prefix_t mpfx = {};

	  lcp_netlink_mk_route_mprefix (rr, &mpfx);

	  NL_INFO ("route_add: mcast table %d prefix %U flags %U",
		   rtnl_route_get_table (rr), format_mfib_prefix, &mpfx,
		   format_fib_entry_flags, entry_flags);
	  mfib_table_entry_update (nlt->nlt_mfib_index, &mpfx,
				   MFIB_SOURCE_PLUGIN_LOW, MFIB_RPF_ID_NONE,
				   MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF);

	  mfib_table_entry_paths_update (nlt->nlt_mfib_index, &mpfx,
					 MFIB_SOURCE_PLUGIN_LOW,
					 MFIB_ENTRY_FLAG_NONE, np.paths);
	}
      else
	{
	  fib_source_t fib_src = lcp_netlink_proto_fib_source (rproto);

	  NL_INFO ("route_add: table %d prefix %U flags %U",
		   rtnl_route_get_table (rr), format_fib_prefix, &pfx,
		   format_fib_entry_flags, entry_flags);

	  if (pfx.fp_proto == FIB_PROTOCOL_IP6)
	    fib_table_entry_path_add2 (nlt->nlt_fib_index, &pfx, fib_src,
				       entry_flags, np.paths);
	  else
	    fib_table_entry_update (nlt->nlt_fib_index, &pfx, fib_src,
				    entry_flags, np.paths);
	}
    }
  else
    NL_WARN ("route_add: no paths table %d prefix %U flags %U netlink %U",
	     rtnl_route_get_table (rr), format_fib_prefix, &pfx,
	     format_fib_entry_flags, entry_flags, format_nl_object, rr);

  vec_free (np.paths);
}

const nl_vft_t lcp_netlink_vft = {
  .nvl_rt_link_add = { .is_mp_safe = 0, .cb = lcp_netlink_link_add },
  .nvl_rt_link_del = { .is_mp_safe = 0, .cb = lcp_netlink_link_del },
  .nvl_rt_addr_add = { .is_mp_safe = 0, .cb = lcp_netlink_addr_add },
  .nvl_rt_addr_del = { .is_mp_safe = 0, .cb = lcp_netlink_addr_del },
  .nvl_rt_neigh_add = { .is_mp_safe = 0, .cb = lcp_netlink_neigh_add },
  .nvl_rt_neigh_del = { .is_mp_safe = 0, .cb = lcp_netlink_neigh_del },
  .nvl_rt_route_add = { .is_mp_safe = 1, .cb = lcp_netlink_route_add },
  .nvl_rt_route_del = { .is_mp_safe = 1, .cb = lcp_netlink_route_del },
};

static clib_error_t *
lcp_netlink_sync_init (vlib_main_t *vm)
{
  lcp_netlink_logger = vlib_log_register_class ("linux-cp", "nl");

  lcp_nl_register_vft (&lcp_netlink_vft);

  /*
   * allocate 2 route sources. The low priority source will be for
   * dynamic routes. If a dynamic route daemon (FRR) tries to remove its
   * route, it will use the low priority source to ensure it will not
   * remove static routes which were added with the higher priority source.
   */
  lcp_rt_fib_src =
    fib_source_allocate ("lcp-rt", FIB_SOURCE_PRIORITY_HI, FIB_SOURCE_BH_API);

  lcp_rt_fib_src_dynamic = fib_source_allocate (
    "lcp-rt-dynamic", FIB_SOURCE_PRIORITY_HI + 1, FIB_SOURCE_BH_API);

  return (NULL);
}

VLIB_INIT_FUNCTION (lcp_netlink_sync_init) = {
  .runs_before = VLIB_INITS ("lcp_nl_init"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
