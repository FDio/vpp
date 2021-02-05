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

//#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include <linux-cp/lcp_nl.h>
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

typedef struct lcp_router_table_t_
{
  uint32_t nlt_id;
  fib_protocol_t nlt_proto;
  u32 nlt_fib_index;
  u32 nlt_mfib_index;
  u32 nlt_refs;
} lcp_router_table_t;

static uword *lcp_router_table_db[FIB_PROTOCOL_MAX];
static lcp_router_table_t *lcp_router_table_pool;
static vlib_log_class_t lcp_router_logger;

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

#define LCP_ROUTER_DBG(...) vlib_log_debug (lcp_router_logger, __VA_ARGS__);

#define LCP_ROUTER_INFO(...) vlib_log_notice (lcp_router_logger, __VA_ARGS__);

#define LCP_ROUTER_ERROR(...) vlib_log_err (lcp_router_logger, __VA_ARGS__);

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
lcp_router_intf_h2p (u32 host)
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

/*
 * Check timestamps on netlink message and interface pair to decide whether
 * the message should be applied. See the declaration of nl_msg_info_t for
 * an explanation on why this is necessary.
 * If timestamps are good (message ts is newer than intf pair ts), return 0.
 * Else, return -1.
 */
static int
lcp_router_lip_ts_check (nl_msg_info_t *msg_info, lcp_itf_pair_t *lip)
{
  if (msg_info->ts > lip->lip_create_ts)
    return 0;

  LCP_ROUTER_INFO ("Early message received for %U",
		   format_vnet_sw_if_index_name, vnet_get_main (),
		   lip->lip_phy_sw_if_index);
  return -1;
}

static void
lcp_router_link_del (struct rtnl_link *rl, void *ctx)
{
  index_t lipi;

  if (!lcp_auto_subint ())
    return;

  lipi = lcp_itf_pair_find_by_vif (rtnl_link_get_ifindex (rl));

  if (INDEX_INVALID != lipi)
    {
      lcp_itf_pair_t *lip;

      lip = lcp_itf_pair_get (lipi);

      if (lcp_router_lip_ts_check ((nl_msg_info_t *) ctx, lip))
	return;

      LCP_ROUTER_INFO ("delete link: %s - %U", rtnl_link_get_type (rl),
		       format_vnet_sw_if_index_name, vnet_get_main (),
		       lip->lip_phy_sw_if_index);
      lcp_itf_pair_delete (lip->lip_phy_sw_if_index);

      if (rtnl_link_is_vlan (rl))
	{
	  LCP_ROUTER_INFO ("delete vlan: %s -> %U", rtnl_link_get_name (rl),
			   format_vnet_sw_if_index_name, vnet_get_main (),
			   lip->lip_phy_sw_if_index);
	  vnet_delete_sub_interface (lip->lip_phy_sw_if_index);
	  vnet_delete_sub_interface (lip->lip_host_sw_if_index);
	}
    }
  else
    LCP_ROUTER_INFO ("ignore link del: %s - %s", rtnl_link_get_type (rl),
		     rtnl_link_get_name (rl));
}

static void
lcp_router_ip4_mroutes_add_del (u32 sw_if_index, u8 is_add)
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
lcp_router_ip6_mroutes_add_del (u32 sw_if_index, u8 is_add)
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
lcp_router_link_mtu (struct rtnl_link *rl, u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 mtu;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;

  mtu = rtnl_link_get_mtu (rl);
  if (!mtu)
    return;

  sw = vnet_get_sw_interface (vnm, sw_if_index);
  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);

  /* If HW interface, try to change hw link */
  if ((sw->type == sw->sup_sw_if_index) &&
      (hw->hw_class_index == ethernet_hw_interface_class.index))
    vnet_hw_interface_set_mtu (vnm, hw->hw_if_index, mtu);
  else
    vnet_sw_interface_set_mtu (vnm, sw->sw_if_index, mtu);
}

static void
lcp_router_link_addr (struct rtnl_link *rl, lcp_itf_pair_t *lip)
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

  /* can only change address on hw interface */
  if (sw->sw_if_index != sw->sup_sw_if_index)
    return;

  hw = vnet_get_sup_hw_interface (vnm, lip->lip_phy_sw_if_index);
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

static void
lcp_router_link_add (struct rtnl_link *rl, void *ctx)
{
  index_t lipi;
  int up;
  vnet_main_t *vnm = vnet_get_main ();

  lipi = lcp_itf_pair_find_by_vif (rtnl_link_get_ifindex (rl));
  up = IFF_UP & rtnl_link_get_flags (rl);

  if (INDEX_INVALID != lipi)
    {
      lcp_itf_pair_t *lip;

      lip = lcp_itf_pair_get (lipi);
      if (!vnet_get_sw_interface (vnm, lip->lip_phy_sw_if_index))
	return;

      if (lcp_router_lip_ts_check ((nl_msg_info_t *) ctx, lip))
	return;

      if (up)
	{
	  vnet_sw_interface_admin_up (vnet_get_main (),
				      lip->lip_phy_sw_if_index);
	}
      else
	{
	  vnet_sw_interface_admin_down (vnet_get_main (),
					lip->lip_phy_sw_if_index);
	}
      LCP_ROUTER_DBG ("link: %s (%d) -> %U/%U %s", rtnl_link_get_name (rl),
		      rtnl_link_get_ifindex (rl), format_vnet_sw_if_index_name,
		      vnm, lip->lip_phy_sw_if_index,
		      format_vnet_sw_if_index_name, vnm,
		      lip->lip_host_sw_if_index, (up ? "up" : "down"));

      lcp_router_link_mtu (rl, lip->lip_phy_sw_if_index);
      lcp_router_link_addr (rl, lip);
    }
  else if (lcp_auto_subint () && rtnl_link_is_vlan (rl))
    {
      /* Find the pair based on the parent VIF */
      lipi = lcp_itf_pair_find_by_vif (rtnl_link_get_link (rl));

      if (INDEX_INVALID != lipi)
	{
	  u32 sub_phy_sw_if_index, sub_host_sw_if_index;
	  const lcp_itf_pair_t *lip;
	  int vlan;
	  u8 *ns = 0; /* FIXME */

	  lip = lcp_itf_pair_get (lipi);

	  vlan = rtnl_link_vlan_get_id (rl);

	  /* create the vlan interface on the parent phy */
	  if (vnet_create_sub_interface (lip->lip_phy_sw_if_index, vlan, 18, 0,
					 vlan, &sub_phy_sw_if_index))
	    {
	      LCP_ROUTER_INFO ("failed create phy vlan: %s on %U",
			       rtnl_link_get_name (rl),
			       format_vnet_sw_if_index_name, vnet_get_main (),
			       lip->lip_phy_sw_if_index);
	      return;
	    }
	  /* create the vlan interface on the parent host */
	  if (vnet_create_sub_interface (lip->lip_host_sw_if_index, vlan, 18,
					 0, vlan, &sub_host_sw_if_index))
	    {
	      LCP_ROUTER_INFO ("failed create vlan: %s on %U",
			       rtnl_link_get_name (rl),
			       format_vnet_sw_if_index_name, vnet_get_main (),
			       lip->lip_host_sw_if_index);
	      return;
	    }

	  char *if_name;
	  u8 *if_namev = 0;

	  LCP_ROUTER_INFO (
	    "create vlan: %s -> (%U, %U) : (%U, %U)", rtnl_link_get_name (rl),
	    format_vnet_sw_if_index_name, vnet_get_main (),
	    lip->lip_phy_sw_if_index, format_vnet_sw_if_index_name,
	    vnet_get_main (), sub_phy_sw_if_index,
	    format_vnet_sw_if_index_name, vnet_get_main (),
	    lip->lip_host_sw_if_index, format_vnet_sw_if_index_name,
	    vnet_get_main (), sub_host_sw_if_index);

	  if ((if_name = rtnl_link_get_name (rl)) != NULL)
	    vec_validate_init_c_string (if_namev, if_name,
					strnlen (if_name, IFNAMSIZ));
	  lcp_itf_pair_add (sub_host_sw_if_index, sub_phy_sw_if_index,
			    if_namev, rtnl_link_get_ifindex (rl),
			    lip->lip_host_type, ns);
	  if (up)
	    vnet_sw_interface_admin_up (vnet_get_main (), sub_phy_sw_if_index);
	  vnet_sw_interface_admin_up (vnet_get_main (), sub_host_sw_if_index);

	  vec_free (if_namev);
	}
      else
	{
	  LCP_ROUTER_INFO ("ignore parent-link add: %s - %s",
			   rtnl_link_get_type (rl), rtnl_link_get_name (rl));
	}
    }
  else
    LCP_ROUTER_INFO ("ignore link add: %s - %s", rtnl_link_get_type (rl),
		     rtnl_link_get_name (rl));
}

static fib_protocol_t
lcp_router_proto_k2f (uint32_t k)
{
  if (AF_INET6 == k)
    return (FIB_PROTOCOL_IP6);
  return (FIB_PROTOCOL_IP4);
}

static void
lcp_router_mk_addr (const struct nl_addr *rna, ip_address_t *ia)
{
  fib_protocol_t fproto;

  ip_address_reset (ia);
  fproto = lcp_router_proto_k2f (nl_addr_get_family (rna));

  ip_address_set (ia, nl_addr_get_binary_addr (rna),
		  FIB_PROTOCOL_IP4 == fproto ? AF_IP4 : AF_IP6);
}

static fib_protocol_t
lcp_router_mk_addr46 (const struct nl_addr *rna, ip46_address_t *ia)
{
  fib_protocol_t fproto;

  fproto = lcp_router_proto_k2f (nl_addr_get_family (rna));
  ip46_address_reset (ia);
  if (FIB_PROTOCOL_IP4 == fproto)
    memcpy (&ia->ip4, nl_addr_get_binary_addr (rna), nl_addr_get_len (rna));
  else
    memcpy (&ia->ip6, nl_addr_get_binary_addr (rna), nl_addr_get_len (rna));

  return (fproto);
}

static void
lcp_router_link_addr_add_del (struct rtnl_addr *rla, int is_del)
{
  u32 sw_if_index;

  sw_if_index = lcp_router_intf_h2p (rtnl_addr_get_ifindex (rla));

  if (~0 != sw_if_index)
    {
      ip_address_t nh;

      lcp_router_mk_addr (rtnl_addr_get_local (rla), &nh);

      if (AF_IP4 == ip_addr_version (&nh))
	{
	  ip4_add_del_interface_address (
	    vlib_get_main (), sw_if_index, &ip_addr_v4 (&nh),
	    rtnl_addr_get_prefixlen (rla), is_del);
	  lcp_router_ip4_mroutes_add_del (sw_if_index, !is_del);
	}
      else if (AF_IP6 == ip_addr_version (&nh))
	{
	  if (ip6_address_is_link_local_unicast (&ip_addr_v6 (&nh)))
	    if (is_del)
	      ip6_link_disable (sw_if_index);
	    else
	      {
		ip6_link_enable (sw_if_index, NULL);
		ip6_link_set_local_address (sw_if_index, &ip_addr_v6 (&nh));
	      }
	  else
	    ip6_add_del_interface_address (
	      vlib_get_main (), sw_if_index, &ip_addr_v6 (&nh),
	      rtnl_addr_get_prefixlen (rla), is_del);
	  lcp_router_ip6_mroutes_add_del (sw_if_index, !is_del);
	}

      LCP_ROUTER_DBG ("link-addr: %U %U/%d", format_vnet_sw_if_index_name,
		      vnet_get_main (), sw_if_index, format_ip_address, &nh,
		      rtnl_addr_get_prefixlen (rla));
    }
}

static void
lcp_router_link_addr_del (struct rtnl_addr *la)
{
  lcp_router_link_addr_add_del (la, 1);
}

static void
lcp_router_link_addr_add (struct rtnl_addr *la)
{
  lcp_router_link_addr_add_del (la, 0);
}

static void
lcp_router_mk_mac_addr (const struct nl_addr *rna, mac_address_t *mac)
{
  mac_address_from_bytes (mac, nl_addr_get_binary_addr (rna));
}

static void
lcp_router_neigh_del (struct rtnl_neigh *rn)
{
  u32 sw_if_index;

  sw_if_index = lcp_router_intf_h2p (rtnl_neigh_get_ifindex (rn));

  if (~0 != sw_if_index)
    {
      ip_address_t nh;
      int rv;

      lcp_router_mk_addr (rtnl_neigh_get_dst (rn), &nh);

      rv = ip_neighbor_del (&nh, sw_if_index);

      if (rv)
	{
	  LCP_ROUTER_ERROR (
	    "Failed to delete neighbor: %U %U", format_ip_address, &nh,
	    format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index);
	}
      else
	{
	  LCP_ROUTER_DBG ("neighbor del: %U %U", format_ip_address, &nh,
			  format_vnet_sw_if_index_name, vnet_get_main (),
			  sw_if_index);
	}
    }
  else
    LCP_ROUTER_INFO ("ignore neighbour del on: %d",
		     rtnl_neigh_get_ifindex (rn));
}

#ifndef NUD_VALID
#define NUD_VALID                                                             \
  (NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE | NUD_PROBE | NUD_STALE |        \
   NUD_DELAY)
#endif

static void
lcp_router_neigh_add (struct rtnl_neigh *rn)
{
  u32 sw_if_index;

  sw_if_index = lcp_router_intf_h2p (rtnl_neigh_get_ifindex (rn));

  if (~0 != sw_if_index)
    {
      struct nl_addr *ll;
      ip_address_t nh;
      int state;

      lcp_router_mk_addr (rtnl_neigh_get_dst (rn), &nh);
      ll = rtnl_neigh_get_lladdr (rn);
      state = rtnl_neigh_get_state (rn);

      if (ll && (state & NUD_VALID))
	{
	  mac_address_t mac;
	  ip_neighbor_flags_t flags;
	  int rv;

	  lcp_router_mk_mac_addr (ll, &mac);

	  if (state & (NUD_NOARP | NUD_PERMANENT))
	    flags = IP_NEIGHBOR_FLAG_STATIC;
	  else
	    flags = IP_NEIGHBOR_FLAG_DYNAMIC;

	  rv = ip_neighbor_add (&nh, &mac, sw_if_index, flags, NULL);

	  if (rv)
	    {
	      LCP_ROUTER_ERROR (
		"Failed to create neighbor: %U %U", format_ip_address, &nh,
		format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index);
	    }
	  else
	    {
	      LCP_ROUTER_DBG ("neighbor add: %U %U", format_ip_address, &nh,
			      format_vnet_sw_if_index_name, vnet_get_main (),
			      sw_if_index);
	    }
	}
      else
	/* It's a delete */
	lcp_router_neigh_del (rn);
    }
  else
    LCP_ROUTER_INFO ("ignore neighbour add on: %d",
		     rtnl_neigh_get_ifindex (rn));
}

static lcp_router_table_t *
lcp_router_table_find (uint32_t id, fib_protocol_t fproto)
{
  uword *p;

  p = hash_get (lcp_router_table_db[fproto], id);

  if (p)
    return pool_elt_at_index (lcp_router_table_pool, p[0]);

  return (NULL);
}

static uint32_t
lcp_router_table_k2f (uint32_t k)
{
  // the kernel's table ID 255 is the default table
  if (k == 255 || k == 254)
    return 0;
  return k;
}

static lcp_router_table_t *
lcp_router_table_add_or_lock (uint32_t id, fib_protocol_t fproto)
{
  lcp_router_table_t *nlt;

  id = lcp_router_table_k2f (id);
  nlt = lcp_router_table_find (id, fproto);

  if (NULL == nlt)
    {
      pool_get_zero (lcp_router_table_pool, nlt);

      nlt->nlt_id = id;
      nlt->nlt_proto = fproto;

      nlt->nlt_fib_index = fib_table_find_or_create_and_lock (
	nlt->nlt_proto, nlt->nlt_id, lcp_rt_fib_src);
      nlt->nlt_mfib_index = mfib_table_find_or_create_and_lock (
	nlt->nlt_proto, nlt->nlt_id, MFIB_SOURCE_PLUGIN_LOW);

      hash_set (lcp_router_table_db[fproto], nlt->nlt_id,
		nlt - lcp_router_table_pool);

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
lcp_router_table_unlock (lcp_router_table_t *nlt)
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

      hash_unset (lcp_router_table_db[nlt->nlt_proto], nlt->nlt_id);
      pool_put (lcp_router_table_pool, nlt);
    }
}

static void
lcp_router_route_mk_prefix (struct rtnl_route *r, fib_prefix_t *p)
{
  const struct nl_addr *addr = rtnl_route_get_dst (r);

  p->fp_len = nl_addr_get_prefixlen (addr);
  p->fp_proto = lcp_router_mk_addr46 (addr, &p->fp_addr);
}

static void
lcp_router_route_mk_mprefix (struct rtnl_route *r, mfib_prefix_t *p)
{
  const struct nl_addr *addr;

  addr = rtnl_route_get_dst (r);

  p->fp_len = nl_addr_get_prefixlen (addr);
  p->fp_proto = lcp_router_mk_addr46 (addr, &p->fp_grp_addr);

  addr = rtnl_route_get_src (r);
  if (addr)
    p->fp_proto = lcp_router_mk_addr46 (addr, &p->fp_src_addr);
}

typedef struct lcp_router_route_path_parse_t_
{
  fib_route_path_t *paths;
  fib_protocol_t route_proto;
  bool is_mcast;
  fib_route_path_flags_t type_flags;
  u8 preference;
} lcp_router_route_path_parse_t;

static void
lcp_router_route_path_parse (struct rtnl_nexthop *rnh, void *arg)
{
  lcp_router_route_path_parse_t *ctx = arg;
  fib_route_path_t *path;
  u32 sw_if_index;

  sw_if_index = lcp_router_intf_h2p (rtnl_route_nh_get_ifindex (rnh));

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
	fproto = lcp_router_mk_addr46 (rtnl_route_nh_get_gateway (rnh),
				       &path->frp_addr);
      else
	fproto = ctx->route_proto;

      path->frp_proto = fib_proto_to_dpo (fproto);

      if (ctx->is_mcast)
	path->frp_mitf_flags = MFIB_ITF_FLAG_FORWARD;

      LCP_ROUTER_DBG (" path:[%U]", format_fib_route_path, path);
    }
}

/*
 * blackhole, unreachable, prohibit will not have a next hop in an
 * RTM_NEWROUTE. Add a path for them.
 */
static void
lcp_router_route_path_add_special (struct rtnl_route *rr,
				   lcp_router_route_path_parse_t *ctx)
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

  LCP_ROUTER_DBG (" path:[%U]", format_fib_route_path, path);
}

/*
 * Map of supported route types. Some types are omitted:
 * RTN_LOCAL - interface address addition creates these automatically
 * RTN_BROADCAST - same as RTN_LOCAL
 * RTN_UNSPEC, RTN_ANYCAST, RTN_THROW, RTN_NAT, RTN_XRESOLVE -
 *   There's not a VPP equivalent for these currently.
 */
static const u8 lcp_router_route_type_valid[__RTN_MAX] = {
  [RTN_UNICAST] = 1,	 [RTN_MULTICAST] = 1, [RTN_BLACKHOLE] = 1,
  [RTN_UNREACHABLE] = 1, [RTN_PROHIBIT] = 1,
};

/* Map of fib entry flags by route type */
static const fib_entry_flag_t lcp_router_route_type_feflags[__RTN_MAX] = {
  [RTN_LOCAL] = FIB_ENTRY_FLAG_LOCAL | FIB_ENTRY_FLAG_CONNECTED,
  [RTN_BROADCAST] = FIB_ENTRY_FLAG_DROP | FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT,
  [RTN_BLACKHOLE] = FIB_ENTRY_FLAG_DROP,
};

/* Map of fib route path flags by route type */
static const fib_route_path_flags_t
  lcp_router_route_type_frpflags[__RTN_MAX] = {
    [RTN_UNREACHABLE] = FIB_ROUTE_PATH_ICMP_UNREACH,
    [RTN_PROHIBIT] = FIB_ROUTE_PATH_ICMP_PROHIBIT,
    [RTN_BLACKHOLE] = FIB_ROUTE_PATH_DROP,
  };

static inline fib_source_t
lcp_router_proto_fib_source (u8 rt_proto)
{
  return (rt_proto <= RTPROT_STATIC) ? lcp_rt_fib_src : lcp_rt_fib_src_dynamic;
}

static fib_entry_flag_t
lcp_router_route_mk_entry_flags (uint8_t rtype, int table_id, uint8_t rproto)
{
  fib_entry_flag_t fef = FIB_ENTRY_FLAG_NONE;

  fef |= lcp_router_route_type_feflags[rtype];
  if ((rproto == RTPROT_KERNEL) || PREDICT_FALSE (255 == table_id))
    /* kernel proto is interface prefixes, 255 is linux's 'local' table */
    fef |= FIB_ENTRY_FLAG_ATTACHED | FIB_ENTRY_FLAG_CONNECTED;

  return (fef);
}

static void
lcp_router_route_del (struct rtnl_route *rr)
{
  fib_entry_flag_t entry_flags;
  uint32_t table_id;
  fib_prefix_t pfx;
  lcp_router_table_t *nlt;
  uint8_t rtype, rproto;

  rtype = rtnl_route_get_type (rr);
  table_id = rtnl_route_get_table (rr);
  rproto = rtnl_route_get_protocol (rr);

  /* skip unsupported route types and local table */
  if (!lcp_router_route_type_valid[rtype] || (table_id == 255))
    return;

  lcp_router_route_mk_prefix (rr, &pfx);
  entry_flags = lcp_router_route_mk_entry_flags (rtype, table_id, rproto);
  nlt = lcp_router_table_find (lcp_router_table_k2f (table_id), pfx.fp_proto);

  LCP_ROUTER_DBG ("route del: %d:%U %U", rtnl_route_get_table (rr),
		  format_fib_prefix, &pfx, format_fib_entry_flags,
		  entry_flags);

  if (NULL == nlt)
    return;

  lcp_router_route_path_parse_t np = {
    .route_proto = pfx.fp_proto,
    .type_flags = lcp_router_route_type_frpflags[rtype],
  };

  rtnl_route_foreach_nexthop (rr, lcp_router_route_path_parse, &np);
  lcp_router_route_path_add_special (rr, &np);

  if (0 != vec_len (np.paths))
    {
      fib_source_t fib_src;

      fib_src = lcp_router_proto_fib_source (rproto);

      if (pfx.fp_proto == FIB_PROTOCOL_IP6)
	fib_table_entry_delete (nlt->nlt_fib_index, &pfx, fib_src);
      else
	fib_table_entry_path_remove2 (nlt->nlt_fib_index, &pfx, fib_src,
				      np.paths);
    }

  vec_free (np.paths);

  lcp_router_table_unlock (nlt);
}

static void
lcp_router_route_add (struct rtnl_route *rr)
{
  fib_entry_flag_t entry_flags;
  uint32_t table_id;
  fib_prefix_t pfx;
  lcp_router_table_t *nlt;
  uint8_t rtype, rproto;

  rtype = rtnl_route_get_type (rr);
  table_id = rtnl_route_get_table (rr);
  rproto = rtnl_route_get_protocol (rr);

  /* skip unsupported route types and local table */
  if (!lcp_router_route_type_valid[rtype] || (table_id == 255))
    return;

  lcp_router_route_mk_prefix (rr, &pfx);
  entry_flags = lcp_router_route_mk_entry_flags (rtype, table_id, rproto);

  /* link local IPv6 */
  if (FIB_PROTOCOL_IP6 == pfx.fp_proto &&
      (ip6_address_is_multicast (&pfx.fp_addr.ip6) ||
       ip6_address_is_link_local_unicast (&pfx.fp_addr.ip6)))
    {
      LCP_ROUTER_DBG ("route skip: %d:%U %U", rtnl_route_get_table (rr),
		      format_fib_prefix, &pfx, format_fib_entry_flags,
		      entry_flags);
    }
  else
    {
      LCP_ROUTER_DBG ("route add: %d:%U %U", rtnl_route_get_table (rr),
		      format_fib_prefix, &pfx, format_fib_entry_flags,
		      entry_flags);

      lcp_router_route_path_parse_t np = {
	.route_proto = pfx.fp_proto,
	.is_mcast = (rtype == RTN_MULTICAST),
	.type_flags = lcp_router_route_type_frpflags[rtype],
	.preference = (u8) rtnl_route_get_priority (rr),
      };

      rtnl_route_foreach_nexthop (rr, lcp_router_route_path_parse, &np);
      lcp_router_route_path_add_special (rr, &np);

      if (0 != vec_len (np.paths))
	{
	  nlt = lcp_router_table_add_or_lock (table_id, pfx.fp_proto);
	  if (rtype == RTN_MULTICAST)
	    {
	      /* it's not clear to me how linux expresses the RPF paramters
	       * so we'll allow from all interfaces and hope for the best */
	      mfib_prefix_t mpfx = {};

	      lcp_router_route_mk_mprefix (rr, &mpfx);

	      mfib_table_entry_update (
		nlt->nlt_mfib_index, &mpfx, MFIB_SOURCE_PLUGIN_LOW,
		MFIB_RPF_ID_NONE, MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF);

	      mfib_table_entry_paths_update (nlt->nlt_mfib_index, &mpfx,
					     MFIB_SOURCE_PLUGIN_LOW,
					     MFIB_ENTRY_FLAG_NONE, np.paths);
	    }
	  else
	    {
	      fib_source_t fib_src;

	      fib_src = lcp_router_proto_fib_source (rproto);

	      if (pfx.fp_proto == FIB_PROTOCOL_IP6)
		fib_table_entry_path_add2 (nlt->nlt_fib_index, &pfx, fib_src,
					   entry_flags, np.paths);
	      else
		fib_table_entry_update (nlt->nlt_fib_index, &pfx, fib_src,
					entry_flags, np.paths);
	    }
	}
      else
	LCP_ROUTER_DBG ("no paths for route add: %d:%U %U",
			rtnl_route_get_table (rr), format_fib_prefix, &pfx,
			format_fib_entry_flags, entry_flags);
      vec_free (np.paths);
    }
}

const nl_vft_t lcp_router_vft = {
  .nvl_rt_link_add = { .is_mp_safe = 0, .cb = lcp_router_link_add },
  .nvl_rt_link_del = { .is_mp_safe = 0, .cb = lcp_router_link_del },
  .nvl_rt_addr_add = { .is_mp_safe = 0, .cb = lcp_router_link_addr_add },
  .nvl_rt_addr_del = { .is_mp_safe = 0, .cb = lcp_router_link_addr_del },
  .nvl_rt_neigh_add = { .is_mp_safe = 0, .cb = lcp_router_neigh_add },
  .nvl_rt_neigh_del = { .is_mp_safe = 0, .cb = lcp_router_neigh_del },
  .nvl_rt_route_add = { .is_mp_safe = 1, .cb = lcp_router_route_add },
  .nvl_rt_route_del = { .is_mp_safe = 1, .cb = lcp_router_route_del },
};

static clib_error_t *
lcp_router_init (vlib_main_t *vm)
{
  lcp_router_logger = vlib_log_register_class ("linux-cp", "router");

  nl_register_vft (&lcp_router_vft);

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

VLIB_INIT_FUNCTION (lcp_router_init) = {
  .runs_before = VLIB_INITS ("lcp_nl_init"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
