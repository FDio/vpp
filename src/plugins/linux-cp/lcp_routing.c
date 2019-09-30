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

/* *INDENT-OFF* */
const static fib_prefix_t pfx_all1s = {
  .fp_addr = {
    .ip4 = {
      .as_u32 = 0xffffffff,
    }
  },
  .fp_proto = FIB_PROTOCOL_IP4,
  .fp_len = 32,
};
/* *INDENT-ON* */

/* The name of the loopback interface in linux */
static const char *loopback_name = "lo";

static fib_source_t lcp_rt_fib_source;

#define LCP_ROUTER_DBG(...)                             \
  vlib_log_notice (lcp_router_logger, __VA_ARGS__);

#define LCP_ROUTER_INFO(...)                            \
  vlib_log_notice (lcp_router_logger, __VA_ARGS__);

#define LCP_ROUTER_ERROR(...)                            \
  vlib_log_err (lcp_router_logger, __VA_ARGS__);

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
   /* (*,224.0.0.0)/24 - all local subnet */
   .fp_grp_addr = {
		   .ip6.as_u64[0] = 0x00000000000002ff,
		   },
   .fp_len = 64,
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

static void
lcp_router_link_del (struct rtnl_link *rl)
{
  index_t lipi;

  lipi = lcp_itf_pair_find_by_vif (rtnl_link_get_ifindex (rl));

  if (INDEX_INVALID != lipi)
    {
      if (rtnl_link_is_vlan (rl))
	{
	  lcp_itf_pair_t *lip;

	  lip = lcp_itf_pair_get (lipi);

	  LCP_ROUTER_INFO ("delete vlan: %s -> %U",
			   rtnl_link_get_name (rl),
			   format_vnet_sw_if_index_name, vnet_get_main (),
			   lip->lip_phy_sw_if_index);

	  vnet_delete_sub_interface (lip->lip_phy_sw_if_index);
	  lcp_itf_pair_delete (lip->lip_phy_sw_if_index);
	}
      else
	LCP_ROUTER_INFO ("ignore non-vlan link del: %s - %s",
			 rtnl_link_get_type (rl), rtnl_link_get_name (rl));
    }
  else
    LCP_ROUTER_INFO ("ignore link del: %s - %s",
		     rtnl_link_get_type (rl), rtnl_link_get_name (rl));

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

  mfib_index = mfib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						     sw_if_index);

  for (ii = 0; ii < ARRAY_LEN (ip4_specials); ii++)
    {
      if (is_add)
	{
	  mfib_table_entry_path_update (mfib_index,
					&ip4_specials[ii],
					MFIB_SOURCE_PLUGIN_LOW, &path);
	}
      else
	{
	  mfib_table_entry_path_remove (mfib_index,
					&ip4_specials[ii],
					MFIB_SOURCE_PLUGIN_LOW, &path);
	}
    }
}

static void
lcp_router_ip6_mroutes_add_del (u32 sw_if_index, u8 is_add)
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

  mfib_index = mfib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						     sw_if_index);

  for (ii = 0; ii < ARRAY_LEN (ip6_specials); ii++)
    {
      if (is_add)
	{
	  mfib_table_entry_path_update (mfib_index,
					&ip6_specials[ii],
					MFIB_SOURCE_PLUGIN_LOW, &path);
	}
      else
	{
	  mfib_table_entry_path_remove (mfib_index,
					&ip6_specials[ii],
					MFIB_SOURCE_PLUGIN_LOW, &path);
	}
    }
}

static void
lcp_router_link_add (struct rtnl_link *rl)
{
  index_t lipi;
  int up;

  lipi = lcp_itf_pair_find_by_vif (rtnl_link_get_ifindex (rl));
  up = IFF_UP & rtnl_link_get_flags (rl);

  if (INDEX_INVALID != lipi)
    {
      lcp_itf_pair_t *lip;

      lip = lcp_itf_pair_get (lipi);

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
      LCP_ROUTER_DBG ("link: %s (%d) -> %U/%U %s",
		      rtnl_link_get_name (rl),
		      rtnl_link_get_ifindex (rl),
		      format_vnet_sw_if_index_name, vnet_get_main (),
		      lip->lip_phy_sw_if_index,
		      format_vnet_sw_if_index_name, vnet_get_main (),
		      lip->lip_host_sw_if_index, (up ? "up" : "down"));
    }
  else if (rtnl_link_is_vlan (rl))
    {
      u32 parent_sw_if_index;
      int parent, vlan;
      u8 *ns = 0;		/* FIXME */

      parent = rtnl_link_get_link (rl);
      vlan = rtnl_link_vlan_get_id (rl);
      parent_sw_if_index = lcp_router_intf_h2p (parent);

      if (~0 != parent_sw_if_index)
	{
	  u32 sub_sw_if_index;

	  /* create the vlan interface on the parent */
	  if (vnet_create_sub_interface (parent_sw_if_index, vlan,
					 18, 0, vlan, &sub_sw_if_index))
	    {
	      LCP_ROUTER_INFO ("failed create vlan: %s on %U",
			       rtnl_link_get_name (rl),
			       format_vnet_sw_if_index_name, vnet_get_main (),
			       parent_sw_if_index);
	    }
	  else
	    {
	      LCP_ROUTER_INFO ("create vlan: %s -> (%U, %U)",
			       rtnl_link_get_name (rl),
			       format_vnet_sw_if_index_name, vnet_get_main (),
			       parent_sw_if_index,
			       format_vnet_sw_if_index_name, vnet_get_main (),
			       sub_sw_if_index);

	      lcp_itf_pair_add_sub (rtnl_link_get_ifindex (rl),
				    sub_sw_if_index, parent_sw_if_index, ns);
	      if (up)
		vnet_sw_interface_admin_up (vnet_get_main (),
					    sub_sw_if_index);
	    }
	}
    }
  else if (!strcmp (loopback_name, rtnl_link_get_name (rl)))
    {
      u32 phy_sw_if_index;
      u8 mac[6] = { };
      u8 *ns = 0;		/* FIXME */

      LCP_ROUTER_INFO ("loopback add: %s", rtnl_link_get_name (rl));

      vnet_create_loopback_interface (&phy_sw_if_index, mac, 0, 0);
      if (up)
	vnet_sw_interface_admin_up (vnet_get_main (), phy_sw_if_index);

      lcp_itf_pair_add (~0, phy_sw_if_index,
			format (NULL, "%s", rtnl_link_get_name (rl)),
			rtnl_link_get_ifindex (rl), ns);
    }
  else
    LCP_ROUTER_INFO ("ignore link add: %s - %s",
		     rtnl_link_get_type (rl), rtnl_link_get_name (rl));
}

static fib_protocol_t
lcp_router_proto_k2f (uint32_t k)
{
  if (AF_INET6 == k)
    return (FIB_PROTOCOL_IP6);
  return (FIB_PROTOCOL_IP4);
}

static fib_protocol_t
lcp_router_mk_addr (const struct nl_addr *rna, ip46_address_t * ia)
{
  fib_protocol_t fproto;

  fproto = lcp_router_proto_k2f (nl_addr_get_family (rna));
  if (FIB_PROTOCOL_IP4 == fproto)
    {
      ip46_address_reset (ia);
      memcpy (&ia->ip4, nl_addr_get_binary_addr (rna), nl_addr_get_len (rna));
    }
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
      ip46_address_t nh = ip46_address_initializer;
      fib_protocol_t fproto;

      fproto = lcp_router_mk_addr (rtnl_addr_get_local (rla), &nh);

      if (FIB_PROTOCOL_IP4 == fproto)
	{
	  ip4_add_del_interface_address (vlib_get_main (),
					 sw_if_index,
					 &nh.ip4,
					 rtnl_addr_get_prefixlen (rla),
					 is_del);
	  lcp_router_ip4_mroutes_add_del (sw_if_index, !is_del);
	}
      else if (FIB_PROTOCOL_IP6 == fproto)
	{
	  if (ip6_address_is_link_local_unicast (&nh.ip6))
	    if (is_del)
	      ip6_link_disable (sw_if_index);
	    else
	      {
		if (!ip6_link_is_enabled (sw_if_index))
		  ip6_link_enable (sw_if_index);
		ip6_set_link_local_address (sw_if_index, &nh.ip6);
	      }
	  else
	    ip6_add_del_interface_address (vlib_get_main (),
					   sw_if_index,
					   &nh.ip6,
					   rtnl_addr_get_prefixlen (rla),
					   is_del);
	  lcp_router_ip6_mroutes_add_del (sw_if_index, !is_del);
	}

      LCP_ROUTER_DBG ("link-addr: %U %U/%d", format_vnet_sw_if_index_name,
		      vnet_get_main (), sw_if_index,
		      format_ip46_address, &nh, IP46_TYPE_ANY,
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
lcp_router_mk_mac_addr (const struct nl_addr *rna, mac_address_t * mac)
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
      fib_protocol_t fproto;
      ip46_address_t nh;
      int rv;

      fproto = lcp_router_mk_addr (rtnl_neigh_get_dst (rn), &nh);

      rv = ip_neighbor_del (&nh, fib_proto_to_ip46 (fproto), sw_if_index);

      if (rv)
	{
	  LCP_ROUTER_ERROR ("Failed to delete neighbor: %U %U",
			    format_ip46_address, &nh, IP46_TYPE_ANY,
			    format_vnet_sw_if_index_name, vnet_get_main (),
			    sw_if_index);
	}
      else
	{
	  LCP_ROUTER_DBG ("neighbor del: %U %U",
			  format_ip46_address, &nh, IP46_TYPE_ANY,
			  format_vnet_sw_if_index_name, vnet_get_main (),
			  sw_if_index);
	}
    }
  else
    LCP_ROUTER_INFO ("ignore neighbour del on: %d",
		     rtnl_neigh_get_ifindex (rn));
}

static void
lcp_router_neigh_add (struct rtnl_neigh *rn)
{
  u32 sw_if_index;

  sw_if_index = lcp_router_intf_h2p (rtnl_neigh_get_ifindex (rn));

  if (~0 != sw_if_index)
    {
      fib_protocol_t fproto;
      struct nl_addr *ll;
      ip46_address_t nh;

      fproto = lcp_router_mk_addr (rtnl_neigh_get_dst (rn), &nh);
      ll = rtnl_neigh_get_lladdr (rn);

      if (ll)
	{
	  mac_address_t mac;
	  int rv;

	  lcp_router_mk_mac_addr (ll, &mac);

	  rv = ip_neighbor_add (&nh, fib_proto_to_ip46 (fproto), &mac,
				sw_if_index, IP_NEIGHBOR_FLAG_STATIC, NULL);

	  if (rv)
	    {
	      LCP_ROUTER_ERROR ("Failed to create neighbor: %U %U",
				format_ip46_address, &nh, IP46_TYPE_ANY,
				format_vnet_sw_if_index_name,
				vnet_get_main (), sw_if_index);
	    }
	  else
	    {
	      LCP_ROUTER_DBG ("neighbor add: %U %U",
			      format_ip46_address, &nh, IP46_TYPE_ANY,
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

      nlt->nlt_fib_index = fib_table_find_or_create_and_lock (nlt->nlt_proto,
							      nlt->nlt_id,
							      lcp_rt_fib_source);
      nlt->nlt_mfib_index =
	mfib_table_find_or_create_and_lock (nlt->nlt_proto, nlt->nlt_id,
					    lcp_rt_fib_source);

      hash_set (lcp_router_table_db[fproto], nlt->nlt_id,
		nlt - lcp_router_table_pool);

      if (FIB_PROTOCOL_IP4 == fproto)
	{
	  /* Set the all 1s address in this table to punt */
	  fib_table_entry_special_add (nlt->nlt_fib_index,
				       &pfx_all1s,
				       lcp_rt_fib_source,
				       FIB_ENTRY_FLAG_LOCAL);

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
	      mfib_table_entry_path_update (nlt->nlt_mfib_index,
					    &ip4_specials[ii],
					    MFIB_SOURCE_PLUGIN_LOW, &path);
	    }
	}
    }

  nlt->nlt_refs++;

  return (nlt);
}

static void
lcp_router_table_unlock (lcp_router_table_t * nlt)
{
  nlt->nlt_refs--;

  if (0 == nlt->nlt_refs)
    {
      if (FIB_PROTOCOL_IP4 == nlt->nlt_proto)
	{
	  /* Set the all 1s address in this table to punt */
	  fib_table_entry_special_remove (nlt->nlt_fib_index,
					  &pfx_all1s, lcp_rt_fib_source);
	}

      fib_table_unlock (nlt->nlt_fib_index,
			nlt->nlt_proto, lcp_rt_fib_source);

      hash_unset (lcp_router_table_db[nlt->nlt_proto], nlt->nlt_id);
      pool_put (lcp_router_table_pool, nlt);
    }
}

static void
lcp_router_route_mk_prefix (struct rtnl_route *r, fib_prefix_t * p)
{
  const struct nl_addr *addr = rtnl_route_get_dst (r);

  p->fp_len = nl_addr_get_prefixlen (addr);
  p->fp_proto = lcp_router_mk_addr (addr, &p->fp_addr);
}

static void
lcp_router_route_mk_mprefix (struct rtnl_route *r, mfib_prefix_t * p)
{
  const struct nl_addr *addr;

  addr = rtnl_route_get_dst (r);

  p->fp_len = nl_addr_get_prefixlen (addr);
  p->fp_proto = lcp_router_mk_addr (addr, &p->fp_grp_addr);

  addr = rtnl_route_get_src (r);
  if (addr)
    p->fp_proto = lcp_router_mk_addr (addr, &p->fp_src_addr);
}

typedef struct lcp_router_route_path_parse_t_
{
  fib_route_path_t *paths;
  fib_protocol_t route_proto;
  bool is_mcast;
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

      path->frp_flags = FIB_ROUTE_PATH_FLAG_NONE;
      path->frp_sw_if_index = sw_if_index;
      path->frp_weight = rtnl_route_nh_get_weight (rnh);

      addr = rtnl_route_nh_get_gateway (rnh);

      if (addr)
	fproto = lcp_router_mk_addr (rtnl_route_nh_get_gateway (rnh),
				     &path->frp_addr);
      else
	fproto = ctx->route_proto;

      path->frp_proto = fib_proto_to_dpo (fproto);

      if (ctx->is_mcast)
	path->frp_mitf_flags = MFIB_ITF_FLAG_FORWARD;

      LCP_ROUTER_DBG (" path:[%U]", format_fib_route_path, path);
    }
}

static fib_entry_flag_t
lcp_router_route_mk_entry_flags (uint8_t rtype, int table_id)
{
  fib_entry_flag_t fef = FIB_ENTRY_FLAG_NONE;

  if (rtype == RTN_LOCAL)
    fef |= FIB_ENTRY_FLAG_LOCAL | FIB_ENTRY_FLAG_CONNECTED;
  if (254 == table_id)
    /* 254 is linux's 'local' table */
    fef |= FIB_ENTRY_FLAG_ATTACHED | FIB_ENTRY_FLAG_CONNECTED;
  if (rtype == RTN_BROADCAST)
    fef |= FIB_ENTRY_FLAG_DROP | FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT;

  return (fef);
}

static void
lcp_router_route_del (struct rtnl_route *rr)
{
  fib_entry_flag_t entry_flags;
  uint32_t table_id;
  fib_prefix_t pfx;
  lcp_router_table_t *nlt;

  lcp_router_route_mk_prefix (rr, &pfx);
  table_id = rtnl_route_get_table (rr);
  entry_flags = lcp_router_route_mk_entry_flags (rtnl_route_get_type (rr),
						 table_id);
  nlt = lcp_router_table_find (lcp_router_table_k2f (table_id), pfx.fp_proto);

  LCP_ROUTER_DBG ("route del: %d:%U %U",
		  rtnl_route_get_table (rr), format_fib_prefix, &pfx,
		  format_fib_entry_flags, entry_flags);

  if (NULL == nlt)
    return;

  lcp_router_route_path_parse_t np = {
    .route_proto = pfx.fp_proto,
  };

  rtnl_route_foreach_nexthop (rr, lcp_router_route_path_parse, &np);

  if (0 != vec_len (np.paths))
    fib_table_entry_path_remove2 (nlt->nlt_fib_index,
				  &pfx, lcp_rt_fib_source, np.paths);
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
  uint8_t rtype;

  rtype = rtnl_route_get_type (rr);
  table_id = rtnl_route_get_table (rr);
  lcp_router_route_mk_prefix (rr, &pfx);
  nlt = lcp_router_table_add_or_lock (table_id, pfx.fp_proto);
  entry_flags = lcp_router_route_mk_entry_flags (rtype, table_id);

  /* link local IPv6 */
  if (FIB_PROTOCOL_IP6 == pfx.fp_proto &&
      (ip6_address_is_multicast (&pfx.fp_addr.ip6) ||
       ip6_address_is_link_local_unicast (&pfx.fp_addr.ip6)))
    {
      LCP_ROUTER_INFO ("route skip: %d:%U %U",
		       rtnl_route_get_table (rr), format_fib_prefix, &pfx,
		       format_fib_entry_flags, entry_flags);
    }
  else
    {
      LCP_ROUTER_INFO ("route add: %d:%U %U",
		       rtnl_route_get_table (rr), format_fib_prefix, &pfx,
		       format_fib_entry_flags, entry_flags);

      lcp_router_route_path_parse_t np = {
	.route_proto = pfx.fp_proto,
	.is_mcast = (rtype == RTN_MULTICAST),
      };

      rtnl_route_foreach_nexthop (rr, lcp_router_route_path_parse, &np);

      if (0 != vec_len (np.paths))
	{
	  if (rtype == RTN_MULTICAST)
	    {
	      /* it's not clear to me how linux expresses the RPF paramters
	       * so we'll allow from all interfaces and hope for the best */
	      mfib_prefix_t mpfx = { };

	      lcp_router_route_mk_mprefix (rr, &mpfx);

	      mfib_table_entry_update (nlt->nlt_mfib_index,
				       &mpfx,
				       MFIB_SOURCE_PLUGIN_LOW,
				       MFIB_RPF_ID_NONE,
				       MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF);

	      mfib_table_entry_paths_update (nlt->nlt_mfib_index,
					     &mpfx,
					     MFIB_SOURCE_PLUGIN_LOW,
					     np.paths);
	    }
	  else
	    fib_table_entry_update (nlt->nlt_fib_index, &pfx,
				    lcp_rt_fib_source, entry_flags, np.paths);
	}
      else
	LCP_ROUTER_DBG ("no paths for route add: %d:%U %U",
			rtnl_route_get_table (rr), format_fib_prefix, &pfx,
			format_fib_entry_flags, entry_flags);
      vec_free (np.paths);
    }
}

const nl_vft_t lcp_router_vft = {
  .nvl_rt_link_add = lcp_router_link_add,
  .nvl_rt_link_del = lcp_router_link_del,
  .nvl_rt_addr_add = lcp_router_link_addr_add,
  .nvl_rt_addr_del = lcp_router_link_addr_del,
  .nvl_rt_neigh_add = lcp_router_neigh_add,
  .nvl_rt_neigh_del = lcp_router_neigh_del,
  .nvl_rt_route_add = lcp_router_route_add,
  .nvl_rt_route_del = lcp_router_route_del,
};

static clib_error_t *
lcp_router_init (vlib_main_t * vm)
{
  lcp_router_logger = vlib_log_register_class ("linux-cp", "router");

  nl_register_vft (&lcp_router_vft);

  lcp_rt_fib_source = fib_source_allocate ("lcp-rt-low",
					   FIB_SOURCE_PRIORITY_LOW,
					   FIB_SOURCE_BH_SIMPLE);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (lcp_router_init) =
{
  .runs_before = VLIB_INITS ("lcp_nl_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
