/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#define _GNU_SOURCE
#include <sched.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/socket.h>
#include <net/if.h>

#include <linux-cp/lcp_interface.h>
#include <netlink/route/link/vlan.h>

#include <vnet/plugin/plugin.h>
#include <vnet/plugin/plugin.h>

#include <vnet/ip/ip_punt_drop.h>
#include <vnet/fib/fib_table.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/udp/udp.h>
#include <vnet/tcp/tcp.h>
#include <vnet/devices/tap/tap.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/netlink.h>
#include <vlibapi/api_helper_macros.h>
#include <vnet/ipsec/ipsec_punt.h>

static vlib_log_class_t lcp_itf_pair_logger;

/**
 * Pool of LIP objects
 */
lcp_itf_pair_t *lcp_itf_pair_pool;

u32
lcp_itf_num_pairs (void)
{
  return pool_elts (lcp_itf_pair_pool);
}

/**
 * DBs of interface-pair objects:
 *  - key'd by VIF (linux ID)
 *  - key'd by VPP's physical interface
 *  - number of shared uses of VPP's tap/host interface
 */
static uword *lip_db_by_vif;
index_t *lip_db_by_phy;
u32 *lip_db_by_host;

#define LCP_ITF_PAIR_DBG(...)                                                 \
  vlib_log_notice (lcp_itf_pair_logger, __VA_ARGS__);

#define LCP_ITF_PAIR_INFO(...)                                                \
  vlib_log_notice (lcp_itf_pair_logger, __VA_ARGS__);

u8 *
format_lcp_itf_pair (u8 *s, va_list *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  lcp_itf_pair_t *lip = va_arg (*args, lcp_itf_pair_t *);
  vnet_sw_interface_t *swif_phy;
  vnet_sw_interface_t *swif_host;

  s = format (s, "itf-pair: [%d]", lip - lcp_itf_pair_pool);

  swif_phy = vnet_get_sw_interface_or_null (vnm, lip->lip_phy_sw_if_index);
  if (!swif_phy)
    s = format (s, " <no-phy-if>");
  else
    s = format (s, " %U", format_vnet_sw_interface_name, vnm, swif_phy);

  swif_host = vnet_get_sw_interface_or_null (vnm, lip->lip_host_sw_if_index);
  if (!swif_host)
    s = format (s, " <no-host-if>");
  else
    s = format (s, " %U", format_vnet_sw_interface_name, vnm, swif_host);

  s = format (s, " %v %d type %s", lip->lip_host_name, lip->lip_vif_index,
	      (lip->lip_host_type == LCP_ITF_HOST_TAP) ? "tap" : "tun");

  if (lip->lip_namespace)
    s = format (s, " netns %s", lip->lip_namespace);

  return s;
}

static walk_rc_t
lcp_itf_pair_walk_show_cb (index_t api, void *ctx)
{
  vlib_main_t *vm;
  lcp_itf_pair_t *lip;

  lip = lcp_itf_pair_get (api);
  if (!lip)
    return WALK_STOP;

  vm = vlib_get_main ();
  vlib_cli_output (vm, "%U\n", format_lcp_itf_pair, lip);

  return WALK_CONTINUE;
}

void
lcp_itf_pair_show (u32 phy_sw_if_index)
{
  vlib_main_t *vm;
  u8 *ns;
  index_t api;

  vm = vlib_get_main ();
  ns = lcp_get_default_ns ();
  vlib_cli_output (vm, "lcp default netns '%s'\n",
		   ns ? (char *) ns : "<unset>");

  if (phy_sw_if_index == ~0)
    {
      lcp_itf_pair_walk (lcp_itf_pair_walk_show_cb, 0);
    }
  else
    {
      api = lcp_itf_pair_find_by_phy (phy_sw_if_index);
      if (api != INDEX_INVALID)
	lcp_itf_pair_walk_show_cb (api, 0);
    }
}

lcp_itf_pair_t *
lcp_itf_pair_get (u32 index)
{
  return pool_elt_at_index (lcp_itf_pair_pool, index);
}

index_t
lcp_itf_pair_find_by_vif (u32 vif_index)
{
  uword *p;

  p = hash_get (lip_db_by_vif, vif_index);

  if (p)
    return p[0];

  return INDEX_INVALID;
}

int
lcp_itf_pair_add_sub (u32 vif, u8 *host_if_name, u32 sub_sw_if_index,
		      u32 phy_sw_if_index, u8 *ns)
{
  lcp_itf_pair_t *lip;

  lip = lcp_itf_pair_get (lcp_itf_pair_find_by_phy (phy_sw_if_index));

  return lcp_itf_pair_add (lip->lip_host_sw_if_index, sub_sw_if_index,
			   host_if_name, vif, lip->lip_host_type, ns);
}

const char *lcp_itf_l3_feat_names[N_LCP_ITF_HOST][N_AF] = {
  [LCP_ITF_HOST_TAP] = {
    [AF_IP4] = "linux-cp-xc-ip4",
    [AF_IP6] = "linux-cp-xc-ip6",
  },
  [LCP_ITF_HOST_TUN] = {
    [AF_IP4] = "linux-cp-xc-l3-ip4",
    [AF_IP6] = "linux-cp-xc-l3-ip6",
  },
};

const fib_route_path_flags_t lcp_itf_route_path_flags[N_LCP_ITF_HOST] = {
  [LCP_ITF_HOST_TAP] = FIB_ROUTE_PATH_DVR,
  [LCP_ITF_HOST_TUN] = FIB_ROUTE_PATH_FLAG_NONE,
};

static void
lcp_itf_unset_adjs (lcp_itf_pair_t *lip)
{
  adj_unlock (lip->lip_phy_adjs.adj_index[AF_IP4]);
  adj_unlock (lip->lip_phy_adjs.adj_index[AF_IP6]);
}

static void
lcp_itf_set_adjs (lcp_itf_pair_t *lip)
{
  if (lip->lip_host_type == LCP_ITF_HOST_TUN)
    {
      lip->lip_phy_adjs.adj_index[AF_IP4] = adj_nbr_add_or_lock (
	FIB_PROTOCOL_IP4, VNET_LINK_IP4, &zero_addr, lip->lip_phy_sw_if_index);
      lip->lip_phy_adjs.adj_index[AF_IP6] = adj_nbr_add_or_lock (
	FIB_PROTOCOL_IP6, VNET_LINK_IP6, &zero_addr, lip->lip_phy_sw_if_index);
    }
  else
    {
      lip->lip_phy_adjs.adj_index[AF_IP4] = adj_mcast_add_or_lock (
	FIB_PROTOCOL_IP4, VNET_LINK_IP4, lip->lip_phy_sw_if_index);
      lip->lip_phy_adjs.adj_index[AF_IP6] = adj_mcast_add_or_lock (
	FIB_PROTOCOL_IP6, VNET_LINK_IP6, lip->lip_phy_sw_if_index);
    }

  ip_adjacency_t *adj;

  adj = adj_get (lip->lip_phy_adjs.adj_index[AF_IP4]);

  lip->lip_rewrite_len = adj->rewrite_header.data_bytes;
}

int __clib_weak
lcp_nl_drain_messages (void)
{
  return 0;
}

int
lcp_itf_pair_add (u32 host_sw_if_index, u32 phy_sw_if_index, u8 *host_name,
		  u32 host_index, lip_host_type_t host_type, u8 *ns)
{
  index_t lipi;
  lcp_itf_pair_t *lip;

  lipi = lcp_itf_pair_find_by_phy (phy_sw_if_index);

  LCP_ITF_PAIR_INFO ("add: host:%U phy:%U, host_if:%v vif:%d ns:%v",
		     format_vnet_sw_if_index_name, vnet_get_main (),
		     host_sw_if_index, format_vnet_sw_if_index_name,
		     vnet_get_main (), phy_sw_if_index, host_name, host_index,
		     ns);

  if (lipi != INDEX_INVALID)
    return VNET_API_ERROR_VALUE_EXIST;

  /*
   * Drain netlink messages before adding the new pair.
   * This avoids unnecessarily applying messages that were generated by
   * the creation of the tap/tun interface. By processing them before we
   * store the pair data, we will ensure that they are ignored.
   */
  lcp_nl_drain_messages ();

  /*
   * Create a new pair.
   */
  pool_get (lcp_itf_pair_pool, lip);

  lipi = lip - lcp_itf_pair_pool;

  vec_validate_init_empty (lip_db_by_phy, phy_sw_if_index, INDEX_INVALID);
  vec_validate_init_empty (lip_db_by_host, host_sw_if_index, INDEX_INVALID);
  lip_db_by_phy[phy_sw_if_index] = lipi;
  lip_db_by_host[host_sw_if_index] = lipi;
  hash_set (lip_db_by_vif, host_index, lipi);

  lip->lip_host_sw_if_index = host_sw_if_index;
  lip->lip_phy_sw_if_index = phy_sw_if_index;
  lip->lip_host_name = vec_dup (host_name);
  lip->lip_host_type = host_type;
  lip->lip_vif_index = host_index;
  lip->lip_namespace = vec_dup (ns);
  lip->lip_create_ts = vlib_time_now (vlib_get_main ());

  if (lip->lip_host_sw_if_index == ~0)
    return 0;

  /*
   * First use of this host interface.
   * Enable the x-connect feature on the host to send
   * all packets to the phy.
   */
  ip_address_family_t af;

  FOR_EACH_IP_ADDRESS_FAMILY (af)
  ip_feature_enable_disable (af, N_SAFI, IP_FEATURE_INPUT,
			     lcp_itf_l3_feat_names[lip->lip_host_type][af],
			     lip->lip_host_sw_if_index, 1, NULL, 0);

  /*
   * Configure passive punt to the host interface.
   */
  fib_route_path_t *rpaths = NULL, rpath = {
    .frp_flags = lcp_itf_route_path_flags[lip->lip_host_type],
    .frp_proto = DPO_PROTO_IP4,
    .frp_sw_if_index = lip->lip_host_sw_if_index,
    .frp_weight = 1,
    .frp_fib_index = ~0,
  };

  vec_add1 (rpaths, rpath);

  ip4_punt_redirect_add_paths (lip->lip_phy_sw_if_index, rpaths);

  rpaths[0].frp_proto = DPO_PROTO_IP6;

  ip6_punt_redirect_add_paths (lip->lip_phy_sw_if_index, rpaths);

  vec_free (rpaths);

  lcp_itf_set_adjs (lip);

  /* enable ARP feature node for broadcast interfaces */
  if (lip->lip_host_type != LCP_ITF_HOST_TUN)
    {
      vnet_feature_enable_disable ("arp", "linux-cp-arp-phy",
				   lip->lip_phy_sw_if_index, 1, NULL, 0);
      vnet_feature_enable_disable ("arp", "linux-cp-arp-host",
				   lip->lip_host_sw_if_index, 1, NULL, 0);
    }
  else
    {
      vnet_feature_enable_disable ("ip4-punt", "linux-cp-punt-l3", 0, 1, NULL,
				   0);
      vnet_feature_enable_disable ("ip6-punt", "linux-cp-punt-l3", 0, 1, NULL,
				   0);
    }

  return 0;
}

static clib_error_t *
lcp_netlink_add_link_vlan (int parent, u32 vlan, const char *name)
{
  struct rtnl_link *link;
  struct nl_sock *sk;
  int err;

  sk = nl_socket_alloc ();
  if ((err = nl_connect (sk, NETLINK_ROUTE)) < 0)
    return clib_error_return (NULL, "Unable to connect socket: %d", err);

  link = rtnl_link_vlan_alloc ();

  rtnl_link_set_link (link, parent);
  rtnl_link_set_name (link, name);

  rtnl_link_vlan_set_id (link, vlan);

  if ((err = rtnl_link_add (sk, link, NLM_F_CREATE)) < 0)
    return clib_error_return (NULL, "Unable to add link %s: %d", name, err);

  rtnl_link_put (link);
  nl_close (sk);

  return NULL;
}

static clib_error_t *
lcp_netlink_del_link (const char *name)
{
  struct rtnl_link *link;
  struct nl_sock *sk;
  int err;

  sk = nl_socket_alloc ();
  if ((err = nl_connect (sk, NETLINK_ROUTE)) < 0)
    return clib_error_return (NULL, "Unable to connect socket: %d", err);

  link = rtnl_link_alloc ();
  rtnl_link_set_name (link, name);

  if ((err = rtnl_link_delete (sk, link)) < 0)
    return clib_error_return (NULL, "Unable to del link %s: %d", name, err);

  rtnl_link_put (link);
  nl_close (sk);

  return NULL;
}

int
lcp_itf_pair_del (u32 phy_sw_if_index)
{
  ip_address_family_t af;
  lcp_itf_pair_t *lip;
  u32 lipi;

  lipi = lcp_itf_pair_find_by_phy (phy_sw_if_index);

  if (lipi == INDEX_INVALID)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  lip = lcp_itf_pair_get (lipi);

  LCP_ITF_PAIR_INFO ("pair delete: {%U, %U, %s}", format_vnet_sw_if_index_name,
		     vnet_get_main (), lip->lip_phy_sw_if_index,
		     format_vnet_sw_if_index_name, vnet_get_main (),
		     lip->lip_host_sw_if_index, lip->lip_host_name);

  FOR_EACH_IP_ADDRESS_FAMILY (af)
  ip_feature_enable_disable (af, N_SAFI, IP_FEATURE_INPUT,
			     lcp_itf_l3_feat_names[lip->lip_host_type][af],
			     lip->lip_host_sw_if_index, 0, NULL, 0);

  lcp_itf_unset_adjs (lip);

  ip4_punt_redirect_del (lip->lip_phy_sw_if_index);
  ip6_punt_redirect_del (lip->lip_phy_sw_if_index);

  /* disable ARP feature node for broadcast interfaces */
  if (lip->lip_host_type != LCP_ITF_HOST_TUN)
    {
      vnet_feature_enable_disable ("arp", "linux-cp-arp-phy",
				   lip->lip_phy_sw_if_index, 0, NULL, 0);
      vnet_feature_enable_disable ("arp", "linux-cp-arp-host",
				   lip->lip_host_sw_if_index, 0, NULL, 0);
    }
  else
    {
      vnet_feature_enable_disable ("ip4-punt", "linux-cp-punt-l3", 0, 0, NULL,
				   0);
      vnet_feature_enable_disable ("ip6-punt", "linux-cp-punt-l3", 0, 0, NULL,
				   0);
    }

  lip_db_by_phy[phy_sw_if_index] = INDEX_INVALID;
  lip_db_by_phy[lip->lip_host_sw_if_index] = INDEX_INVALID;

  vec_free (lip->lip_host_name);
  vec_free (lip->lip_namespace);
  pool_put (lcp_itf_pair_pool, lip);

  return 0;
}

static void
lcp_itf_pair_delete_by_index (index_t lipi)
{
  u32 host_sw_if_index;
  lcp_itf_pair_t *lip;
  u8 *host_name;

  lip = lcp_itf_pair_get (lipi);

  host_name = vec_dup (lip->lip_host_name);
  host_sw_if_index = lip->lip_host_sw_if_index;

  lcp_itf_pair_del (lip->lip_phy_sw_if_index);

  if (vnet_sw_interface_is_sub (vnet_get_main (), host_sw_if_index))
    {
      lcp_netlink_del_link ((const char *) host_name);
      vnet_delete_sub_interface (host_sw_if_index);
    }
  else
    tap_delete_if (vlib_get_main (), host_sw_if_index);

  vec_free (host_name);
}

int
lcp_itf_pair_delete (u32 phy_sw_if_index)
{
  index_t lipi;

  lipi = lcp_itf_pair_find_by_phy (phy_sw_if_index);

  if (lipi == INDEX_INVALID)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  lcp_itf_pair_delete_by_index (lipi);

  return 0;
}

void
lcp_itf_pair_walk (lcp_itf_pair_walk_cb_t cb, void *ctx)
{
  u32 api;

  pool_foreach_index (api, lcp_itf_pair_pool)
    {
      if (!cb (api, ctx))
	break;
    };
}

typedef struct lcp_itf_pair_names_t_
{
  u8 *lipn_host_name;
  u8 *lipn_phy_name;
  u8 *lipn_namespace;
  u32 lipn_phy_sw_if_index;
} lcp_itf_pair_names_t;

static lcp_itf_pair_names_t *lipn_names;

static clib_error_t *
lcp_itf_pair_config (vlib_main_t *vm, unformat_input_t *input)
{
  u8 *host, *phy;
  u8 *ns;
  u8 *default_ns;

  host = phy = ns = default_ns = NULL;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      vec_reset_length (host);

      if (unformat (input, "pair %s %s %s", &phy, &host, &ns))
	{
	  lcp_itf_pair_names_t *lipn;

	  if (vec_len (ns) > LCP_NS_LEN)
	    {
	      return clib_error_return (0,
					"linux-cp IF namespace must"
					" be less than %d characters",
					LCP_NS_LEN);
	    }

	  vec_add2 (lipn_names, lipn, 1);

	  lipn->lipn_host_name = vec_dup (host);
	  lipn->lipn_phy_name = vec_dup (phy);
	  lipn->lipn_namespace = vec_dup (ns);
	}
      else if (unformat (input, "pair %v %v", &phy, &host))
	{
	  lcp_itf_pair_names_t *lipn;

	  vec_add2 (lipn_names, lipn, 1);

	  lipn->lipn_host_name = vec_dup (host);
	  lipn->lipn_phy_name = vec_dup (phy);
	  lipn->lipn_namespace = 0;
	}
      else if (unformat (input, "default netns %v", &default_ns))
	{
	  vec_add1 (default_ns, 0);
	  if (lcp_set_default_ns (default_ns) < 0)
	    {
	      return clib_error_return (0,
					"linux-cp default namespace must"
					" be less than %d characters",
					LCP_NS_LEN);
	    }
	}
      else if (unformat (input, "interface-auto-create"))
	lcp_set_auto_intf (1 /* is_auto */);
      else
	return clib_error_return (0, "interfaces not found");
    }

  vec_free (host);
  vec_free (phy);
  vec_free (default_ns);

  return NULL;
}

VLIB_EARLY_CONFIG_FUNCTION (lcp_itf_pair_config, "linux-cp");

/*
 * Returns 1 if the tap name is valid.
 * Returns 0 if the tap name is invalid.
 */
static int
lcp_validate_if_name (u8 *name)
{
  int len;
  char *p;

  p = (char *) name;
  len = clib_strnlen (p, IFNAMSIZ);
  if (len >= IFNAMSIZ)
    return 0;

  for (; *p; ++p)
    {
      if (isalnum (*p))
	continue;

      switch (*p)
	{
	case '-':
	case '_':
	case '%':
	case '@':
	case ':':
	case '.':
	  continue;
	}

      return 0;
    }

  return 1;
}

static int
lcp_itf_get_ns_fd (char *ns_name)
{
  char ns_path[256] = "/proc/self/ns/net";

  if (ns_name)
    snprintf (ns_path, sizeof (ns_path) - 1, "/var/run/netns/%s", ns_name);

  return open (ns_path, O_RDONLY);
}

static void
lcp_itf_set_vif_link_state (u32 vif_index, u8 up, u8 *ns)
{
  int curr_ns_fd, vif_ns_fd;

  curr_ns_fd = vif_ns_fd = -1;

  if (ns)
    {
      u8 *ns_path = 0;

      curr_ns_fd = open ("/proc/self/ns/net", O_RDONLY);
      ns_path = format (0, "/var/run/netns/%s%c", (char *) ns, 0);
      vif_ns_fd = open ((char *) ns_path, O_RDONLY);
      if (vif_ns_fd != -1)
	setns (vif_ns_fd, CLONE_NEWNET);
    }

  vnet_netlink_set_link_state (vif_index, up);

  if (vif_ns_fd != -1)
    close (vif_ns_fd);

  if (curr_ns_fd != -1)
    {
      setns (curr_ns_fd, CLONE_NEWNET);
      close (curr_ns_fd);
    }
}

int
lcp_itf_pair_create (u32 phy_sw_if_index, u8 *host_if_name,
		     lip_host_type_t host_if_type, u8 *ns)
{
  vlib_main_t *vm;
  vnet_main_t *vnm;
  u32 vif_index = 0, host_sw_if_index;
  const vnet_sw_interface_t *sw;
  const vnet_hw_interface_t *hw;

  if (!vnet_sw_if_index_is_api_valid (phy_sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (!lcp_validate_if_name (host_if_name))
    return VNET_API_ERROR_INVALID_ARGUMENT;

  vnm = vnet_get_main ();
  sw = vnet_get_sw_interface (vnm, phy_sw_if_index);
  hw = vnet_get_sup_hw_interface (vnm, phy_sw_if_index);

  /*
   * Use interface-specific netns if supplied.
   * Otherwise, use default netns if defined.
   * Otherwise ignore a netns and use the OS default.
   */
  if (ns == 0 || ns[0] == 0)
    ns = lcp_get_default_ns ();

  /* sub interfaces do not need a tap created */
  if (vnet_sw_interface_is_sub (vnm, phy_sw_if_index))
    {
      const lcp_itf_pair_t *lip;
      int orig_ns_fd, ns_fd;
      clib_error_t *err;
      u16 vlan;

      /*
       * Find the parent tap by finding the pair from the parent phy
       */
      lip = lcp_itf_pair_get (lcp_itf_pair_find_by_phy (sw->sup_sw_if_index));
      vlan = sw->sub.eth.outer_vlan_id;

      /*
       * see if the requested host interface has already been created
       */
      orig_ns_fd = ns_fd = -1;
      err = NULL;

      if (ns && ns[0] != 0)
	{
	  orig_ns_fd = lcp_itf_get_ns_fd (NULL);
	  ns_fd = lcp_itf_get_ns_fd ((char *) ns);
	  if (orig_ns_fd == -1 || ns_fd == -1)
	    goto socket_close;

	  setns (ns_fd, CLONE_NEWNET);
	}

      vif_index = if_nametoindex ((const char *) host_if_name);

      if (!vif_index)
	{
	  /*
	   * no existing host interface, create it now
	   */
	  err = lcp_netlink_add_link_vlan (lip->lip_vif_index, vlan,
					   (const char *) host_if_name);

	  if (!err && -1 != ns_fd)
	    err = vnet_netlink_set_link_netns (vif_index, ns_fd, NULL);

	  if (!err)
	    vif_index = if_nametoindex ((char *) host_if_name);
	}

      /*
       * create a sub-interface on the tap
       */
      if (!err && vnet_create_sub_interface (lip->lip_host_sw_if_index,
					     sw->sub.id, sw->sub.eth.raw_flags,
					     sw->sub.eth.inner_vlan_id, vlan,
					     &host_sw_if_index))
	LCP_ITF_PAIR_INFO ("failed create vlan: %d on %U", vlan,
			   format_vnet_sw_if_index_name, vnet_get_main (),
			   lip->lip_host_sw_if_index);

    socket_close:
      if (orig_ns_fd != -1)
	{
	  setns (orig_ns_fd, CLONE_NEWNET);
	  close (orig_ns_fd);
	}
      if (ns_fd != -1)
	close (ns_fd);

      if (err)
	return VNET_API_ERROR_INVALID_ARGUMENT;
    }
  else
    {
      tap_create_if_args_t args = {
	.num_rx_queues = clib_max (1, vlib_num_workers ()),
	.id = hw->hw_if_index,
	.sw_if_index = ~0,
	.rx_ring_sz = 256,
	.tx_ring_sz = 256,
	.host_if_name = host_if_name,
	.host_namespace = 0,
      };
      ethernet_interface_t *ei;

      if (host_if_type == LCP_ITF_HOST_TUN)
	args.tap_flags |= TAP_FLAG_TUN;
      else
	{
	  ei = pool_elt_at_index (ethernet_main.interfaces, hw->hw_instance);
	  mac_address_copy (&args.host_mac_addr, &ei->address.mac);
	}

      if (sw->mtu[VNET_MTU_L3])
	{
	  args.host_mtu_set = 1;
	  args.host_mtu_size = sw->mtu[VNET_MTU_L3];
	}

      if (ns && ns[0] != 0)
	args.host_namespace = ns;

      vm = vlib_get_main ();
      tap_create_if (vm, &args);

      if (args.rv < 0)
	{
	  return args.rv;
	}

      /*
       * get the hw and ethernet of the tap
       */
      hw = vnet_get_sup_hw_interface (vnm, args.sw_if_index);

      /*
       * Set the interface down on the host side.
       * This controls whether the host can RX/TX.
       */
      virtio_main_t *mm = &virtio_main;
      virtio_if_t *vif = pool_elt_at_index (mm->interfaces, hw->dev_instance);

      lcp_itf_set_vif_link_state (vif->ifindex, 0 /* down */,
				  args.host_namespace);

      /*
       * Leave the TAP permanently up on the VPP side.
       * This TAP will be shared by many sub-interface.
       * Therefore we can't use it to manage admin state.
       * force the tap in promiscuous mode.
       */
      if (host_if_type == LCP_ITF_HOST_TAP)
	{
	  ei = pool_elt_at_index (ethernet_main.interfaces, hw->hw_instance);
	  ei->flags |= ETHERNET_INTERFACE_FLAG_STATUS_L3;
	}

      vif_index = vif->ifindex;
      host_sw_if_index = args.sw_if_index;
    }

  if (!vif_index)
    {
      LCP_ITF_PAIR_INFO ("failed pair add (no vif index): {%U, %U, %s}",
			 format_vnet_sw_if_index_name, vnet_get_main (),
			 phy_sw_if_index, format_vnet_sw_if_index_name,
			 vnet_get_main (), host_sw_if_index, host_if_name);
      return -1;
    }

  vnet_sw_interface_admin_up (vnm, host_sw_if_index);
  lcp_itf_pair_add (host_sw_if_index, phy_sw_if_index, host_if_name, vif_index,
		    host_if_type, ns);

  LCP_ITF_PAIR_INFO ("pair create: {%U, %U, %s}", format_vnet_sw_if_index_name,
		     vnet_get_main (), phy_sw_if_index,
		     format_vnet_sw_if_index_name, vnet_get_main (),
		     host_sw_if_index, host_if_name);

  return 0;
}

static walk_rc_t
lcp_itf_pair_walk_mark (index_t lipi, void *ctx)
{
  lcp_itf_pair_t *lip;

  lip = lcp_itf_pair_get (lipi);

  lip->lip_flags |= LIP_FLAG_STALE;

  return (WALK_CONTINUE);
}

int
lcp_itf_pair_replace_begin (void)
{
  lcp_itf_pair_walk (lcp_itf_pair_walk_mark, NULL);

  return (0);
}

typedef struct lcp_itf_pair_sweep_ctx_t_
{
  index_t *indicies;
} lcp_itf_pair_sweep_ctx_t;

static walk_rc_t
lcp_itf_pair_walk_sweep (index_t lipi, void *arg)
{
  lcp_itf_pair_sweep_ctx_t *ctx = arg;
  lcp_itf_pair_t *lip;

  lip = lcp_itf_pair_get (lipi);

  if (lip->lip_flags & LIP_FLAG_STALE)
    vec_add1 (ctx->indicies, lipi);

  return (WALK_CONTINUE);
}

int
lcp_itf_pair_replace_end (void)
{
  lcp_itf_pair_sweep_ctx_t ctx = {
    .indicies = NULL,
  };
  index_t *lipi;

  lcp_itf_pair_walk (lcp_itf_pair_walk_sweep, &ctx);

  vec_foreach (lipi, ctx.indicies)
    lcp_itf_pair_delete_by_index (*lipi);

  vec_free (ctx.indicies);
  return (0);
}

static uword
lcp_itf_pair_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
		      vlib_frame_t *f)
{
  uword *event_data = 0;
  uword *lipn_index;

  while (1)
    {
      vlib_process_wait_for_event (vm);

      vlib_process_get_events (vm, &event_data);

      vec_foreach (lipn_index, event_data)
	{
	  lcp_itf_pair_names_t *lipn;

	  lipn = &lipn_names[*lipn_index];
	  lcp_itf_pair_create (lipn->lipn_phy_sw_if_index,
			       lipn->lipn_host_name, LCP_ITF_HOST_TAP,
			       lipn->lipn_namespace);
	}

      vec_reset_length (event_data);
    }

  return 0;
}

VLIB_REGISTER_NODE (lcp_itf_pair_process_node, static) = {
  .function = lcp_itf_pair_process,
  .name = "linux-cp-itf-process",
  .type = VLIB_NODE_TYPE_PROCESS,
};

static clib_error_t *
lcp_itf_phy_add (vnet_main_t *vnm, u32 sw_if_index, u32 is_create)
{
  lcp_itf_pair_names_t *lipn;
  vlib_main_t *vm = vlib_get_main ();
  vnet_hw_interface_t *hw;

  if (!is_create || vnet_sw_interface_is_sub (vnm, sw_if_index))
    return NULL;

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);

  vec_foreach (lipn, lipn_names)
    {
      if (!vec_cmp (hw->name, lipn->lipn_phy_name))
	{
	  lipn->lipn_phy_sw_if_index = sw_if_index;

	  vlib_process_signal_event (vm, lcp_itf_pair_process_node.index, 0,
				     lipn - lipn_names);
	  break;
	}
    }

  return NULL;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (lcp_itf_phy_add);

static clib_error_t *
lcp_itf_pair_link_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  index_t lipi;
  lcp_itf_pair_t *lip;

  hi = vnet_get_hw_interface_or_null (vnm, hw_if_index);
  if (!hi)
    return 0;

  lipi = lcp_itf_pair_find_by_phy (hi->sw_if_index);
  if (lipi == INDEX_INVALID)
    return 0;

  lip = lcp_itf_pair_get (lipi);
  si = vnet_get_sw_interface_or_null (vnm, lip->lip_host_sw_if_index);
  if (!si)
    return 0;

  if (!lcp_main.test_mode)
    {
      tap_set_carrier (si->hw_if_index,
		       (flags & VNET_HW_INTERFACE_FLAG_LINK_UP));

      if (flags & VNET_HW_INTERFACE_FLAG_LINK_UP)
	{
	  tap_set_speed (si->hw_if_index, hi->link_speed / 1000);
	}
    }

  return 0;
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (lcp_itf_pair_link_up_down);

static clib_error_t *
lcp_itf_pair_init (vlib_main_t *vm)
{
  vlib_punt_hdl_t punt_hdl = vlib_punt_client_register ("linux-cp");

  /* punt IKE */
  vlib_punt_register (punt_hdl, ipsec_punt_reason[IPSEC_PUNT_IP4_SPI_UDP_0],
		      "linux-cp-punt");

  /* punt all unknown ports */
  udp_punt_unknown (vm, 0, 1);
  udp_punt_unknown (vm, 1, 1);
  tcp_punt_unknown (vm, 0, 1);
  tcp_punt_unknown (vm, 1, 1);

  lcp_itf_pair_logger = vlib_log_register_class ("linux-cp", "itf");

  return NULL;
}

VLIB_INIT_FUNCTION (lcp_itf_pair_init) = {
  .runs_after = VLIB_INITS ("vnet_interface_init", "tcp_init", "udp_init"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
