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
#include <fcntl.h>
#include <ctype.h>
#include <sys/socket.h>
#include <net/if.h>

#include <linux-cp/lcp_interface.h>
#include <netlink/route/link/vlan.h>
#include <linux/if_ether.h>

#include <vnet/plugin/plugin.h>
#include <vnet/plugin/plugin.h>

#include <vppinfra/linux/netns.h>

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

vlib_log_class_t lcp_itf_pair_logger;

/**
 * Pool of LIP objects
 */
lcp_itf_pair_t *lcp_itf_pair_pool = NULL;

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

/**
 * vector of virtual function table
 */
static lcp_itf_pair_vft_t *lcp_itf_vfts = NULL;

void
lcp_itf_pair_register_vft (lcp_itf_pair_vft_t *lcp_itf_vft)
{
  vec_add1 (lcp_itf_vfts, *lcp_itf_vft);
}

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
  vlib_cli_output (vm, "lcp lcp-auto-subint %s\n",
		   lcp_auto_subint () ? "on" : "off");
  vlib_cli_output (vm, "lcp lcp-sync %s\n", lcp_sync () ? "on" : "off");

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
  if (!lcp_itf_pair_pool)
    return NULL;
  if (index == INDEX_INVALID)
    return NULL;

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

int
lcp_itf_pair_add (u32 host_sw_if_index, u32 phy_sw_if_index, u8 *host_name,
		  u32 host_index, lip_host_type_t host_type, u8 *ns)
{
  index_t lipi;
  lcp_itf_pair_t *lip;

  if (host_sw_if_index == ~0)
    {
      LCP_ITF_PAIR_ERR ("pair_add: Cannot add LIP - invalid host");
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }

  lipi = lcp_itf_pair_find_by_phy (phy_sw_if_index);

  if (lipi != INDEX_INVALID)
    return VNET_API_ERROR_VALUE_EXIST;

  LCP_ITF_PAIR_INFO ("add: host:%U phy:%U, host_if:%v vif:%d ns:%s",
		     format_vnet_sw_if_index_name, vnet_get_main (),
		     host_sw_if_index, format_vnet_sw_if_index_name,
		     vnet_get_main (), phy_sw_if_index, host_name, host_index,
		     ns);

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

  /* invoke registered callbacks for pair addition */
  lcp_itf_pair_vft_t *vft;

  vec_foreach (vft, lcp_itf_vfts)
    {
      if (vft->pair_add_fn)
	vft->pair_add_fn (lip);
    }

  /* set timestamp when pair entered service */
  lip->lip_create_ts = vlib_time_now (vlib_get_main ());

  return 0;
}

static clib_error_t *
lcp_netlink_add_link_vlan (int parent, u32 vlan, u16 proto, const char *name)
{
  struct rtnl_link *link;
  struct nl_sock *sk;
  int err;

  sk = nl_socket_alloc ();
  if ((err = nl_connect (sk, NETLINK_ROUTE)) < 0)
    {
      LCP_ITF_PAIR_ERR ("netlink_add_link_vlan: connect error: %s",
			nl_geterror (err));
      return clib_error_return (NULL, "Unable to connect socket: %d", err);
    }

  link = rtnl_link_vlan_alloc ();

  rtnl_link_set_link (link, parent);
  rtnl_link_set_name (link, name);
  rtnl_link_vlan_set_id (link, vlan);
  rtnl_link_vlan_set_protocol (link, htons (proto));

  if ((err = rtnl_link_add (sk, link, NLM_F_CREATE)) < 0)
    {
      LCP_ITF_PAIR_ERR ("netlink_add_link_vlan: link add error: %s",
			nl_geterror (err));
      return clib_error_return (NULL, "Unable to add link %s: %d", name, err);
    }

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
  lcp_itf_pair_vft_t *vft;

  lipi = lcp_itf_pair_find_by_phy (phy_sw_if_index);

  if (lipi == INDEX_INVALID)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  lip = lcp_itf_pair_get (lipi);

  LCP_ITF_PAIR_NOTICE (
    "pair_del: host:%U phy:%U host_if:%s vif:%d ns:%s",
    format_vnet_sw_if_index_name, vnet_get_main (), lip->lip_host_sw_if_index,
    format_vnet_sw_if_index_name, vnet_get_main (), lip->lip_phy_sw_if_index,
    lip->lip_host_name, lip->lip_vif_index, lip->lip_namespace);

  /* invoke registered callbacks for pair deletion */
  vec_foreach (vft, lcp_itf_vfts)
    {
      if (vft->pair_del_fn)
	vft->pair_del_fn (lip);
    }

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
  lip_db_by_host[lip->lip_host_sw_if_index] = INDEX_INVALID;
  hash_unset (lip_db_by_vif, lip->lip_vif_index);

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
  u8 *host_name, *ns;

  lip = lcp_itf_pair_get (lipi);

  host_name = vec_dup (lip->lip_host_name);
  host_sw_if_index = lip->lip_host_sw_if_index;
  ns = vec_dup (lip->lip_namespace);

  lcp_itf_pair_del (lip->lip_phy_sw_if_index);

  if (vnet_sw_interface_is_sub (vnet_get_main (), host_sw_if_index))
    {
      int curr_ns_fd = -1;
      int vif_ns_fd = -1;
      if (ns)
	{
	  curr_ns_fd = clib_netns_open (NULL /* self */);
	  vif_ns_fd = clib_netns_open ((u8 *) ns);
	  if (vif_ns_fd != -1)
	    clib_setns (vif_ns_fd);
	}

      lcp_netlink_del_link ((const char *) host_name);
      if (vif_ns_fd != -1)
	close (vif_ns_fd);

      if (curr_ns_fd != -1)
	{
	  clib_setns (curr_ns_fd);
	  close (curr_ns_fd);
	}

      vnet_delete_sub_interface (host_sw_if_index);
    }
  else
    tap_delete_if (vlib_get_main (), host_sw_if_index);

  vec_free (host_name);
  vec_free (ns);
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

/**
 * lcp_itf_interface_add_del
 *
 * Registered to receive interface Add and delete notifications
 */
static clib_error_t *
lcp_itf_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  if (!is_add)
    /* remove any interface pair we have for this interface */
    lcp_itf_pair_delete (sw_if_index);

  return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (lcp_itf_interface_add_del);

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

static clib_error_t *
lcp_itf_pair_config (vlib_main_t *vm, unformat_input_t *input)
{
  u8 *default_ns;

  default_ns = NULL;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "default netns %v", &default_ns))
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
      else if (unformat (input, "lcp-auto-subint"))
	lcp_set_auto_subint (1 /* is_auto */);
      else if (unformat (input, "lcp-sync"))
	lcp_set_sync (1 /* is_auto */);
      else
	return clib_error_return (0, "interfaces not found");
    }

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

void
lcp_itf_set_link_state (const lcp_itf_pair_t *lip, u8 state)
{
  int curr_ns_fd, vif_ns_fd;

  if (!lip)
    return;

  curr_ns_fd = vif_ns_fd = -1;

  if (lip->lip_namespace)
    {
      curr_ns_fd = clib_netns_open (NULL /* self */);
      vif_ns_fd = clib_netns_open (lip->lip_namespace);
      if (vif_ns_fd != -1)
	clib_setns (vif_ns_fd);
    }

  /* Set the same link state on the netlink interface
   */
  vnet_netlink_set_link_state (lip->lip_vif_index, state);

  if (vif_ns_fd != -1)
    close (vif_ns_fd);

  if (curr_ns_fd != -1)
    {
      clib_setns (curr_ns_fd);
      close (curr_ns_fd);
    }

  return;
}

void
lcp_itf_set_interface_addr (const lcp_itf_pair_t *lip)
{
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  ip_lookup_main_t *lm4 = &im4->lookup_main;
  ip_lookup_main_t *lm6 = &im6->lookup_main;
  ip_interface_address_t *ia = 0;
  int vif_ns_fd = -1;
  int curr_ns_fd = -1;

  if (!lip)
    return;

  if (lip->lip_namespace)
    {
      curr_ns_fd = clib_netns_open (NULL /* self */);
      vif_ns_fd = clib_netns_open (lip->lip_namespace);
      if (vif_ns_fd != -1)
	clib_setns (vif_ns_fd);
    }

  /* Sync any IP4 addressing info into LCP */
  foreach_ip_interface_address (
    lm4, ia, lip->lip_phy_sw_if_index, 1 /* honor unnumbered */, ({
      ip4_address_t *r4 = ip_interface_address_get_address (lm4, ia);
      LCP_ITF_PAIR_NOTICE ("set_interface_addr: %U add ip4 %U/%d",
			   format_lcp_itf_pair, lip, format_ip4_address, r4,
			   ia->address_length);
      vnet_netlink_add_ip4_addr (lip->lip_vif_index, r4, ia->address_length);
    }));

  /* Sync any IP6 addressing info into LCP */
  foreach_ip_interface_address (
    lm6, ia, lip->lip_phy_sw_if_index, 1 /* honor unnumbered */, ({
      ip6_address_t *r6 = ip_interface_address_get_address (lm6, ia);
      LCP_ITF_PAIR_NOTICE ("set_interface_addr: %U add ip6 %U/%d",
			   format_lcp_itf_pair, lip, format_ip6_address, r6,
			   ia->address_length);
      vnet_netlink_add_ip6_addr (lip->lip_vif_index, r6, ia->address_length);
    }));

  if (vif_ns_fd != -1)
    close (vif_ns_fd);

  if (curr_ns_fd != -1)
    {
      clib_setns (curr_ns_fd);
      close (curr_ns_fd);
    }
}

typedef struct
{
  u32 vlan;
  bool dot1ad;

  u32 matched_sw_if_index;
} lcp_itf_match_t;

static walk_rc_t
lcp_itf_pair_find_walk (vnet_main_t *vnm, u32 sw_if_index, void *arg)
{
  lcp_itf_match_t *match = arg;
  const vnet_sw_interface_t *sw;

  sw = vnet_get_sw_interface (vnm, sw_if_index);
  if (sw && (sw->sub.eth.inner_vlan_id == 0) &&
      (sw->sub.eth.outer_vlan_id == match->vlan) &&
      (sw->sub.eth.flags.dot1ad == match->dot1ad))
    {
      LCP_ITF_PAIR_DBG ("find_walk: found match outer %d dot1ad %d "
			"inner-dot1q %d: interface %U",
			sw->sub.eth.outer_vlan_id, sw->sub.eth.flags.dot1ad,
			sw->sub.eth.inner_vlan_id,
			format_vnet_sw_if_index_name, vnet_get_main (),
			sw->sw_if_index);
      match->matched_sw_if_index = sw->sw_if_index;
      return WALK_STOP;
    }

  return WALK_CONTINUE;
}

/* Return the index of the sub-int on the phy that has the given vlan and
 * proto,
 */
static index_t
lcp_itf_pair_find_by_outer_vlan (u32 sup_if_index, u16 vlan, bool dot1ad)
{
  lcp_itf_match_t match;
  const vnet_hw_interface_t *hw;

  match.vlan = vlan;
  match.dot1ad = dot1ad;
  match.matched_sw_if_index = INDEX_INVALID;
  hw = vnet_get_sup_hw_interface (vnet_get_main (), sup_if_index);

  vnet_hw_interface_walk_sw (vnet_get_main (), hw->hw_if_index,
			     lcp_itf_pair_find_walk, &match);

  if (match.matched_sw_if_index >= vec_len (lip_db_by_phy))
    return INDEX_INVALID;

  return lip_db_by_phy[match.matched_sw_if_index];
}

int
lcp_itf_pair_create (u32 phy_sw_if_index, u8 *host_if_name,
		     lip_host_type_t host_if_type, u8 *ns,
		     u32 *host_sw_if_indexp)
{
  vlib_main_t *vm;
  vnet_main_t *vnm;
  u32 vif_index = 0, host_sw_if_index;
  const vnet_sw_interface_t *sw;
  const vnet_hw_interface_t *hw;
  const lcp_itf_pair_t *lip;

  if (!vnet_sw_if_index_is_api_valid (phy_sw_if_index))
    {
      LCP_ITF_PAIR_ERR ("pair_create: invalid phy index %u", phy_sw_if_index);
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }

  if (!lcp_validate_if_name (host_if_name))
    {
      LCP_ITF_PAIR_ERR ("pair_create: invalid host-if-name '%s'",
			host_if_name);
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  vnm = vnet_get_main ();
  sw = vnet_get_sw_interface (vnm, phy_sw_if_index);
  hw = vnet_get_sup_hw_interface (vnm, phy_sw_if_index);
  if (!sw || !hw)
    {
      LCP_ITF_PAIR_ERR ("pair_create: invalid interface");
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }

  /*
   * Use interface-specific netns if supplied.
   * Otherwise, use netns if defined, otherwise use the OS default.
   */
  if (ns == 0 || ns[0] == 0)
    ns = lcp_get_default_ns ();

  /* sub interfaces do not need a tap created */
  if (vnet_sw_interface_is_sub (vnm, phy_sw_if_index))
    {
      index_t parent_if_index;
      int orig_ns_fd, ns_fd;
      clib_error_t *err;
      u16 outer_vlan, inner_vlan;
      u16 outer_proto, inner_proto;
      u16 vlan, proto;
      u32 parent_vif_index;

      err = vnet_sw_interface_supports_addressing (vnm, phy_sw_if_index);
      if (err)
	{
	  LCP_ITF_PAIR_ERR ("pair_create: can't create LCP for a "
			    "sub-interface without exact-match set");
	  return VNET_API_ERROR_INVALID_ARGUMENT;
	}

      outer_vlan = sw->sub.eth.outer_vlan_id;
      inner_vlan = sw->sub.eth.inner_vlan_id;
      outer_proto = inner_proto = ETH_P_8021Q;
      if (1 == sw->sub.eth.flags.dot1ad)
	outer_proto = ETH_P_8021AD;

      LCP_ITF_PAIR_INFO ("pair_create: subif: dot1%s outer %d inner %d on %U",
			 sw->sub.eth.flags.dot1ad ? "ad" : "q", outer_vlan,
			 inner_vlan, format_vnet_sw_if_index_name, vnm,
			 hw->sw_if_index);

      parent_if_index = lcp_itf_pair_find_by_phy (sw->sup_sw_if_index);
      if (INDEX_INVALID == parent_if_index)
	{
	  LCP_ITF_PAIR_ERR ("pair_create: can't find LCP for %U",
			    format_vnet_sw_if_index_name, vnet_get_main (),
			    sw->sup_sw_if_index);
	  return VNET_API_ERROR_INVALID_SW_IF_INDEX;
	}
      lip = lcp_itf_pair_get (parent_if_index);
      if (!lip)
	{
	  LCP_ITF_PAIR_ERR ("pair_create: can't create LCP for a "
			    "sub-interface without an LCP on the parent");
	  return VNET_API_ERROR_INVALID_ARGUMENT;
	}
      LCP_ITF_PAIR_DBG ("pair_create: parent %U", format_lcp_itf_pair, lip);
      parent_vif_index = lip->lip_vif_index;

      /*
       * see if the requested host interface has already been created
       */
      orig_ns_fd = ns_fd = -1;
      err = NULL;

      if (ns && ns[0] != 0)
	{
	  orig_ns_fd = clib_netns_open (NULL /* self */);
	  ns_fd = clib_netns_open (ns);
	  if (orig_ns_fd == -1 || ns_fd == -1)
	    goto socket_close;

	  clib_setns (ns_fd);
	}

      vif_index = if_nametoindex ((const char *) host_if_name);

      if (!vif_index)
	{
	  /*
	   * no existing host interface, create it now
	   */

	  /*
	   * Find the parent tap:
	   * - if this is an outer VLAN, use the pair from the parent phy
	   * - if this is an inner VLAN, find the pair from the outer sub-int,
	   * which must exist.
	   */
	  if (inner_vlan)
	    {
	      index_t linux_parent_if_index;
	      const lcp_itf_pair_t *llip;

	      vlan = inner_vlan;
	      proto = inner_proto;
	      linux_parent_if_index = lcp_itf_pair_find_by_outer_vlan (
		hw->sw_if_index, sw->sub.eth.outer_vlan_id,
		sw->sub.eth.flags.dot1ad);
	      if (INDEX_INVALID == linux_parent_if_index ||
		  !(llip = lcp_itf_pair_get (linux_parent_if_index)))
		{
		  LCP_ITF_PAIR_ERR (
		    "pair_create: can't find LCP for outer vlan %d "
		    "proto %s on %U",
		    outer_vlan,
		    outer_proto == ETH_P_8021AD ? "dot1ad" : "dot1q",
		    format_vnet_sw_if_index_name, vnm, hw->sw_if_index);
		  err = clib_error_return (0, "parent pair not found");
		  goto socket_close;
		}

	      LCP_ITF_PAIR_DBG ("pair_create: linux parent %U",
				format_lcp_itf_pair, llip);
	      parent_vif_index = llip->lip_vif_index;
	    }
	  else
	    {
	      vlan = outer_vlan;
	      proto = outer_proto;
	    }

	  err = lcp_netlink_add_link_vlan (parent_vif_index, vlan, proto,
					   (const char *) host_if_name);
	  if (err != 0)
	    {
	      LCP_ITF_PAIR_ERR ("pair_create: cannot create link "
				"outer(proto:0x%04x,vlan:%u).inner(proto:0x%"
				"04x,vlan:%u) name:'%s'",
				outer_proto, outer_vlan, inner_proto,
				inner_vlan, host_if_name);
	    }

	  if (!err)
	    vif_index = if_nametoindex ((char *) host_if_name);
	}

      /*
       * create a sub-interface on the tap
       */
      if (!err &&
	  vnet_create_sub_interface (lip->lip_host_sw_if_index, sw->sub.id,
				     sw->sub.eth.raw_flags, inner_vlan,
				     outer_vlan, &host_sw_if_index))
	{
	  LCP_ITF_PAIR_ERR (
	    "pair_create: failed to create tap subint: %d.%d on %U",
	    outer_vlan, inner_vlan, format_vnet_sw_if_index_name, vnm,
	    lip->lip_host_sw_if_index);
	  err = clib_error_return (
	    0, "failed to create tap subint: %d.%d. on %U", outer_vlan,
	    inner_vlan, format_vnet_sw_if_index_name, vnm,
	    lip->lip_host_sw_if_index);
	}

    socket_close:
      if (orig_ns_fd != -1)
	{
	  clib_setns (orig_ns_fd);
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
	.num_tx_queues = 1,
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
	  LCP_ITF_PAIR_ERR ("pair_create: could not create tap, retval:%d",
			    args.rv);
	  return args.rv;
	}

      /*
       * The TAP interface does copy forward the host MTU based on the VPP
       * interface's L3 MTU, but it should also ensure that the VPP tap
       * interface has an MTU that is greater-or-equal to those. Considering
       * users can set the interfaces at runtime (set interface mtu packet ...)
       * ensure that the tap MTU is large enough, taking the VPP interface L3
       * if it's set, and otherwise a sensible default.
       */
      if (sw->mtu[VNET_MTU_L3])
	vnet_sw_interface_set_mtu (vnm, args.sw_if_index,
				   sw->mtu[VNET_MTU_L3]);
      else
	vnet_sw_interface_set_mtu (vnm, args.sw_if_index,
				   ETHERNET_MAX_PACKET_BYTES);

      /*
       * get the hw and ethernet of the tap
       */
      hw = vnet_get_sup_hw_interface (vnm, args.sw_if_index);
      virtio_main_t *mm = &virtio_main;
      virtio_if_t *vif = pool_elt_at_index (mm->interfaces, hw->dev_instance);

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

  LCP_ITF_PAIR_INFO ("pair create: {%U, %U, %s}", format_vnet_sw_if_index_name,
		     vnet_get_main (), phy_sw_if_index,
		     format_vnet_sw_if_index_name, vnet_get_main (),
		     host_sw_if_index, host_if_name);
  lcp_itf_pair_add (host_sw_if_index, phy_sw_if_index, host_if_name, vif_index,
		    host_if_type, ns);

  /*
   * Copy the link state from VPP into the host side.
   * The TAP is shared by many interfaces, always keep it up.
   * This controls whether the host can RX/TX.
   */

  lip = lcp_itf_pair_get (lcp_itf_pair_find_by_vif (vif_index));
  LCP_ITF_PAIR_INFO ("pair create: %U sw-flags %u hw-flags %u",
		     format_lcp_itf_pair, lip, sw->flags, hw->flags);
  vnet_sw_interface_admin_up (vnm, host_sw_if_index);
  lcp_itf_set_link_state (lip, sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  if (host_sw_if_indexp)
    *host_sw_if_indexp = host_sw_if_index;

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
lcp_interface_init (vlib_main_t *vm)
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

  lcp_itf_pair_logger = vlib_log_register_class ("linux-cp", "if");

  return NULL;
}

VLIB_INIT_FUNCTION (lcp_interface_init) = {
  .runs_after = VLIB_INITS ("vnet_interface_init", "tcp_init", "udp_init"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
