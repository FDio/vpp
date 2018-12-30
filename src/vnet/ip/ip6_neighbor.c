/*
 * ip/ip6_neighbor.c: IP6 neighbor handling
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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

#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_neighbor.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/mhash.h>
#include <vnet/adj/adj.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/mfib/ip6_mfib.h>
#include <vnet/ip/ip6_ll_table.h>
#include <vnet/l2/l2_input.h>

/**
 * @file
 * @brief IPv6 Neighbor Adjacency and Neighbor Discovery.
 *
 * The files contains the API and CLI code for managing IPv6 neighbor
 * adjacency tables and neighbor discovery logic.
 */

/* can't use sizeof link_layer_address, that's 8 */
#define ETHER_MAC_ADDR_LEN 6

/* advertised prefix option */
typedef struct
{
  /* basic advertised information */
  ip6_address_t prefix;
  u8 prefix_len;
  int adv_on_link_flag;
  int adv_autonomous_flag;
  u32 adv_valid_lifetime_in_secs;
  u32 adv_pref_lifetime_in_secs;

  /* advertised values are computed from these times if decrementing */
  f64 valid_lifetime_expires;
  f64 pref_lifetime_expires;

  /* local information */
  int enabled;
  int deprecated_prefix_flag;
  int decrement_lifetime_flag;

#define MIN_ADV_VALID_LIFETIME 7203	/* seconds */
#define DEF_ADV_VALID_LIFETIME  2592000
#define DEF_ADV_PREF_LIFETIME 604800

  /* extensions are added here, mobile, DNS etc.. */
} ip6_radv_prefix_t;


typedef struct
{
  /* group information */
  u8 type;
  ip6_address_t mcast_address;
  u16 num_sources;
  ip6_address_t *mcast_source_address_pool;
} ip6_mldp_group_t;

/* configured router advertisement information per ipv6 interface */
typedef struct
{

  /* advertised config information, zero means unspecified  */
  u8 curr_hop_limit;
  int adv_managed_flag;
  int adv_other_flag;
  u16 adv_router_lifetime_in_sec;
  u32 adv_neighbor_reachable_time_in_msec;
  u32 adv_time_in_msec_between_retransmitted_neighbor_solicitations;

  /* mtu option */
  u32 adv_link_mtu;

  /* source link layer option */
  u8 link_layer_address[8];
  u8 link_layer_addr_len;

  /* prefix option */
  ip6_radv_prefix_t *adv_prefixes_pool;

  /* Hash table mapping address to index in interface advertised  prefix pool. */
  mhash_t address_to_prefix_index;

  /* MLDP  group information */
  ip6_mldp_group_t *mldp_group_pool;

  /* Hash table mapping address to index in mldp address pool. */
  mhash_t address_to_mldp_index;

  /* local information */
  u32 sw_if_index;
  int send_radv;		/* radv on/off on this interface -  set by config */
  int cease_radv;		/* we are ceasing  to send  - set byf config */
  int send_unicast;
  int adv_link_layer_address;
  int prefix_option;
  int failed_device_check;
  int all_routers_mcast;
  u32 seed;
  u64 randomizer;
  int ref_count;
  adj_index_t mcast_adj_index;

  /* timing information */
#define DEF_MAX_RADV_INTERVAL 200
#define DEF_MIN_RADV_INTERVAL .75 * DEF_MAX_RADV_INTERVAL
#define DEF_CURR_HOP_LIMIT  64
#define DEF_DEF_RTR_LIFETIME   3 * DEF_MAX_RADV_INTERVAL
#define MAX_DEF_RTR_LIFETIME   9000

#define MAX_INITIAL_RTR_ADVERT_INTERVAL   16	/* seconds */
#define MAX_INITIAL_RTR_ADVERTISEMENTS        3	/*transmissions */
#define MIN_DELAY_BETWEEN_RAS                              3	/* seconds */
#define MAX_DELAY_BETWEEN_RAS                    1800	/* seconds */
#define MAX_RA_DELAY_TIME                                          .5	/* seconds */

  f64 max_radv_interval;
  f64 min_radv_interval;
  f64 min_delay_between_radv;
  f64 max_delay_between_radv;
  f64 max_rtr_default_lifetime;

  f64 last_radv_time;
  f64 last_multicast_time;
  f64 next_multicast_time;


  u32 initial_adverts_count;
  f64 initial_adverts_interval;
  u32 initial_adverts_sent;

  /* stats */
  u32 n_advertisements_sent;
  u32 n_solicitations_rcvd;
  u32 n_solicitations_dropped;

  /* Link local address to use (defaults to underlying physical for logical interfaces */
  ip6_address_t link_local_address;

  /* router solicitations sending state */
  u8 keep_sending_rs;		/* when true then next fields are valid */
  icmp6_send_router_solicitation_params_t params;
  f64 sleep_interval;
  f64 due_time;
  u32 n_left;
  f64 start_time;
  vlib_buffer_t *buffer;
} ip6_radv_t;

typedef struct
{
  u32 next_index;
  uword node_index;
  uword type_opaque;
  uword data;
  /* Used for nd event notification only */
  void *data_callback;
  u32 pid;
} pending_resolution_t;


typedef struct
{
  /* Hash tables mapping name to opcode. */
  uword *opcode_by_name;

  /* lite beer "glean" adjacency handling */
  mhash_t pending_resolutions_by_address;
  pending_resolution_t *pending_resolutions;

  /* Mac address change notification */
  mhash_t mac_changes_by_address;
  pending_resolution_t *mac_changes;

  u32 *neighbor_input_next_index_by_hw_if_index;

  ip6_neighbor_t *neighbor_pool;

  mhash_t neighbor_index_by_key;

  u32 *if_radv_pool_index_by_sw_if_index;

  ip6_radv_t *if_radv_pool;

  /* Neighbor attack mitigation */
  u32 limit_neighbor_cache_size;
  u32 neighbor_delete_rotor;

  /* Wildcard nd report publisher */
  uword wc_ip6_nd_publisher_node;
  uword wc_ip6_nd_publisher_et;

  /* Router advertisement report publisher */
  uword ip6_ra_publisher_node;
  uword ip6_ra_publisher_et;
} ip6_neighbor_main_t;

/* ipv6 neighbor discovery - timer/event types */
typedef enum
{
  ICMP6_ND_EVENT_INIT,
} ip6_icmp_neighbor_discovery_event_type_t;

typedef union
{
  u32 add_del_swindex;
  struct
  {
    u32 up_down_swindex;
    u32 fib_index;
  } up_down_event;
} ip6_icmp_neighbor_discovery_event_data_t;

static ip6_neighbor_main_t ip6_neighbor_main;
ip6_neighbor_public_main_t ip6_neighbor_public_main;
static ip6_address_t ip6a_zero;	/* ip6 address 0 */

static void wc_nd_signal_report (wc_nd_report_t * r);
static void ra_signal_report (ra_report_t * r);

ip6_address_t
ip6_neighbor_get_link_local_address (u32 sw_if_index)
{
  static ip6_address_t empty_address = { {0} };
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_radv_t *radv_info;
  u32 ri = ~0;

  if (vec_len (nm->if_radv_pool_index_by_sw_if_index) > sw_if_index)
    ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];
  if (ri == ~0)
    {
      clib_warning ("IPv6 is not enabled for sw_if_index %d", sw_if_index);
      return empty_address;
    }
  radv_info = pool_elt_at_index (nm->if_radv_pool, ri);
  if (radv_info == NULL)
    {
      clib_warning ("Internal error");
      return empty_address;
    }
  return radv_info->link_local_address;
}

/**
 * @brief publish wildcard arp event
 * @param sw_if_index The interface on which the ARP entires are acted
 */
static int
vnet_nd_wc_publish (u32 sw_if_index, u8 * mac, ip6_address_t * ip6)
{
  wc_nd_report_t r = {
    .sw_if_index = sw_if_index,
    .ip6 = *ip6,
  };
  memcpy (r.mac, mac, sizeof r.mac);

  void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);
  vl_api_rpc_call_main_thread (wc_nd_signal_report, (u8 *) & r, sizeof r);
  return 0;
}

static void
wc_nd_signal_report (wc_nd_report_t * r)
{
  vlib_main_t *vm = vlib_get_main ();
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  uword ni = nm->wc_ip6_nd_publisher_node;
  uword et = nm->wc_ip6_nd_publisher_et;

  if (ni == (uword) ~ 0)
    return;
  wc_nd_report_t *q =
    vlib_process_signal_event_data (vm, ni, et, 1, sizeof *q);

  *q = *r;
}

void
wc_nd_set_publisher_node (uword node_index, uword event_type)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  nm->wc_ip6_nd_publisher_node = node_index;
  nm->wc_ip6_nd_publisher_et = event_type;
}

static int
ra_publish (ra_report_t * r)
{
  void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);
  vl_api_rpc_call_main_thread (ra_signal_report, (u8 *) r, sizeof *r);
  return 0;
}

static void
ra_signal_report (ra_report_t * r)
{
  vlib_main_t *vm = vlib_get_main ();
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  uword ni = nm->ip6_ra_publisher_node;
  uword et = nm->ip6_ra_publisher_et;

  if (ni == (uword) ~ 0)
    return;
  ra_report_t *q = vlib_process_signal_event_data (vm, ni, et, 1, sizeof *q);

  *q = *r;
}

void
ra_set_publisher_node (uword node_index, uword event_type)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  nm->ip6_ra_publisher_node = node_index;
  nm->ip6_ra_publisher_et = event_type;
}

static u8 *
format_ip6_neighbor_ip6_entry (u8 * s, va_list * va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  ip6_neighbor_t *n = va_arg (*va, ip6_neighbor_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si;
  u8 *flags = 0;

  if (!n)
    return format (s, "%=12s%=45s%=6s%=20s%=40s", "Time", "Address", "Flags",
		   "Link layer", "Interface");

  if (n->flags & IP6_NEIGHBOR_FLAG_DYNAMIC)
    flags = format (flags, "D");

  if (n->flags & IP6_NEIGHBOR_FLAG_STATIC)
    flags = format (flags, "S");

  if (n->flags & IP6_NEIGHBOR_FLAG_NO_FIB_ENTRY)
    flags = format (flags, "N");

  si = vnet_get_sw_interface (vnm, n->key.sw_if_index);
  s = format (s, "%=12U%=45U%=6s%=20U%=40U",
	      format_vlib_time, vm, n->time_last_updated,
	      format_ip6_address, &n->key.ip6_address,
	      flags ? (char *) flags : "",
	      format_ethernet_address, n->link_layer_address,
	      format_vnet_sw_interface_name, vnm, si);

  vec_free (flags);
  return s;
}

static void
ip6_neighbor_adj_fib_remove (ip6_neighbor_t * n, u32 fib_index)
{
  if (FIB_NODE_INDEX_INVALID != n->fib_entry_index)
    {
      if (ip6_address_is_link_local_unicast (&n->key.ip6_address))
	{
	  ip6_ll_prefix_t pfx = {
	    .ilp_addr = n->key.ip6_address,
	    .ilp_sw_if_index = n->key.sw_if_index,
	  };
	  ip6_ll_table_entry_delete (&pfx);
	}
      else
	{
	  fib_prefix_t pfx = {
	    .fp_len = 128,
	    .fp_proto = FIB_PROTOCOL_IP6,
	    .fp_addr.ip6 = n->key.ip6_address,
	  };
	  fib_table_entry_path_remove (fib_index,
				       &pfx,
				       FIB_SOURCE_ADJ,
				       DPO_PROTO_IP6,
				       &pfx.fp_addr,
				       n->key.sw_if_index, ~0,
				       1, FIB_ROUTE_PATH_FLAG_NONE);
	}
    }
}

typedef struct
{
  u8 is_add;
  u8 is_static;
  u8 is_no_fib_entry;
  u8 link_layer_address[6];
  u32 sw_if_index;
  ip6_address_t addr;
} ip6_neighbor_set_unset_rpc_args_t;

static void ip6_neighbor_set_unset_rpc_callback
  (ip6_neighbor_set_unset_rpc_args_t * a);

static void set_unset_ip6_neighbor_rpc
  (vlib_main_t * vm,
   u32 sw_if_index,
   const ip6_address_t * a,
   const u8 * link_layer_address,
   int is_add, int is_static, int is_no_fib_entry)
{
  ip6_neighbor_set_unset_rpc_args_t args;
  void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);

  args.sw_if_index = sw_if_index;
  args.is_add = is_add;
  args.is_static = is_static;
  args.is_no_fib_entry = is_no_fib_entry;
  clib_memcpy (&args.addr, a, sizeof (*a));
  if (NULL != link_layer_address)
    clib_memcpy (args.link_layer_address, link_layer_address, 6);

  vl_api_rpc_call_main_thread (ip6_neighbor_set_unset_rpc_callback,
			       (u8 *) & args, sizeof (args));
}

static void
ip6_nbr_probe (ip_adjacency_t * adj)
{
  icmp6_neighbor_solicitation_header_t *h;
  vnet_main_t *vnm = vnet_get_main ();
  ip6_main_t *im = &ip6_main;
  ip_interface_address_t *ia;
  ip6_address_t *dst, *src;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  vlib_buffer_t *b;
  int bogus_length;
  vlib_main_t *vm;
  u32 bi = 0;

  vm = vlib_get_main ();

  si = vnet_get_sw_interface (vnm, adj->rewrite_header.sw_if_index);
  dst = &adj->sub_type.nbr.next_hop.ip6;

  if (!(si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
    {
      return;
    }
  src = ip6_interface_address_matching_destination (im, dst,
						    adj->rewrite_header.
						    sw_if_index, &ia);
  if (!src)
    {
      return;
    }

  h = vlib_packet_template_get_packet (vm,
				       &im->discover_neighbor_packet_template,
				       &bi);
  if (!h)
    return;

  hi = vnet_get_sup_hw_interface (vnm, adj->rewrite_header.sw_if_index);

  h->ip.dst_address.as_u8[13] = dst->as_u8[13];
  h->ip.dst_address.as_u8[14] = dst->as_u8[14];
  h->ip.dst_address.as_u8[15] = dst->as_u8[15];
  h->ip.src_address = src[0];
  h->neighbor.target_address = dst[0];

  clib_memcpy (h->link_layer_option.ethernet_address,
	       hi->hw_address, vec_len (hi->hw_address));

  h->neighbor.icmp.checksum =
    ip6_tcp_udp_icmp_compute_checksum (vm, 0, &h->ip, &bogus_length);
  ASSERT (bogus_length == 0);

  b = vlib_get_buffer (vm, bi);
  vnet_buffer (b)->sw_if_index[VLIB_RX] =
    vnet_buffer (b)->sw_if_index[VLIB_TX] = adj->rewrite_header.sw_if_index;

  /* Add encapsulation string for software interface (e.g. ethernet header). */
  vnet_rewrite_one_header (adj[0], h, sizeof (ethernet_header_t));
  vlib_buffer_advance (b, -adj->rewrite_header.data_bytes);

  {
    vlib_frame_t *f = vlib_get_frame_to_node (vm, hi->output_node_index);
    u32 *to_next = vlib_frame_vector_args (f);
    to_next[0] = bi;
    f->n_vectors = 1;
    vlib_put_frame_to_node (vm, hi->output_node_index, f);
  }
}

static void
ip6_nd_mk_complete (adj_index_t ai, ip6_neighbor_t * nbr)
{
  adj_nbr_update_rewrite (ai, ADJ_NBR_REWRITE_FLAG_COMPLETE,
			  ethernet_build_rewrite (vnet_get_main (),
						  nbr->key.sw_if_index,
						  adj_get_link_type (ai),
						  nbr->link_layer_address));
}

static void
ip6_nd_mk_incomplete (adj_index_t ai)
{
  ip_adjacency_t *adj = adj_get (ai);

  adj_nbr_update_rewrite (ai,
			  ADJ_NBR_REWRITE_FLAG_INCOMPLETE,
			  ethernet_build_rewrite (vnet_get_main (),
						  adj->rewrite_header.
						  sw_if_index,
						  adj_get_link_type (ai),
						  VNET_REWRITE_FOR_SW_INTERFACE_ADDRESS_BROADCAST));
}

#define IP6_NBR_MK_KEY(k, sw_if_index, addr) \
{					     \
    k.sw_if_index = sw_if_index;	     \
    k.ip6_address = *addr;		     \
    k.pad = 0;				     \
}

static ip6_neighbor_t *
ip6_nd_find (u32 sw_if_index, const ip6_address_t * addr)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_neighbor_t *n = NULL;
  ip6_neighbor_key_t k;
  uword *p;

  IP6_NBR_MK_KEY (k, sw_if_index, addr);

  p = mhash_get (&nm->neighbor_index_by_key, &k);
  if (p)
    {
      n = pool_elt_at_index (nm->neighbor_pool, p[0]);
    }

  return (n);
}

static adj_walk_rc_t
ip6_nd_mk_complete_walk (adj_index_t ai, void *ctx)
{
  ip6_neighbor_t *nbr = ctx;

  ip6_nd_mk_complete (ai, nbr);

  return (ADJ_WALK_RC_CONTINUE);
}

static adj_walk_rc_t
ip6_nd_mk_incomplete_walk (adj_index_t ai, void *ctx)
{
  ip6_nd_mk_incomplete (ai);

  return (ADJ_WALK_RC_CONTINUE);
}

static clib_error_t *
ip6_neighbor_sw_interface_up_down (vnet_main_t * vnm,
				   u32 sw_if_index, u32 flags)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_neighbor_t *n;
  u32 i, *to_delete = 0;

  /* *INDENT-OFF* */
  pool_foreach (n, nm->neighbor_pool,
  ({
    if (n->key.sw_if_index == sw_if_index)
      vec_add1 (to_delete, n - nm->neighbor_pool);
  }));
  /* *INDENT-ON* */

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    {
      for (i = 0; i < vec_len (to_delete); i++)
	{
	  n = pool_elt_at_index (nm->neighbor_pool, to_delete[i]);
	  adj_nbr_walk_nh6 (n->key.sw_if_index, &n->key.ip6_address,
			    ip6_nd_mk_complete_walk, n);
	}
    }
  else
    {
      for (i = 0; i < vec_len (to_delete); i++)
	{
	  n = pool_elt_at_index (nm->neighbor_pool, to_delete[i]);
	  adj_nbr_walk_nh6 (n->key.sw_if_index, &n->key.ip6_address,
			    ip6_nd_mk_incomplete_walk, NULL);
	  if (n->flags & IP6_NEIGHBOR_FLAG_STATIC)
	    continue;
	  ip6_neighbor_adj_fib_remove (n,
				       ip6_fib_table_get_index_for_sw_if_index
				       (n->key.sw_if_index));
	  mhash_unset (&nm->neighbor_index_by_key, &n->key, 0);
	  pool_put (nm->neighbor_pool, n);
	}
    }

  vec_free (to_delete);
  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (ip6_neighbor_sw_interface_up_down);

void
ip6_ethernet_update_adjacency (vnet_main_t * vnm, u32 sw_if_index, u32 ai)
{
  ip6_neighbor_t *nbr;
  ip_adjacency_t *adj;

  adj = adj_get (ai);

  nbr = ip6_nd_find (sw_if_index, &adj->sub_type.nbr.next_hop.ip6);

  switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_GLEAN:
      adj_glean_update_rewrite (ai);
      break;
    case IP_LOOKUP_NEXT_ARP:
      if (NULL != nbr)
	{
	  adj_nbr_walk_nh6 (sw_if_index, &nbr->key.ip6_address,
			    ip6_nd_mk_complete_walk, nbr);
	}
      else
	{
	  /*
	   * no matching ND entry.
	   * construct the rewrite required to for an ND packet, and stick
	   * that in the adj's pipe to smoke.
	   */
	  adj_nbr_update_rewrite (ai,
				  ADJ_NBR_REWRITE_FLAG_INCOMPLETE,
				  ethernet_build_rewrite (vnm,
							  sw_if_index,
							  VNET_LINK_IP6,
							  VNET_REWRITE_FOR_SW_INTERFACE_ADDRESS_BROADCAST));

	  /*
	   * since the FIB has added this adj for a route, it makes sense it may
	   * want to forward traffic sometime soon. Let's send a speculative ND.
	   * just one. If we were to do periodically that wouldn't be bad either,
	   * but that's more code than i'm prepared to write at this time for
	   * relatively little reward.
	   */
	  ip6_nbr_probe (adj);
	}
      break;
    case IP_LOOKUP_NEXT_BCAST:
      adj_nbr_update_rewrite (ai,
			      ADJ_NBR_REWRITE_FLAG_COMPLETE,
			      ethernet_build_rewrite (vnm,
						      sw_if_index,
						      VNET_LINK_IP6,
						      VNET_REWRITE_FOR_SW_INTERFACE_ADDRESS_BROADCAST));
      break;
    case IP_LOOKUP_NEXT_MCAST:
      {
	/*
	 * Construct a partial rewrite from the known ethernet mcast dest MAC
	 */
	u8 *rewrite;
	u8 offset;

	rewrite = ethernet_build_rewrite (vnm,
					  sw_if_index,
					  adj->ia_link,
					  ethernet_ip6_mcast_dst_addr ());

	/*
	 * Complete the remaining fields of the adj's rewrite to direct the
	 * complete of the rewrite at switch time by copying in the IP
	 * dst address's bytes.
	 * Ofset is 2 bytes into the desintation address.
	 */
	offset = vec_len (rewrite) - 2;
	adj_mcast_update_rewrite (ai, rewrite, offset);

	break;
      }
    case IP_LOOKUP_NEXT_DROP:
    case IP_LOOKUP_NEXT_PUNT:
    case IP_LOOKUP_NEXT_LOCAL:
    case IP_LOOKUP_NEXT_REWRITE:
    case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
    case IP_LOOKUP_NEXT_MIDCHAIN:
    case IP_LOOKUP_NEXT_ICMP_ERROR:
    case IP_LOOKUP_N_NEXT:
      ASSERT (0);
      break;
    }
}


static void
ip6_neighbor_adj_fib_add (ip6_neighbor_t * n, u32 fib_index)
{
  if (ip6_address_is_link_local_unicast (&n->key.ip6_address))
    {
      ip6_ll_prefix_t pfx = {
	.ilp_addr = n->key.ip6_address,
	.ilp_sw_if_index = n->key.sw_if_index,
      };
      n->fib_entry_index =
	ip6_ll_table_entry_update (&pfx, FIB_ROUTE_PATH_FLAG_NONE);
    }
  else
    {
      fib_prefix_t pfx = {
	.fp_len = 128,
	.fp_proto = FIB_PROTOCOL_IP6,
	.fp_addr.ip6 = n->key.ip6_address,
      };

      n->fib_entry_index =
	fib_table_entry_path_add (fib_index, &pfx, FIB_SOURCE_ADJ,
				  FIB_ENTRY_FLAG_ATTACHED,
				  DPO_PROTO_IP6, &pfx.fp_addr,
				  n->key.sw_if_index, ~0, 1, NULL,
				  FIB_ROUTE_PATH_FLAG_NONE);
    }
}

static ip6_neighbor_t *
force_reuse_neighbor_entry (void)
{
  ip6_neighbor_t *n;
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  u32 count = 0;
  u32 index = pool_next_index (nm->neighbor_pool, nm->neighbor_delete_rotor);
  if (index == ~0)		/* Try again from elt 0 */
    index = pool_next_index (nm->neighbor_pool, index);

  /* Find a non-static random entry to free up for reuse */
  do
    {
      if ((count++ == 100) || (index == ~0))
	return NULL;		/* give up after 100 entries */
      n = pool_elt_at_index (nm->neighbor_pool, index);
      nm->neighbor_delete_rotor = index;
      index = pool_next_index (nm->neighbor_pool, index);
    }
  while (n->flags & IP6_NEIGHBOR_FLAG_STATIC);

  /* Remove ARP entry from its interface and update fib */
  adj_nbr_walk_nh6 (n->key.sw_if_index,
		    &n->key.ip6_address, ip6_nd_mk_incomplete_walk, NULL);
  ip6_neighbor_adj_fib_remove
    (n, ip6_fib_table_get_index_for_sw_if_index (n->key.sw_if_index));
  mhash_unset (&nm->neighbor_index_by_key, &n->key, 0);

  return n;
}

int
vnet_set_ip6_ethernet_neighbor (vlib_main_t * vm,
				u32 sw_if_index,
				const ip6_address_t * a,
				const u8 * link_layer_address,
				uword n_bytes_link_layer_address,
				int is_static, int is_no_fib_entry)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_neighbor_key_t k;
  ip6_neighbor_t *n = 0;
  int make_new_nd_cache_entry = 1;
  uword *p;
  u32 next_index;
  pending_resolution_t *pr, *mc;

  if (vlib_get_thread_index ())
    {
      set_unset_ip6_neighbor_rpc (vm, sw_if_index, a, link_layer_address,
				  1 /* set new neighbor */ , is_static,
				  is_no_fib_entry);
      return 0;
    }

  k.sw_if_index = sw_if_index;
  k.ip6_address = a[0];
  k.pad = 0;

  p = mhash_get (&nm->neighbor_index_by_key, &k);
  if (p)
    {
      n = pool_elt_at_index (nm->neighbor_pool, p[0]);
      /* Refuse to over-write static neighbor entry. */
      if (!is_static && (n->flags & IP6_NEIGHBOR_FLAG_STATIC))
	{
	  /* if MAC address match, still check to send event */
	  if (0 == memcmp (n->link_layer_address,
			   link_layer_address, n_bytes_link_layer_address))
	    goto check_customers;
	  return -2;
	}
      make_new_nd_cache_entry = 0;
    }

  if (make_new_nd_cache_entry)
    {
      if (nm->limit_neighbor_cache_size &&
	  pool_elts (nm->neighbor_pool) >= nm->limit_neighbor_cache_size)
	{
	  n = force_reuse_neighbor_entry ();
	  if (NULL == n)
	    return -2;
	}
      else
	pool_get (nm->neighbor_pool, n);

      mhash_set (&nm->neighbor_index_by_key, &k, n - nm->neighbor_pool,
		 /* old value */ 0);
      n->key = k;
      n->fib_entry_index = FIB_NODE_INDEX_INVALID;

      clib_memcpy (n->link_layer_address,
		   link_layer_address, n_bytes_link_layer_address);

      /*
       * create the adj-fib. the entry in the FIB table for and to the peer.
       */
      if (!is_no_fib_entry)
	{
	  ip6_neighbor_adj_fib_add
	    (n, ip6_fib_table_get_index_for_sw_if_index (n->key.sw_if_index));
	}
      else
	{
	  n->flags |= IP6_NEIGHBOR_FLAG_NO_FIB_ENTRY;
	}
    }
  else
    {
      /*
       * prevent a DoS attack from the data-plane that
       * spams us with no-op updates to the MAC address
       */
      if (0 == memcmp (n->link_layer_address,
		       link_layer_address, n_bytes_link_layer_address))
	{
	  n->time_last_updated = vlib_time_now (vm);
	  goto check_customers;
	}

      clib_memcpy (n->link_layer_address,
		   link_layer_address, n_bytes_link_layer_address);
    }

  /* Update time stamp and flags. */
  n->time_last_updated = vlib_time_now (vm);
  if (is_static)
    {
      n->flags |= IP6_NEIGHBOR_FLAG_STATIC;
      n->flags &= ~IP6_NEIGHBOR_FLAG_DYNAMIC;
    }
  else
    {
      n->flags |= IP6_NEIGHBOR_FLAG_DYNAMIC;
      n->flags &= ~IP6_NEIGHBOR_FLAG_STATIC;
    }

  adj_nbr_walk_nh6 (sw_if_index,
		    &n->key.ip6_address, ip6_nd_mk_complete_walk, n);

check_customers:
  /* Customer(s) waiting for this address to be resolved? */
  p = mhash_get (&nm->pending_resolutions_by_address, a);
  if (p)
    {
      next_index = p[0];

      while (next_index != (u32) ~ 0)
	{
	  pr = pool_elt_at_index (nm->pending_resolutions, next_index);
	  vlib_process_signal_event (vm, pr->node_index,
				     pr->type_opaque, pr->data);
	  next_index = pr->next_index;
	  pool_put (nm->pending_resolutions, pr);
	}

      mhash_unset (&nm->pending_resolutions_by_address, (void *) a, 0);
    }

  /* Customer(s) requesting ND event for this address? */
  p = mhash_get (&nm->mac_changes_by_address, a);
  if (p)
    {
      next_index = p[0];

      while (next_index != (u32) ~ 0)
	{
	  int (*fp) (u32, u8 *, u32, ip6_address_t *);
	  int rv = 1;
	  mc = pool_elt_at_index (nm->mac_changes, next_index);
	  fp = mc->data_callback;

	  /* Call the user's data callback, return 1 to suppress dup events */
	  if (fp)
	    rv =
	      (*fp) (mc->data, (u8 *) link_layer_address, sw_if_index,
		     &ip6a_zero);
	  /*
	   * Signal the resolver process, as long as the user
	   * says they want to be notified
	   */
	  if (rv == 0)
	    vlib_process_signal_event (vm, mc->node_index,
				       mc->type_opaque, mc->data);
	  next_index = mc->next_index;
	}
    }

  return 0;
}

int
vnet_unset_ip6_ethernet_neighbor (vlib_main_t * vm,
				  u32 sw_if_index, const ip6_address_t * a)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_neighbor_key_t k;
  ip6_neighbor_t *n;
  uword *p;
  int rv = 0;

  if (vlib_get_thread_index ())
    {
      set_unset_ip6_neighbor_rpc (vm, sw_if_index, a, NULL,
				  0 /* unset */ , 0, 0);
      return 0;
    }

  k.sw_if_index = sw_if_index;
  k.ip6_address = a[0];
  k.pad = 0;

  p = mhash_get (&nm->neighbor_index_by_key, &k);
  if (p == 0)
    {
      rv = -1;
      goto out;
    }

  n = pool_elt_at_index (nm->neighbor_pool, p[0]);

  adj_nbr_walk_nh6 (sw_if_index,
		    &n->key.ip6_address, ip6_nd_mk_incomplete_walk, NULL);
  ip6_neighbor_adj_fib_remove
    (n, ip6_fib_table_get_index_for_sw_if_index (sw_if_index));

  mhash_unset (&nm->neighbor_index_by_key, &n->key, 0);
  pool_put (nm->neighbor_pool, n);

out:
  return rv;
}

static void ip6_neighbor_set_unset_rpc_callback
  (ip6_neighbor_set_unset_rpc_args_t * a)
{
  vlib_main_t *vm = vlib_get_main ();
  if (a->is_add)
    vnet_set_ip6_ethernet_neighbor (vm, a->sw_if_index, &a->addr,
				    a->link_layer_address, 6, a->is_static,
				    a->is_no_fib_entry);
  else
    vnet_unset_ip6_ethernet_neighbor (vm, a->sw_if_index, &a->addr);
}

static int
ip6_neighbor_sort (void *a1, void *a2)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_neighbor_t *n1 = a1, *n2 = a2;
  int cmp;
  cmp = vnet_sw_interface_compare (vnm, n1->key.sw_if_index,
				   n2->key.sw_if_index);
  if (!cmp)
    cmp = ip6_address_compare (&n1->key.ip6_address, &n2->key.ip6_address);
  return cmp;
}

ip6_neighbor_t *
ip6_neighbors_pool (void)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  return nm->neighbor_pool;
}

ip6_neighbor_t *
ip6_neighbors_entries (u32 sw_if_index)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_neighbor_t *n, *ns = 0;

  /* *INDENT-OFF* */
  pool_foreach (n, nm->neighbor_pool,
  ({
    if (sw_if_index != ~0 && n->key.sw_if_index != sw_if_index)
      continue;
    vec_add1 (ns, n[0]);
  }));
  /* *INDENT-ON* */

  if (ns)
    vec_sort_with_function (ns, ip6_neighbor_sort);
  return ns;
}

static clib_error_t *
show_ip6_neighbors (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_neighbor_t *n, *ns;
  clib_error_t *error = 0;
  u32 sw_if_index;

  /* Filter entries by interface if given. */
  sw_if_index = ~0;
  (void) unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index);

  ns = ip6_neighbors_entries (sw_if_index);
  if (ns)
    {
      vlib_cli_output (vm, "%U", format_ip6_neighbor_ip6_entry, vm, 0);
      vec_foreach (n, ns)
      {
	vlib_cli_output (vm, "%U", format_ip6_neighbor_ip6_entry, vm, n);
      }
      vec_free (ns);
    }

  return error;
}

/*?
 * This command is used to display the adjacent IPv6 hosts found via
 * neighbor discovery. Optionally, limit the output to the specified
 * interface.
 *
 * @cliexpar
 * Example of how to display the IPv6 neighbor adjacency table:
 * @cliexstart{show ip6 neighbors}
 *     Time           Address       Flags     Link layer                     Interface
 *      34.0910     ::a:1:1:0:7            02:fe:6a:07:39:6f                GigabitEthernet2/0/0
 *     173.2916     ::b:5:1:c:2            02:fe:50:62:3a:94                GigabitEthernet2/0/0
 *     886.6654     ::1:1:c:0:9       S    02:fe:e4:45:27:5b                GigabitEthernet3/0/0
 * @cliexend
 * Example of how to display the IPv6 neighbor adjacency table for given interface:
 * @cliexstart{show ip6 neighbors GigabitEthernet2/0/0}
 *     Time           Address       Flags     Link layer                     Interface
 *      34.0910     ::a:1:1:0:7            02:fe:6a:07:39:6f                GigabitEthernet2/0/0
 *     173.2916     ::b:5:1:c:2            02:fe:50:62:3a:94                GigabitEthernet2/0/0
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip6_neighbors_command, static) = {
  .path = "show ip6 neighbors",
  .function = show_ip6_neighbors,
  .short_help = "show ip6 neighbors [<interface>]",
};
/* *INDENT-ON* */

static clib_error_t *
set_ip6_neighbor (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_address_t addr;
  u8 mac_address[6];
  int addr_valid = 0;
  int is_del = 0;
  int is_static = 0;
  int is_no_fib_entry = 0;
  u32 sw_if_index;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      /* intfc, ip6-address, mac-address */
      if (unformat (input, "%U %U %U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index,
		    unformat_ip6_address, &addr,
		    unformat_ethernet_address, mac_address))
	addr_valid = 1;

      else if (unformat (input, "delete") || unformat (input, "del"))
	is_del = 1;
      else if (unformat (input, "static"))
	is_static = 1;
      else if (unformat (input, "no-fib-entry"))
	is_no_fib_entry = 1;
      else
	break;
    }

  if (!addr_valid)
    return clib_error_return (0, "Missing interface, ip6 or hw address");

  if (!is_del)
    vnet_set_ip6_ethernet_neighbor (vm, sw_if_index, &addr,
				    mac_address, sizeof (mac_address),
				    is_static, is_no_fib_entry);
  else
    vnet_unset_ip6_ethernet_neighbor (vm, sw_if_index, &addr);
  return 0;
}

/*?
 * This command is used to manually add an entry to the IPv6 neighbor
 * adjacency table. Optionally, the entry can be added as static. It is
 * also used to remove an entry from the table. Use the '<em>show ip6
 * neighbors</em>' command to display all learned and manually entered entries.
 *
 * @cliexpar
 * Example of how to add a static entry to the IPv6 neighbor adjacency table:
 * @cliexcmd{set ip6 neighbor GigabitEthernet2/0/0 ::1:1:c:0:9 02:fe:e4:45:27:5b static}
 * Example of how to delete an entry from the IPv6 neighbor adjacency table:
 * @cliexcmd{set ip6 neighbor del GigabitEthernet2/0/0 ::1:1:c:0:9 02:fe:e4:45:27:5b}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ip6_neighbor_command, static) =
{
  .path = "set ip6 neighbor",
  .function = set_ip6_neighbor,
  .short_help = "set ip6 neighbor [del] <interface> <ip6-address> <mac-address> [static]",
};
/* *INDENT-ON* */

typedef enum
{
  ICMP6_NEIGHBOR_SOLICITATION_NEXT_DROP,
  ICMP6_NEIGHBOR_SOLICITATION_NEXT_REPLY,
  ICMP6_NEIGHBOR_SOLICITATION_N_NEXT,
} icmp6_neighbor_solicitation_or_advertisement_next_t;

static_always_inline uword
icmp6_neighbor_solicitation_or_advertisement (vlib_main_t * vm,
					      vlib_node_runtime_t * node,
					      vlib_frame_t * frame,
					      uword is_solicitation)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_main_t *im = &ip6_main;
  uword n_packets = frame->n_vectors;
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next, next_index, n_advertisements_sent;
  icmp6_neighbor_discovery_option_type_t option_type;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_icmp_input_node.index);
  int bogus_length;

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (icmp6_input_trace_t));

  option_type =
    (is_solicitation
     ? ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address
     : ICMP6_NEIGHBOR_DISCOVERY_OPTION_target_link_layer_address);
  n_advertisements_sent = 0;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;
	  icmp6_neighbor_solicitation_or_advertisement_header_t *h0;
	  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *o0;
	  u32 bi0, options_len0, sw_if_index0, next0, error0;
	  u32 ip6_sadd_link_local, ip6_sadd_unspecified;
	  int is_rewrite0;
	  u32 ni0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  h0 = ip6_next_header (ip0);
	  options_len0 =
	    clib_net_to_host_u16 (ip0->payload_length) - sizeof (h0[0]);

	  error0 = ICMP6_ERROR_NONE;
	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];
	  ip6_sadd_link_local =
	    ip6_address_is_link_local_unicast (&ip0->src_address);
	  ip6_sadd_unspecified =
	    ip6_address_is_unspecified (&ip0->src_address);

	  /* Check that source address is unspecified, link-local or else on-link. */
	  if (!ip6_sadd_unspecified && !ip6_sadd_link_local)
	    {
	      u32 src_adj_index0 = ip6_src_lookup_for_packet (im, p0, ip0);

	      if (ADJ_INDEX_INVALID != src_adj_index0)
		{
		  ip_adjacency_t *adj0 = adj_get (src_adj_index0);

		  /* Allow all realistic-looking rewrite adjacencies to pass */
		  ni0 = adj0->lookup_next_index;
		  is_rewrite0 = (ni0 >= IP_LOOKUP_NEXT_ARP) &&
		    (ni0 < IP6_LOOKUP_N_NEXT);

		  error0 = ((adj0->rewrite_header.sw_if_index != sw_if_index0
			     || !is_rewrite0)
			    ?
			    ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_NOT_ON_LINK
			    : error0);
		}
	      else
		{
		  error0 =
		    ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_NOT_ON_LINK;
		}
	    }

	  o0 = (void *) (h0 + 1);
	  o0 = ((options_len0 == 8 && o0->header.type == option_type
		 && o0->header.n_data_u64s == 1) ? o0 : 0);

	  /* If src address unspecified or link local, donot learn neighbor MAC */
	  if (PREDICT_TRUE (error0 == ICMP6_ERROR_NONE && o0 != 0 &&
			    !ip6_sadd_unspecified))
	    {
	      vnet_set_ip6_ethernet_neighbor (vm, sw_if_index0,
					      is_solicitation ?
					      &ip0->src_address :
					      &h0->target_address,
					      o0->ethernet_address,
					      sizeof (o0->ethernet_address),
					      0, 0);
	    }

	  if (is_solicitation && error0 == ICMP6_ERROR_NONE)
	    {
	      /* Check that target address is local to this router. */
	      fib_node_index_t fei;
	      u32 fib_index;

	      fib_index =
		ip6_fib_table_get_index_for_sw_if_index (sw_if_index0);

	      if (~0 == fib_index)
		{
		  error0 = ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_UNKNOWN;
		}
	      else
		{
		  if (ip6_address_is_link_local_unicast (&h0->target_address))
		    {
		      fei = ip6_fib_table_lookup_exact_match
			(ip6_ll_fib_get (sw_if_index0),
			 &h0->target_address, 128);
		    }
		  else
		    {
		      fei = ip6_fib_table_lookup_exact_match (fib_index,
							      &h0->target_address,
							      128);
		    }

		  if (FIB_NODE_INDEX_INVALID == fei)
		    {
		      /* The target address is not in the FIB */
		      error0 =
			ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_UNKNOWN;
		    }
		  else
		    {
		      if (FIB_ENTRY_FLAG_LOCAL &
			  fib_entry_get_flags_for_source (fei,
							  FIB_SOURCE_INTERFACE))
			{
			  /* It's an address that belongs to one of our interfaces
			   * that's good. */
			}
		      else
			if (fib_entry_is_sourced
			    (fei, FIB_SOURCE_IP6_ND_PROXY) ||
			    fib_entry_is_sourced (fei, FIB_SOURCE_IP6_ND))
			{
			  /* The address was added by IPv6 Proxy ND config.
			   * We should only respond to these if the NS arrived on
			   * the link that has a matching covering prefix */
			}
		      else
			{
			  error0 =
			    ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_UNKNOWN;
			}
		    }
		}
	    }

	  if (is_solicitation)
	    next0 = (error0 != ICMP6_ERROR_NONE
		     ? ICMP6_NEIGHBOR_SOLICITATION_NEXT_DROP
		     : ICMP6_NEIGHBOR_SOLICITATION_NEXT_REPLY);
	  else
	    {
	      next0 = 0;
	      error0 = error0 == ICMP6_ERROR_NONE ?
		ICMP6_ERROR_NEIGHBOR_ADVERTISEMENTS_RX : error0;
	    }

	  if (is_solicitation && error0 == ICMP6_ERROR_NONE)
	    {
	      vnet_sw_interface_t *sw_if0;
	      ethernet_interface_t *eth_if0;
	      ethernet_header_t *eth0;

	      /* dst address is either source address or the all-nodes mcast addr */
	      if (!ip6_sadd_unspecified)
		ip0->dst_address = ip0->src_address;
	      else
		ip6_set_reserved_multicast_address (&ip0->dst_address,
						    IP6_MULTICAST_SCOPE_link_local,
						    IP6_MULTICAST_GROUP_ID_all_hosts);

	      ip0->src_address = h0->target_address;
	      ip0->hop_limit = 255;
	      h0->icmp.type = ICMP6_neighbor_advertisement;

	      sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index0);
	      ASSERT (sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
	      eth_if0 =
		ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);
	      if (eth_if0 && o0)
		{
		  clib_memcpy (o0->ethernet_address, eth_if0->address, 6);
		  o0->header.type =
		    ICMP6_NEIGHBOR_DISCOVERY_OPTION_target_link_layer_address;
		}

	      h0->advertisement_flags = clib_host_to_net_u32
		(ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_SOLICITED
		 | ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERRIDE);

	      h0->icmp.checksum = 0;
	      h0->icmp.checksum =
		ip6_tcp_udp_icmp_compute_checksum (vm, p0, ip0,
						   &bogus_length);
	      ASSERT (bogus_length == 0);

	      /* Reuse current MAC header, copy SMAC to DMAC and
	       * interface MAC to SMAC */
	      vlib_buffer_advance (p0, -ethernet_buffer_header_size (p0));
	      eth0 = vlib_buffer_get_current (p0);
	      clib_memcpy (eth0->dst_address, eth0->src_address, 6);
	      if (eth_if0)
		clib_memcpy (eth0->src_address, eth_if0->address, 6);

	      /* Setup input and output sw_if_index for packet */
	      ASSERT (vnet_buffer (p0)->sw_if_index[VLIB_RX] == sw_if_index0);
	      vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index0;
	      vnet_buffer (p0)->sw_if_index[VLIB_RX] =
		vnet_main.local_interface_sw_if_index;

	      n_advertisements_sent++;
	    }

	  p0->error = error_node->errors[error0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Account for advertisements sent. */
  vlib_error_count (vm, error_node->node_index,
		    ICMP6_ERROR_NEIGHBOR_ADVERTISEMENTS_TX,
		    n_advertisements_sent);

  return frame->n_vectors;
}

/* for "syslogging" - use elog for now */
#define foreach_log_level	     \
  _ (DEBUG, "DEBUG")                         \
  _ (INFO, "INFORMATION")	     \
  _ (NOTICE, "NOTICE")		     \
  _ (WARNING, "WARNING")	     \
  _ (ERR, "ERROR")				      \
  _ (CRIT, "CRITICAL")			      \
  _ (ALERT, "ALERT")			      \
  _ (EMERG,  "EMERGENCY")

typedef enum
{
#define _(f,s) LOG_##f,
  foreach_log_level
#undef _
} log_level_t;

static char *log_level_strings[] = {
#define _(f,s) s,
  foreach_log_level
#undef _
};

static int logmask = 1 << LOG_DEBUG;

static void
ip6_neighbor_syslog (vlib_main_t * vm, int priority, char *fmt, ...)
{
  /* just use elog for now */
  u8 *what;
  va_list va;

  if ((priority > LOG_EMERG) || !(logmask & (1 << priority)))
    return;

  va_start (va, fmt);
  if (fmt)
    {
      what = va_format (0, fmt, &va);

      ELOG_TYPE_DECLARE (e) =
      {
      .format = "ip6 nd:  (%s): %s",.format_args = "T4T4",};
      struct
      {
	u32 s[2];
      } *ed;
      ed = ELOG_DATA (&vm->elog_main, e);
      ed->s[0] = elog_string (&vm->elog_main, log_level_strings[priority]);
      ed->s[1] = elog_string (&vm->elog_main, (char *) what);
    }
  va_end (va);
  return;
}

clib_error_t *
call_ip6_neighbor_callbacks (void *data,
			     _vnet_ip6_neighbor_function_list_elt_t * elt)
{
  clib_error_t *error = 0;

  while (elt)
    {
      error = elt->fp (data);
      if (error)
	return error;
      elt = elt->next_ip6_neighbor_function;
    }

  return error;
}

/* ipv6 neighbor discovery - router advertisements */
typedef enum
{
  ICMP6_ROUTER_SOLICITATION_NEXT_DROP,
  ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_RW,
  ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_TX,
  ICMP6_ROUTER_SOLICITATION_N_NEXT,
} icmp6_router_solicitation_or_advertisement_next_t;

static_always_inline uword
icmp6_router_solicitation (vlib_main_t * vm,
			   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_main_t *im = &ip6_main;
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  uword n_packets = frame->n_vectors;
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next, next_index;
  u32 n_advertisements_sent = 0;
  int bogus_length;

  icmp6_neighbor_discovery_option_type_t option_type;

  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_icmp_input_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (icmp6_input_trace_t));

  /* source may append his LL address */
  option_type = ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;
	  ip6_radv_t *radv_info = 0;

	  icmp6_neighbor_discovery_header_t *h0;
	  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *o0;

	  u32 bi0, options_len0, sw_if_index0, next0, error0;
	  u32 is_solicitation = 1, is_dropped = 0;
	  u32 is_unspecified, is_link_local;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  h0 = ip6_next_header (ip0);
	  options_len0 =
	    clib_net_to_host_u16 (ip0->payload_length) - sizeof (h0[0]);
	  is_unspecified = ip6_address_is_unspecified (&ip0->src_address);
	  is_link_local =
	    ip6_address_is_link_local_unicast (&ip0->src_address);

	  error0 = ICMP6_ERROR_NONE;
	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];

	  /* check if solicitation  (not from nd_timer node) */
	  if (ip6_address_is_unspecified (&ip0->dst_address))
	    is_solicitation = 0;

	  /* Check that source address is unspecified, link-local or else on-link. */
	  if (!is_unspecified && !is_link_local)
	    {
	      u32 src_adj_index0 = ip6_src_lookup_for_packet (im, p0, ip0);

	      if (ADJ_INDEX_INVALID != src_adj_index0)
		{
		  ip_adjacency_t *adj0 = adj_get (src_adj_index0);

		  error0 = (adj0->rewrite_header.sw_if_index != sw_if_index0
			    ?
			    ICMP6_ERROR_ROUTER_SOLICITATION_SOURCE_NOT_ON_LINK
			    : error0);
		}
	      else
		{
		  error0 = ICMP6_ERROR_ROUTER_SOLICITATION_SOURCE_NOT_ON_LINK;
		}
	    }

	  /* check for source LL option and process */
	  o0 = (void *) (h0 + 1);
	  o0 = ((options_len0 == 8
		 && o0->header.type == option_type
		 && o0->header.n_data_u64s == 1) ? o0 : 0);

	  /* if src address unspecified IGNORE any options */
	  if (PREDICT_TRUE (error0 == ICMP6_ERROR_NONE && o0 != 0 &&
			    !is_unspecified && !is_link_local))
	    {
	      vnet_set_ip6_ethernet_neighbor (vm, sw_if_index0,
					      &ip0->src_address,
					      o0->ethernet_address,
					      sizeof (o0->ethernet_address),
					      0, 0);
	    }

	  /* default is to drop */
	  next0 = ICMP6_ROUTER_SOLICITATION_NEXT_DROP;

	  if (error0 == ICMP6_ERROR_NONE)
	    {
	      vnet_sw_interface_t *sw_if0;
	      ethernet_interface_t *eth_if0;
	      u32 adj_index0;

	      sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index0);
	      ASSERT (sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
	      eth_if0 =
		ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);

	      /* only support ethernet interface type for now */
	      error0 =
		(!eth_if0) ? ICMP6_ERROR_ROUTER_SOLICITATION_UNSUPPORTED_INTF
		: error0;

	      if (error0 == ICMP6_ERROR_NONE)
		{
		  u32 ri;

		  /* adjust the sizeof the buffer to just include the ipv6 header */
		  p0->current_length -=
		    (options_len0 +
		     sizeof (icmp6_neighbor_discovery_header_t));

		  /* look up the radv_t information for this interface */
		  if (vec_len (nm->if_radv_pool_index_by_sw_if_index) >
		      sw_if_index0)
		    {
		      ri =
			nm->if_radv_pool_index_by_sw_if_index[sw_if_index0];

		      if (ri != ~0)
			radv_info = pool_elt_at_index (nm->if_radv_pool, ri);
		    }

		  error0 =
		    ((!radv_info) ?
		     ICMP6_ERROR_ROUTER_SOLICITATION_RADV_NOT_CONFIG :
		     error0);

		  if (error0 == ICMP6_ERROR_NONE)
		    {
		      f64 now = vlib_time_now (vm);

		      /* for solicited adverts - need to rate limit */
		      if (is_solicitation)
			{
			  if (0 != radv_info->last_radv_time &&
			      (now - radv_info->last_radv_time) <
			      MIN_DELAY_BETWEEN_RAS)
			    is_dropped = 1;
			  else
			    radv_info->last_radv_time = now;
			}

		      /* send now  */
		      icmp6_router_advertisement_header_t rh;

		      rh.icmp.type = ICMP6_router_advertisement;
		      rh.icmp.code = 0;
		      rh.icmp.checksum = 0;

		      rh.current_hop_limit = radv_info->curr_hop_limit;
		      rh.router_lifetime_in_sec =
			clib_host_to_net_u16
			(radv_info->adv_router_lifetime_in_sec);
		      rh.
			time_in_msec_between_retransmitted_neighbor_solicitations
			=
			clib_host_to_net_u32 (radv_info->
					      adv_time_in_msec_between_retransmitted_neighbor_solicitations);
		      rh.neighbor_reachable_time_in_msec =
			clib_host_to_net_u32 (radv_info->
					      adv_neighbor_reachable_time_in_msec);

		      rh.flags =
			(radv_info->adv_managed_flag) ?
			ICMP6_ROUTER_DISCOVERY_FLAG_ADDRESS_CONFIG_VIA_DHCP :
			0;
		      rh.flags |=
			((radv_info->adv_other_flag) ?
			 ICMP6_ROUTER_DISCOVERY_FLAG_OTHER_CONFIG_VIA_DHCP :
			 0);


		      u16 payload_length =
			sizeof (icmp6_router_advertisement_header_t);

		      vlib_buffer_add_data (vm,
					    vlib_buffer_get_free_list_index
					    (p0), bi0, (void *) &rh,
					    sizeof
					    (icmp6_router_advertisement_header_t));

		      if (radv_info->adv_link_layer_address)
			{
			  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
			    h;

			  h.header.type =
			    ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address;
			  h.header.n_data_u64s = 1;

			  /* copy ll address */
			  clib_memcpy (&h.ethernet_address[0],
				       eth_if0->address, 6);

			  vlib_buffer_add_data (vm,
						vlib_buffer_get_free_list_index
						(p0), bi0, (void *) &h,
						sizeof
						(icmp6_neighbor_discovery_ethernet_link_layer_address_option_t));

			  payload_length +=
			    sizeof
			    (icmp6_neighbor_discovery_ethernet_link_layer_address_option_t);
			}

		      /* add MTU option */
		      if (radv_info->adv_link_mtu)
			{
			  icmp6_neighbor_discovery_mtu_option_t h;

			  h.unused = 0;
			  h.mtu =
			    clib_host_to_net_u32 (radv_info->adv_link_mtu);
			  h.header.type = ICMP6_NEIGHBOR_DISCOVERY_OPTION_mtu;
			  h.header.n_data_u64s = 1;

			  payload_length +=
			    sizeof (icmp6_neighbor_discovery_mtu_option_t);

			  vlib_buffer_add_data (vm,
						vlib_buffer_get_free_list_index
						(p0), bi0, (void *) &h,
						sizeof
						(icmp6_neighbor_discovery_mtu_option_t));
			}

		      /* add advertised prefix options  */
		      ip6_radv_prefix_t *pr_info;

		      /* *INDENT-OFF* */
		      pool_foreach (pr_info, radv_info->adv_prefixes_pool,
                      ({
                        if(pr_info->enabled &&
                           (!pr_info->decrement_lifetime_flag
                            || (pr_info->pref_lifetime_expires >0)))
                          {
                            /* advertise this prefix */
                            icmp6_neighbor_discovery_prefix_information_option_t h;

                            h.header.type = ICMP6_NEIGHBOR_DISCOVERY_OPTION_prefix_information;
                            h.header.n_data_u64s  =  (sizeof(icmp6_neighbor_discovery_prefix_information_option_t) >> 3);

                            h.dst_address_length  = pr_info->prefix_len;

                            h.flags  = (pr_info->adv_on_link_flag) ? ICMP6_NEIGHBOR_DISCOVERY_PREFIX_INFORMATION_FLAG_ON_LINK : 0;
                            h.flags |= (pr_info->adv_autonomous_flag) ?  ICMP6_NEIGHBOR_DISCOVERY_PREFIX_INFORMATION_AUTO :  0;

                            if(radv_info->cease_radv && pr_info->deprecated_prefix_flag)
                              {
                                h.valid_time = clib_host_to_net_u32(MIN_ADV_VALID_LIFETIME);
                                h.preferred_time  = 0;
                              }
                            else
                              {
                                if(pr_info->decrement_lifetime_flag)
                                  {
                                    pr_info->adv_valid_lifetime_in_secs = ((pr_info->valid_lifetime_expires  > now)) ?
                                      (pr_info->valid_lifetime_expires  - now) : 0;

                                    pr_info->adv_pref_lifetime_in_secs = ((pr_info->pref_lifetime_expires  > now)) ?
                                      (pr_info->pref_lifetime_expires  - now) : 0;
                                  }

                                h.valid_time = clib_host_to_net_u32(pr_info->adv_valid_lifetime_in_secs);
                                h.preferred_time  = clib_host_to_net_u32(pr_info->adv_pref_lifetime_in_secs) ;
                              }
                            h.unused  = 0;

                            clib_memcpy(&h.dst_address, &pr_info->prefix,  sizeof(ip6_address_t));

                            payload_length += sizeof( icmp6_neighbor_discovery_prefix_information_option_t);

                            vlib_buffer_add_data (vm,
					    vlib_buffer_get_free_list_index (p0),
                                                  bi0,
                                                  (void *)&h, sizeof(icmp6_neighbor_discovery_prefix_information_option_t));

                          }
                      }));
		      /* *INDENT-ON* */

		      /* add additional options before here */

		      /* finish building the router advertisement... */
		      if (!is_unspecified && radv_info->send_unicast)
			{
			  ip0->dst_address = ip0->src_address;
			}
		      else
			{
			  /* target address is all-nodes mcast addr */
			  ip6_set_reserved_multicast_address
			    (&ip0->dst_address,
			     IP6_MULTICAST_SCOPE_link_local,
			     IP6_MULTICAST_GROUP_ID_all_hosts);
			}

		      /* source address MUST be the link-local address */
		      ip0->src_address = radv_info->link_local_address;

		      ip0->hop_limit = 255;
		      ip0->payload_length =
			clib_host_to_net_u16 (payload_length);

		      icmp6_router_advertisement_header_t *rh0 =
			(icmp6_router_advertisement_header_t *) (ip0 + 1);
		      rh0->icmp.checksum =
			ip6_tcp_udp_icmp_compute_checksum (vm, p0, ip0,
							   &bogus_length);
		      ASSERT (bogus_length == 0);

		      /* setup output if and adjacency */
		      vnet_buffer (p0)->sw_if_index[VLIB_RX] =
			vnet_main.local_interface_sw_if_index;

		      if (is_solicitation)
			{
			  ethernet_header_t *eth0;
			  /* Reuse current MAC header, copy SMAC to DMAC and
			   * interface MAC to SMAC */
			  vlib_buffer_reset (p0);
			  eth0 = vlib_buffer_get_current (p0);
			  clib_memcpy (eth0->dst_address, eth0->src_address,
				       6);
			  clib_memcpy (eth0->src_address, eth_if0->address,
				       6);
			  next0 =
			    is_dropped ? next0 :
			    ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_TX;
			  vnet_buffer (p0)->sw_if_index[VLIB_TX] =
			    sw_if_index0;
			}
		      else
			{
			  adj_index0 = radv_info->mcast_adj_index;
			  if (adj_index0 == 0)
			    error0 = ICMP6_ERROR_DST_LOOKUP_MISS;
			  else
			    {
			      next0 =
				is_dropped ? next0 :
				ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_RW;
			      vnet_buffer (p0)->ip.adj_index[VLIB_TX] =
				adj_index0;
			    }
			}
		      p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

		      radv_info->n_solicitations_dropped += is_dropped;
		      radv_info->n_solicitations_rcvd += is_solicitation;

		      if ((error0 == ICMP6_ERROR_NONE) && !is_dropped)
			{
			  radv_info->n_advertisements_sent++;
			  n_advertisements_sent++;
			}
		    }
		}
	    }

	  p0->error = error_node->errors[error0];

	  if (error0 != ICMP6_ERROR_NONE)
	    vlib_error_count (vm, error_node->node_index, error0, 1);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);

	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Account for router advertisements sent. */
  vlib_error_count (vm, error_node->node_index,
		    ICMP6_ERROR_ROUTER_ADVERTISEMENTS_TX,
		    n_advertisements_sent);

  return frame->n_vectors;
}

 /* validate advertised info for consistancy (see RFC-4861 section 6.2.7) - log any inconsistencies, packet will always  be dropped  */
static_always_inline uword
icmp6_router_advertisement (vlib_main_t * vm,
			    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  uword n_packets = frame->n_vectors;
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next, next_index;
  u32 n_advertisements_rcvd = 0;

  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_icmp_input_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (icmp6_input_trace_t));

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;
	  ip6_radv_t *radv_info = 0;
	  icmp6_router_advertisement_header_t *h0;
	  u32 bi0, options_len0, sw_if_index0, next0, error0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  h0 = ip6_next_header (ip0);
	  options_len0 =
	    clib_net_to_host_u16 (ip0->payload_length) - sizeof (h0[0]);

	  error0 = ICMP6_ERROR_NONE;
	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];

	  /* Check that source address is link-local */
	  error0 = (!ip6_address_is_link_local_unicast (&ip0->src_address)) ?
	    ICMP6_ERROR_ROUTER_ADVERTISEMENT_SOURCE_NOT_LINK_LOCAL : error0;

	  /* default is to drop */
	  next0 = ICMP6_ROUTER_SOLICITATION_NEXT_DROP;

	  n_advertisements_rcvd++;

	  if (error0 == ICMP6_ERROR_NONE)
	    {
	      vnet_sw_interface_t *sw_if0;
	      ethernet_interface_t *eth_if0;

	      sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index0);
	      ASSERT (sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
	      eth_if0 =
		ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);

	      /* only support ethernet interface type for now */
	      error0 =
		(!eth_if0) ? ICMP6_ERROR_ROUTER_SOLICITATION_UNSUPPORTED_INTF
		: error0;

	      if (error0 == ICMP6_ERROR_NONE)
		{
		  u32 ri;

		  /* look up the radv_t information for this interface */
		  if (vec_len (nm->if_radv_pool_index_by_sw_if_index) >
		      sw_if_index0)
		    {
		      ri =
			nm->if_radv_pool_index_by_sw_if_index[sw_if_index0];

		      if (ri != ~0)
			radv_info = pool_elt_at_index (nm->if_radv_pool, ri);
		    }

		  error0 =
		    ((!radv_info) ?
		     ICMP6_ERROR_ROUTER_SOLICITATION_RADV_NOT_CONFIG :
		     error0);

		  if (error0 == ICMP6_ERROR_NONE)
		    {
		      radv_info->keep_sending_rs = 0;

		      ra_report_t r;

		      r.sw_if_index = sw_if_index0;
		      memcpy (r.router_address, &ip0->src_address, 16);
		      r.current_hop_limit = h0->current_hop_limit;
		      r.flags = h0->flags;
		      r.router_lifetime_in_sec =
			clib_net_to_host_u16 (h0->router_lifetime_in_sec);
		      r.neighbor_reachable_time_in_msec =
			clib_net_to_host_u32
			(h0->neighbor_reachable_time_in_msec);
		      r.time_in_msec_between_retransmitted_neighbor_solicitations = clib_net_to_host_u32 (h0->time_in_msec_between_retransmitted_neighbor_solicitations);
		      r.prefixes = 0;

		      /* validate advertised information */
		      if ((h0->current_hop_limit && radv_info->curr_hop_limit)
			  && (h0->current_hop_limit !=
			      radv_info->curr_hop_limit))
			{
			  ip6_neighbor_syslog (vm, LOG_WARNING,
					       "our AdvCurHopLimit on %U doesn't agree with %U",
					       format_vnet_sw_if_index_name,
					       vnm, sw_if_index0,
					       format_ip6_address,
					       &ip0->src_address);
			}

		      if ((h0->flags &
			   ICMP6_ROUTER_DISCOVERY_FLAG_ADDRESS_CONFIG_VIA_DHCP)
			  != radv_info->adv_managed_flag)
			{
			  ip6_neighbor_syslog (vm, LOG_WARNING,
					       "our AdvManagedFlag on %U doesn't agree with %U",
					       format_vnet_sw_if_index_name,
					       vnm, sw_if_index0,
					       format_ip6_address,
					       &ip0->src_address);
			}

		      if ((h0->flags &
			   ICMP6_ROUTER_DISCOVERY_FLAG_OTHER_CONFIG_VIA_DHCP)
			  != radv_info->adv_other_flag)
			{
			  ip6_neighbor_syslog (vm, LOG_WARNING,
					       "our AdvOtherConfigFlag on %U doesn't agree with %U",
					       format_vnet_sw_if_index_name,
					       vnm, sw_if_index0,
					       format_ip6_address,
					       &ip0->src_address);
			}

		      if ((h0->
			   time_in_msec_between_retransmitted_neighbor_solicitations
			   && radv_info->
			   adv_time_in_msec_between_retransmitted_neighbor_solicitations)
			  && (h0->
			      time_in_msec_between_retransmitted_neighbor_solicitations
			      !=
			      clib_host_to_net_u32 (radv_info->
						    adv_time_in_msec_between_retransmitted_neighbor_solicitations)))
			{
			  ip6_neighbor_syslog (vm, LOG_WARNING,
					       "our AdvRetransTimer on %U doesn't agree with %U",
					       format_vnet_sw_if_index_name,
					       vnm, sw_if_index0,
					       format_ip6_address,
					       &ip0->src_address);
			}

		      if ((h0->neighbor_reachable_time_in_msec &&
			   radv_info->adv_neighbor_reachable_time_in_msec) &&
			  (h0->neighbor_reachable_time_in_msec !=
			   clib_host_to_net_u32
			   (radv_info->adv_neighbor_reachable_time_in_msec)))
			{
			  ip6_neighbor_syslog (vm, LOG_WARNING,
					       "our AdvReachableTime on %U doesn't agree with %U",
					       format_vnet_sw_if_index_name,
					       vnm, sw_if_index0,
					       format_ip6_address,
					       &ip0->src_address);
			}

		      /* check for MTU or prefix options or .. */
		      u8 *opt_hdr = (u8 *) (h0 + 1);
		      while (options_len0 > 0)
			{
			  icmp6_neighbor_discovery_option_header_t *o0 =
			    (icmp6_neighbor_discovery_option_header_t *)
			    opt_hdr;
			  int opt_len = o0->n_data_u64s << 3;
			  icmp6_neighbor_discovery_option_type_t option_type =
			    o0->type;

			  if (options_len0 < 2)
			    {
			      ip6_neighbor_syslog (vm, LOG_ERR,
						   "malformed RA packet on %U from %U",
						   format_vnet_sw_if_index_name,
						   vnm, sw_if_index0,
						   format_ip6_address,
						   &ip0->src_address);
			      break;
			    }

			  if (opt_len == 0)
			    {
			      ip6_neighbor_syslog (vm, LOG_ERR,
						   " zero length option in RA on %U from %U",
						   format_vnet_sw_if_index_name,
						   vnm, sw_if_index0,
						   format_ip6_address,
						   &ip0->src_address);
			      break;
			    }
			  else if (opt_len > options_len0)
			    {
			      ip6_neighbor_syslog (vm, LOG_ERR,
						   "option length in RA packet  greater than total length on %U from %U",
						   format_vnet_sw_if_index_name,
						   vnm, sw_if_index0,
						   format_ip6_address,
						   &ip0->src_address);
			      break;
			    }

			  options_len0 -= opt_len;
			  opt_hdr += opt_len;

			  switch (option_type)
			    {
			    case ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address:
			      {
				icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
				  * h =
				  (icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
				   *) (o0);

				if (opt_len < sizeof (*h))
				  break;

				memcpy (r.slla, h->ethernet_address, 6);
			      }
			      break;

			    case ICMP6_NEIGHBOR_DISCOVERY_OPTION_mtu:
			      {
				icmp6_neighbor_discovery_mtu_option_t *h =
				  (icmp6_neighbor_discovery_mtu_option_t
				   *) (o0);

				if (opt_len < sizeof (*h))
				  break;

				r.mtu = clib_net_to_host_u32 (h->mtu);

				if ((h->mtu && radv_info->adv_link_mtu) &&
				    (h->mtu !=
				     clib_host_to_net_u32
				     (radv_info->adv_link_mtu)))
				  {
				    ip6_neighbor_syslog (vm, LOG_WARNING,
							 "our AdvLinkMTU on %U doesn't agree with %U",
							 format_vnet_sw_if_index_name,
							 vnm, sw_if_index0,
							 format_ip6_address,
							 &ip0->src_address);
				  }
			      }
			      break;

			    case ICMP6_NEIGHBOR_DISCOVERY_OPTION_prefix_information:
			      {
				icmp6_neighbor_discovery_prefix_information_option_t
				  * h =
				  (icmp6_neighbor_discovery_prefix_information_option_t
				   *) (o0);

				/* validate advertised prefix options  */
				ip6_radv_prefix_t *pr_info;
				u32 preferred, valid;

				if (opt_len < sizeof (*h))
				  break;

				vec_validate (r.prefixes,
					      vec_len (r.prefixes));
				ra_report_prefix_info_t *prefix =
				  vec_elt_at_index (r.prefixes,
						    vec_len (r.prefixes) - 1);

				preferred =
				  clib_net_to_host_u32 (h->preferred_time);
				valid = clib_net_to_host_u32 (h->valid_time);

				prefix->preferred_time = preferred;
				prefix->valid_time = valid;
				prefix->flags = h->flags & 0xc0;
				prefix->dst_address_length =
				  h->dst_address_length;
				prefix->dst_address = h->dst_address;

				/* look for matching prefix - if we our advertising it, it better be consistant */
				/* *INDENT-OFF* */
				pool_foreach (pr_info, radv_info->adv_prefixes_pool,
                                ({

                                  ip6_address_t mask;
                                  ip6_address_mask_from_width(&mask, pr_info->prefix_len);

                                  if(pr_info->enabled &&
                                     (pr_info->prefix_len == h->dst_address_length) &&
                                     ip6_address_is_equal_masked (&pr_info->prefix,  &h->dst_address, &mask))
                                    {
                                      /* found it */
                                      if(!pr_info->decrement_lifetime_flag &&
                                         valid != pr_info->adv_valid_lifetime_in_secs)
                                        {
                                          ip6_neighbor_syslog(vm,  LOG_WARNING,
                                                              "our ADV validlifetime on  %U for %U does not  agree with %U",
                                                              format_vnet_sw_if_index_name, vnm, sw_if_index0,format_ip6_address, &pr_info->prefix,
                                                              format_ip6_address, &h->dst_address);
                                        }
                                      if(!pr_info->decrement_lifetime_flag &&
                                         preferred != pr_info->adv_pref_lifetime_in_secs)
                                        {
                                          ip6_neighbor_syslog(vm,  LOG_WARNING,
                                                              "our ADV preferredlifetime on  %U for %U does not  agree with %U",
                                                              format_vnet_sw_if_index_name, vnm, sw_if_index0,format_ip6_address, &pr_info->prefix,
                                                              format_ip6_address, &h->dst_address);
                                        }
                                    }
                                  break;
                                }));
				/* *INDENT-ON* */
				break;
			      }
			    default:
			      /* skip this one */
			      break;
			    }
			}
		      ra_publish (&r);
		    }
		}
	    }

	  p0->error = error_node->errors[error0];

	  if (error0 != ICMP6_ERROR_NONE)
	    vlib_error_count (vm, error_node->node_index, error0, 1);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Account for router advertisements received. */
  vlib_error_count (vm, error_node->node_index,
		    ICMP6_ERROR_ROUTER_ADVERTISEMENTS_RX,
		    n_advertisements_rcvd);

  return frame->n_vectors;
}

static inline f64
random_f64_from_to (f64 from, f64 to)
{
  static u32 seed = 0;
  static u8 seed_set = 0;
  if (!seed_set)
    {
      seed = random_default_seed ();
      seed_set = 1;
    }
  return random_f64 (&seed) * (to - from) + from;
}

static inline u8
get_mac_address (u32 sw_if_index, u8 * address)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw_if = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (!hw_if->hw_address)
    return 1;
  clib_memcpy (address, hw_if->hw_address, 6);
  return 0;
}

static inline vlib_buffer_t *
create_buffer_for_rs (vlib_main_t * vm, ip6_radv_t * radv_info)
{
  u32 bi0;
  vlib_buffer_t *p0;
  vlib_buffer_free_list_t *fl;
  icmp6_router_solicitation_header_t *rh;
  u16 payload_length;
  int bogus_length;
  u32 sw_if_index;

  sw_if_index = radv_info->sw_if_index;

  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    {
      clib_warning ("buffer allocation failure");
      return 0;
    }

  p0 = vlib_get_buffer (vm, bi0);
  fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
  vlib_buffer_init_for_free_list (p0, fl);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (p0);
  p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  vnet_buffer (p0)->sw_if_index[VLIB_RX] = sw_if_index;
  vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index;

  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = radv_info->mcast_adj_index;

  rh = vlib_buffer_get_current (p0);
  p0->current_length = sizeof (*rh);

  rh->neighbor.icmp.type = ICMP6_router_solicitation;
  rh->neighbor.icmp.code = 0;
  rh->neighbor.icmp.checksum = 0;
  rh->neighbor.reserved_must_be_zero = 0;

  rh->link_layer_option.header.type =
    ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address;
  if (0 != get_mac_address (sw_if_index,
			    rh->link_layer_option.ethernet_address))
    {
      clib_warning ("interface with sw_if_index %u has no mac address",
		    sw_if_index);
      vlib_buffer_free (vm, &bi0, 1);
      return 0;
    }
  rh->link_layer_option.header.n_data_u64s = 1;

  payload_length = sizeof (rh->neighbor) + sizeof (u64);

  rh->ip.ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x6 << 28);
  rh->ip.payload_length = clib_host_to_net_u16 (payload_length);
  rh->ip.protocol = IP_PROTOCOL_ICMP6;
  rh->ip.hop_limit = 255;
  rh->ip.src_address = radv_info->link_local_address;
  /* set address ff02::2 */
  rh->ip.dst_address.as_u64[0] = clib_host_to_net_u64 (0xff02L << 48);
  rh->ip.dst_address.as_u64[1] = clib_host_to_net_u64 (2);

  rh->neighbor.icmp.checksum = ip6_tcp_udp_icmp_compute_checksum (vm, p0,
								  &rh->ip,
								  &bogus_length);

  return p0;
}

static inline void
stop_sending_rs (vlib_main_t * vm, ip6_radv_t * ra)
{
  u32 bi0;

  ra->keep_sending_rs = 0;
  if (ra->buffer)
    {
      bi0 = vlib_get_buffer_index (vm, ra->buffer);
      vlib_buffer_free (vm, &bi0, 1);
      ra->buffer = 0;
    }
}

static inline bool
check_send_rs (vlib_main_t * vm, ip6_radv_t * radv_info, f64 current_time,
	       f64 * due_time)
{
  vlib_buffer_t *p0;
  vlib_frame_t *f;
  u32 *to_next;
  u32 next_index;
  vlib_buffer_t *c0;
  u32 ci0;

  icmp6_send_router_solicitation_params_t *params;

  if (!radv_info->keep_sending_rs)
    return false;

  params = &radv_info->params;

  if (radv_info->due_time > current_time)
    {
      *due_time = radv_info->due_time;
      return true;
    }

  p0 = radv_info->buffer;

  next_index = ip6_rewrite_mcast_node.index;

  c0 = vlib_buffer_copy (vm, p0);
  ci0 = vlib_get_buffer_index (vm, c0);

  f = vlib_get_frame_to_node (vm, next_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = ci0;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, next_index, f);

  if (params->mrc != 0 && --radv_info->n_left == 0)
    stop_sending_rs (vm, radv_info);
  else
    {
      radv_info->sleep_interval =
	(2 + random_f64_from_to (-0.1, 0.1)) * radv_info->sleep_interval;
      if (radv_info->sleep_interval > params->mrt)
	radv_info->sleep_interval =
	  (1 + random_f64_from_to (-0.1, 0.1)) * params->mrt;

      radv_info->due_time = current_time + radv_info->sleep_interval;

      if (params->mrd != 0
	  && current_time > radv_info->start_time + params->mrd)
	stop_sending_rs (vm, radv_info);
      else
	*due_time = radv_info->due_time;
    }

  return radv_info->keep_sending_rs;
}

static uword
send_rs_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		 vlib_frame_t * f0)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_radv_t *radv_info;
  uword *event_data = 0;
  f64 sleep_time = 1e9;
  f64 current_time;
  f64 due_time;
  f64 dt = 0;

  while (true)
    {
      vlib_process_wait_for_event_or_clock (vm, sleep_time);
      vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      current_time = vlib_time_now (vm);
      do
	{
	  due_time = current_time + 1e9;
        /* *INDENT-OFF* */
        pool_foreach (radv_info, nm->if_radv_pool,
        ({
	    if (check_send_rs (vm, radv_info, current_time, &dt)
		&& (dt < due_time))
	      due_time = dt;
        }));
        /* *INDENT-ON* */
	  current_time = vlib_time_now (vm);
	}
      while (due_time < current_time);

      sleep_time = due_time - current_time;
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (send_rs_process_node) = {
    .function = send_rs_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "send-rs-process",
};
/* *INDENT-ON* */

void
icmp6_send_router_solicitation (vlib_main_t * vm, u32 sw_if_index, u8 stop,
				icmp6_send_router_solicitation_params_t *
				params)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  u32 rai;
  ip6_radv_t *ra = 0;

  ASSERT (~0 != sw_if_index);

  rai = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];
  ra = pool_elt_at_index (nm->if_radv_pool, rai);

  stop_sending_rs (vm, ra);

  if (!stop)
    {
      ra->keep_sending_rs = 1;
      ra->params = *params;
      ra->n_left = params->mrc;
      ra->start_time = vlib_time_now (vm);
      ra->sleep_interval = (1 + random_f64_from_to (-0.1, 0.1)) * params->irt;
      ra->due_time = 0;		/* send first packet ASAP */
      ra->buffer = create_buffer_for_rs (vm, ra);
      if (!ra->buffer)
	ra->keep_sending_rs = 0;
      else
	vlib_process_signal_event (vm, send_rs_process_node.index, 1, 0);
    }
}

/**
 * @brief Add a multicast Address to the advertised MLD set
 */
static void
ip6_neighbor_add_mld_prefix (ip6_radv_t * radv_info, ip6_address_t * addr)
{
  ip6_mldp_group_t *mcast_group_info;
  uword *p;

  /* lookup  mldp info for this interface */
  p = mhash_get (&radv_info->address_to_mldp_index, addr);
  mcast_group_info =
    p ? pool_elt_at_index (radv_info->mldp_group_pool, p[0]) : 0;

  /* add address */
  if (!mcast_group_info)
    {
      /* add */
      u32 mi;
      pool_get (radv_info->mldp_group_pool, mcast_group_info);

      mi = mcast_group_info - radv_info->mldp_group_pool;
      mhash_set (&radv_info->address_to_mldp_index, addr, mi,	/* old_value */
		 0);

      mcast_group_info->type = 4;
      mcast_group_info->mcast_source_address_pool = 0;
      mcast_group_info->num_sources = 0;
      clib_memcpy (&mcast_group_info->mcast_address, addr,
		   sizeof (ip6_address_t));
    }
}

/**
 * @brief Delete a multicast Address from the advertised MLD set
 */
static void
ip6_neighbor_del_mld_prefix (ip6_radv_t * radv_info, ip6_address_t * addr)
{
  ip6_mldp_group_t *mcast_group_info;
  uword *p;

  p = mhash_get (&radv_info->address_to_mldp_index, &addr);
  mcast_group_info =
    p ? pool_elt_at_index (radv_info->mldp_group_pool, p[0]) : 0;

  if (mcast_group_info)
    {
      mhash_unset (&radv_info->address_to_mldp_index, &addr,
		   /* old_value */ 0);
      pool_put (radv_info->mldp_group_pool, mcast_group_info);
    }
}

/**
 * @brief Add a multicast Address to the advertised MLD set
 */
static void
ip6_neighbor_add_mld_grp (ip6_radv_t * a,
			  ip6_multicast_address_scope_t scope,
			  ip6_multicast_link_local_group_id_t group)
{
  ip6_address_t addr;

  ip6_set_reserved_multicast_address (&addr, scope, group);

  ip6_neighbor_add_mld_prefix (a, &addr);
}

/**
 * @brief create and initialize router advertisement parameters with default
 * values for this intfc
 */
u32
ip6_neighbor_sw_interface_add_del (vnet_main_t * vnm,
				   u32 sw_if_index, u32 is_add)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_radv_t *a = 0;
  u32 ri = ~0;
  vnet_sw_interface_t *sw_if0;
  ethernet_interface_t *eth_if0 = 0;

  /* lookup radv container  - ethernet interfaces only */
  sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index);
  if (sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
    eth_if0 = ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);

  if (!eth_if0)
    return ri;

  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index,
			   ~0);
  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];

  if (ri != ~0)
    {
      a = pool_elt_at_index (nm->if_radv_pool, ri);

      if (!is_add)
	{
	  ip6_radv_prefix_t *p;
	  ip6_mldp_group_t *m;

	  /* release the lock on the interface's mcast adj */
	  adj_unlock (a->mcast_adj_index);

	  /* clean up prefix and MDP pools */
	  /* *INDENT-OFF* */
          pool_flush(p, a->adv_prefixes_pool,
          ({
	      mhash_unset (&a->address_to_prefix_index, &p->prefix, 0);
          }));
	  pool_flush (m, a->mldp_group_pool,
          ({
	      mhash_unset (&a->address_to_mldp_index, &m->mcast_address, 0);
          }));
	  /* *INDENT-ON* */

	  pool_free (a->mldp_group_pool);
	  pool_free (a->adv_prefixes_pool);

	  mhash_free (&a->address_to_prefix_index);
	  mhash_free (&a->address_to_mldp_index);

	  if (a->keep_sending_rs)
	    a->keep_sending_rs = 0;

	  pool_put (nm->if_radv_pool, a);
	  nm->if_radv_pool_index_by_sw_if_index[sw_if_index] = ~0;
	  ri = ~0;
	}
    }
  else
    {
      if (is_add)
	{
	  pool_get (nm->if_radv_pool, a);

	  ri = a - nm->if_radv_pool;
	  nm->if_radv_pool_index_by_sw_if_index[sw_if_index] = ri;

	  /* initialize default values (most of which are zero) */
	  clib_memset (a, 0, sizeof (a[0]));

	  a->sw_if_index = sw_if_index;
	  a->max_radv_interval = DEF_MAX_RADV_INTERVAL;
	  a->min_radv_interval = DEF_MIN_RADV_INTERVAL;
	  a->curr_hop_limit = DEF_CURR_HOP_LIMIT;
	  a->adv_router_lifetime_in_sec = DEF_DEF_RTR_LIFETIME;

	  /* send ll address source address option */
	  a->adv_link_layer_address = 1;

	  a->min_delay_between_radv = MIN_DELAY_BETWEEN_RAS;
	  a->max_delay_between_radv = MAX_DELAY_BETWEEN_RAS;
	  a->max_rtr_default_lifetime = MAX_DEF_RTR_LIFETIME;
	  a->seed = (u32) clib_cpu_time_now ();
	  (void) random_u32 (&a->seed);
	  a->randomizer = clib_cpu_time_now ();
	  (void) random_u64 (&a->randomizer);

	  a->initial_adverts_count = MAX_INITIAL_RTR_ADVERTISEMENTS;
	  a->initial_adverts_sent = a->initial_adverts_count - 1;
	  a->initial_adverts_interval = MAX_INITIAL_RTR_ADVERT_INTERVAL;

	  /* deafult is to send */
	  a->send_radv = 1;

	  /* fill in radv_info for this interface that will be needed later */
	  a->adv_link_mtu =
	    vnet_sw_interface_get_mtu (vnm, sw_if_index, VNET_MTU_IP6);

	  clib_memcpy (a->link_layer_address, eth_if0->address, 6);

	  /* fill in default link-local address  (this may be overridden) */
	  ip6_link_local_address_from_ethernet_address
	    (&a->link_local_address, eth_if0->address);

	  mhash_init (&a->address_to_prefix_index, sizeof (uword),
		      sizeof (ip6_address_t));
	  mhash_init (&a->address_to_mldp_index, sizeof (uword),
		      sizeof (ip6_address_t));

	  a->mcast_adj_index = adj_mcast_add_or_lock (FIB_PROTOCOL_IP6,
						      VNET_LINK_IP6,
						      sw_if_index);

	  a->keep_sending_rs = 0;

	  /* add multicast groups we will always be reporting  */
	  ip6_neighbor_add_mld_grp (a,
				    IP6_MULTICAST_SCOPE_link_local,
				    IP6_MULTICAST_GROUP_ID_all_hosts);
	  ip6_neighbor_add_mld_grp (a,
				    IP6_MULTICAST_SCOPE_link_local,
				    IP6_MULTICAST_GROUP_ID_all_routers);
	  ip6_neighbor_add_mld_grp (a,
				    IP6_MULTICAST_SCOPE_link_local,
				    IP6_MULTICAST_GROUP_ID_mldv2_routers);
	}
    }
  return ri;
}

/* send an mldpv2 report  */
static void
ip6_neighbor_send_mldpv2_report (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vnm->vlib_main;
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  vnet_sw_interface_t *sw_if0;
  ethernet_interface_t *eth_if0;
  u32 ri;
  int bogus_length;

  ip6_radv_t *radv_info;
  u16 payload_length;
  vlib_buffer_t *b0;
  ip6_header_t *ip0;
  u32 *to_next;
  vlib_frame_t *f;
  u32 bo0;
  u32 n_to_alloc = 1;
  u32 n_allocated;

  icmp6_multicast_listener_report_header_t *rh0;
  icmp6_multicast_listener_report_packet_t *rp0;

  sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index);
  ASSERT (sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
  eth_if0 = ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);

  if (!eth_if0 || !vnet_sw_interface_is_admin_up (vnm, sw_if_index))
    return;

  /* look up the radv_t  information for this interface */
  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index,
			   ~0);

  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];

  if (ri == ~0)
    return;

  /* send report now - build a mldpv2 report packet  */
  n_allocated = vlib_buffer_alloc (vm, &bo0, n_to_alloc);
  if (PREDICT_FALSE (n_allocated == 0))
    {
      clib_warning ("buffer allocation failure");
      return;
    }

  b0 = vlib_get_buffer (vm, bo0);

  /* adjust the sizeof the buffer to just include the ipv6 header */
  b0->current_length = sizeof (icmp6_multicast_listener_report_packet_t);

  payload_length = sizeof (icmp6_multicast_listener_report_header_t);

  b0->error = ICMP6_ERROR_NONE;

  rp0 = vlib_buffer_get_current (b0);
  ip0 = (ip6_header_t *) & rp0->ip;
  rh0 = (icmp6_multicast_listener_report_header_t *) & rp0->report_hdr;

  clib_memset (rp0, 0x0, sizeof (icmp6_multicast_listener_report_packet_t));

  ip0->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x6 << 28);

  ip0->protocol = IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS;
  /* for DEBUG - vnet driver won't seem to emit router alerts */
  /* ip0->protocol = IP_PROTOCOL_ICMP6; */
  ip0->hop_limit = 1;

  rh0->icmp.type = ICMP6_multicast_listener_report_v2;

  /* source address MUST be the link-local address */
  radv_info = pool_elt_at_index (nm->if_radv_pool, ri);
  ip0->src_address = radv_info->link_local_address;

  /* destination is all mldpv2 routers */
  ip6_set_reserved_multicast_address (&ip0->dst_address,
				      IP6_MULTICAST_SCOPE_link_local,
				      IP6_MULTICAST_GROUP_ID_mldv2_routers);

  /* add reports here */
  ip6_mldp_group_t *m;
  int num_addr_records = 0;
  icmp6_multicast_address_record_t rr;

  /* fill in the hop-by-hop extension header (router alert) info */
  rh0->ext_hdr.next_hdr = IP_PROTOCOL_ICMP6;
  rh0->ext_hdr.n_data_u64s = 0;

  rh0->alert.type = IP6_MLDP_ALERT_TYPE;
  rh0->alert.len = 2;
  rh0->alert.value = 0;

  rh0->pad.type = 1;
  rh0->pad.len = 0;

  rh0->icmp.checksum = 0;

  /* *INDENT-OFF* */
  pool_foreach (m, radv_info->mldp_group_pool,
  ({
    rr.type = m->type;
    rr.aux_data_len_u32s = 0;
    rr.num_sources = clib_host_to_net_u16 (m->num_sources);
    clib_memcpy(&rr.mcast_addr, &m->mcast_address, sizeof(ip6_address_t));

    num_addr_records++;

    vlib_buffer_add_data
      (vm, vlib_buffer_get_free_list_index (b0), bo0,
       (void *)&rr, sizeof(icmp6_multicast_address_record_t));

    payload_length += sizeof( icmp6_multicast_address_record_t);
  }));
  /* *INDENT-ON* */

  rh0->rsvd = 0;
  rh0->num_addr_records = clib_host_to_net_u16 (num_addr_records);

  /* update lengths */
  ip0->payload_length = clib_host_to_net_u16 (payload_length);

  rh0->icmp.checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip0,
							  &bogus_length);
  ASSERT (bogus_length == 0);

  /*
   * OK to override w/ no regard for actual FIB, because
   * ip6-rewrite only looks at the adjacency.
   */
  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
    vnet_main.local_interface_sw_if_index;

  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = radv_info->mcast_adj_index;
  b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "ip6-rewrite-mcast");

  f = vlib_get_frame_to_node (vm, node->index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bo0;
  f->n_vectors = 1;

  vlib_put_frame_to_node (vm, node->index, f);
  return;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_icmp_router_solicitation_node,static) =
{
  .function = icmp6_router_solicitation,
  .name = "icmp6-router-solicitation",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_next_nodes = ICMP6_ROUTER_SOLICITATION_N_NEXT,
  .next_nodes = {
    [ICMP6_ROUTER_SOLICITATION_NEXT_DROP] = "ip6-drop",
    [ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_RW] = "ip6-rewrite-mcast",
    [ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_TX] = "interface-output",
  },
};
/* *INDENT-ON* */

/* send a RA or update the timer info etc.. */
static uword
ip6_neighbor_process_timer_event (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_radv_t *radv_info;
  vlib_frame_t *f = 0;
  u32 n_this_frame = 0;
  u32 n_left_to_next = 0;
  u32 *to_next = 0;
  u32 bo0;
  icmp6_router_solicitation_header_t *h0;
  vlib_buffer_t *b0;
  f64 now = vlib_time_now (vm);

  /* Interface ip6 radv info list */
  /* *INDENT-OFF* */
  pool_foreach (radv_info, nm->if_radv_pool,
  ({
    if( !vnet_sw_interface_is_admin_up (vnm, radv_info->sw_if_index))
      {
        radv_info->initial_adverts_sent = radv_info->initial_adverts_count-1;
        radv_info->next_multicast_time = now;
        radv_info->last_multicast_time = now;
        radv_info->last_radv_time = 0;
        radv_info->all_routers_mcast = 0;
        continue;
      }

    /* Make sure that we've joined the all-routers multicast group */
    if(!radv_info->all_routers_mcast)
      {
        /* send MDLP_REPORT_EVENT message */
        ip6_neighbor_send_mldpv2_report(radv_info->sw_if_index);
        radv_info->all_routers_mcast = 1;
      }

    /* is it time to send a multicast  RA on this interface? */
    if(radv_info->send_radv && (now >=  radv_info->next_multicast_time))
      {
        u32 n_to_alloc = 1;
        u32 n_allocated;

        f64 rfn = (radv_info->max_radv_interval - radv_info->min_radv_interval) *
          random_f64 (&radv_info->seed) + radv_info->min_radv_interval;

        /* multicast send - compute next multicast send time */
        if( radv_info->initial_adverts_sent > 0)
          {
            radv_info->initial_adverts_sent--;
            if(rfn > radv_info-> initial_adverts_interval)
              rfn =  radv_info-> initial_adverts_interval;

            /* check to see if we are ceasing to send */
            if( radv_info->initial_adverts_sent  == 0)
              if(radv_info->cease_radv)
                radv_info->send_radv = 0;
          }

        radv_info->next_multicast_time =  rfn + now;
        radv_info->last_multicast_time = now;

        /* send advert now - build a "solicted" router advert with unspecified source address */
        n_allocated = vlib_buffer_alloc (vm, &bo0, n_to_alloc);

        if (PREDICT_FALSE(n_allocated == 0))
          {
            clib_warning ("buffer allocation failure");
            continue;
          }
        b0 = vlib_get_buffer (vm, bo0);
        b0->current_length = sizeof( icmp6_router_solicitation_header_t);
        b0->error = ICMP6_ERROR_NONE;
        vnet_buffer (b0)->sw_if_index[VLIB_RX] = radv_info->sw_if_index;

        h0 =  vlib_buffer_get_current (b0);

        clib_memset (h0, 0, sizeof (icmp6_router_solicitation_header_t));

        h0->ip.ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (0x6 << 28);
        h0->ip.payload_length = clib_host_to_net_u16 (sizeof (icmp6_router_solicitation_header_t)
                                                      - STRUCT_OFFSET_OF (icmp6_router_solicitation_header_t, neighbor));
        h0->ip.protocol = IP_PROTOCOL_ICMP6;
        h0->ip.hop_limit = 255;

        /* set src/dst address as "unspecified" this marks this packet as internally generated rather than recieved */
        h0->ip.src_address.as_u64[0] = 0;
        h0->ip.src_address.as_u64[1] = 0;

        h0->ip.dst_address.as_u64[0] = 0;
        h0->ip.dst_address.as_u64[1] = 0;

        h0->neighbor.icmp.type = ICMP6_router_solicitation;

        if (PREDICT_FALSE(f == 0))
          {
            f = vlib_get_frame_to_node (vm, ip6_icmp_router_solicitation_node.index);
            to_next = vlib_frame_vector_args (f);
            n_left_to_next = VLIB_FRAME_SIZE;
            n_this_frame = 0;
          }

        n_this_frame++;
        n_left_to_next--;
        to_next[0] = bo0;
        to_next += 1;

        if (PREDICT_FALSE(n_left_to_next == 0))
          {
            f->n_vectors = n_this_frame;
            vlib_put_frame_to_node (vm, ip6_icmp_router_solicitation_node.index, f);
            f = 0;
          }
      }
  }));
  /* *INDENT-ON* */

  if (f)
    {
      ASSERT (n_this_frame);
      f->n_vectors = n_this_frame;
      vlib_put_frame_to_node (vm, ip6_icmp_router_solicitation_node.index, f);
    }
  return 0;
}

static uword
ip6_icmp_neighbor_discovery_event_process (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * frame)
{
  uword event_type;
  ip6_icmp_neighbor_discovery_event_data_t *event_data;

  /* init code here */

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 1. /* seconds */ );

      event_data = vlib_process_get_event_data (vm, &event_type);

      if (!event_data)
	{
	  /* No events found: timer expired. */
	  /* process interface list and send RAs as appropriate, update timer info */
	  ip6_neighbor_process_timer_event (vm, node, frame);
	}
      else
	{
	  switch (event_type)
	    {

	    case ICMP6_ND_EVENT_INIT:
	      break;

	    case ~0:
	      break;

	    default:
	      ASSERT (0);
	    }

	  if (event_data)
	    _vec_len (event_data) = 0;
	}
    }
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_icmp_router_advertisement_node,static) =
{
  .function = icmp6_router_advertisement,
  .name = "icmp6-router-advertisement",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip6-drop",
  },
};
/* *INDENT-ON* */

vlib_node_registration_t ip6_icmp_neighbor_discovery_event_node = {

  .function = ip6_icmp_neighbor_discovery_event_process,
  .name = "ip6-icmp-neighbor-discovery-event-process",
  .type = VLIB_NODE_TYPE_PROCESS,
};

static uword
icmp6_neighbor_solicitation (vlib_main_t * vm,
			     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return icmp6_neighbor_solicitation_or_advertisement (vm, node, frame,
						       /* is_solicitation */
						       1);
}

static uword
icmp6_neighbor_advertisement (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
{
  return icmp6_neighbor_solicitation_or_advertisement (vm, node, frame,
						       /* is_solicitation */
						       0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_icmp_neighbor_solicitation_node,static) =
{
  .function = icmp6_neighbor_solicitation,
  .name = "icmp6-neighbor-solicitation",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_next_nodes = ICMP6_NEIGHBOR_SOLICITATION_N_NEXT,
  .next_nodes = {
    [ICMP6_NEIGHBOR_SOLICITATION_NEXT_DROP] = "ip6-drop",
    [ICMP6_NEIGHBOR_SOLICITATION_NEXT_REPLY] = "interface-output",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_icmp_neighbor_advertisement_node,static) =
{
  .function = icmp6_neighbor_advertisement,
  .name = "icmp6-neighbor-advertisement",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip6-drop",
  },
};
/* *INDENT-ON* */

typedef enum
{
  IP6_DISCOVER_NEIGHBOR_NEXT_DROP,
  IP6_DISCOVER_NEIGHBOR_NEXT_REPLY_TX,
  IP6_DISCOVER_NEIGHBOR_N_NEXT,
} ip6_discover_neighbor_next_t;

typedef enum
{
  IP6_DISCOVER_NEIGHBOR_ERROR_DROP,
  IP6_DISCOVER_NEIGHBOR_ERROR_REQUEST_SENT,
  IP6_DISCOVER_NEIGHBOR_ERROR_NO_SOURCE_ADDRESS,
} ip6_discover_neighbor_error_t;

static uword
ip6_discover_neighbor_inline (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * frame, int is_glean)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_main_t *im = &ip6_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  u32 *from, *to_next_drop;
  uword n_left_from, n_left_to_next_drop;
  u64 seed;
  u32 thread_index = vm->thread_index;
  int bogus_length;
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip6_forward_next_trace (vm, node, frame, VLIB_TX);

  seed = throttle_seed (&im->nd_throttle, thread_index, vlib_time_now (vm));

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, IP6_DISCOVER_NEIGHBOR_NEXT_DROP,
			   to_next_drop, n_left_to_next_drop);

      while (n_left_from > 0 && n_left_to_next_drop > 0)
	{
	  u32 pi0, adj_index0, sw_if_index0, drop0, r0, next0;
	  vnet_hw_interface_t *hw_if0;
	  ip6_radv_t *radv_info;
	  ip_adjacency_t *adj0;
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;

	  pi0 = from[0];

	  p0 = vlib_get_buffer (vm, pi0);

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];

	  ip0 = vlib_buffer_get_current (p0);

	  adj0 = adj_get (adj_index0);

	  if (!is_glean)
	    {
	      ip0->dst_address.as_u64[0] =
		adj0->sub_type.nbr.next_hop.ip6.as_u64[0];
	      ip0->dst_address.as_u64[1] =
		adj0->sub_type.nbr.next_hop.ip6.as_u64[1];
	    }

	  sw_if_index0 = adj0->rewrite_header.sw_if_index;
	  vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index0;

	  /* combine the address and interface for a hash */
	  r0 = ip6_address_hash_to_u64 (&ip0->dst_address) ^ sw_if_index0;

	  drop0 = throttle_check (&im->nd_throttle, thread_index, r0, seed);

	  from += 1;
	  n_left_from -= 1;
	  to_next_drop[0] = pi0;
	  to_next_drop += 1;
	  n_left_to_next_drop -= 1;

	  hw_if0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);

	  /* If the interface is link-down, drop the pkt */
	  if (!(hw_if0->flags & VNET_HW_INTERFACE_FLAG_LINK_UP))
	    drop0 = 1;

	  if (vec_len (nm->if_radv_pool_index_by_sw_if_index) > sw_if_index0)
	    {
	      u32 ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index0];

	      if (ri != ~0)
		radv_info = pool_elt_at_index (nm->if_radv_pool, ri);
	      else
		drop0 = 1;
	    }
	  else
	    drop0 = 1;

	  /*
	   * the adj has been updated to a rewrite but the node the DPO that got
	   * us here hasn't - yet. no big deal. we'll drop while we wait.
	   */
	  if (IP_LOOKUP_NEXT_REWRITE == adj0->lookup_next_index)
	    drop0 = 1;

	  p0->error =
	    node->errors[drop0 ? IP6_DISCOVER_NEIGHBOR_ERROR_DROP
			 : IP6_DISCOVER_NEIGHBOR_ERROR_REQUEST_SENT];

	  if (drop0)
	    continue;

	  {
	    u32 bi0 = 0;
	    icmp6_neighbor_solicitation_header_t *h0;
	    vlib_buffer_t *b0;

	    h0 = vlib_packet_template_get_packet
	      (vm, &im->discover_neighbor_packet_template, &bi0);
	    if (!h0)
	      continue;

	    /*
	     * Build ethernet header.
	     * Choose source address based on destination lookup
	     * adjacency.
	     */
	    if (!ip6_src_address_for_packet (lm,
					     sw_if_index0,
					     &ip0->dst_address,
					     &h0->ip.src_address))
	      {
		/* There is no address on the interface */
		p0->error =
		  node->errors[IP6_DISCOVER_NEIGHBOR_ERROR_NO_SOURCE_ADDRESS];
		vlib_buffer_free (vm, &bi0, 1);
		continue;
	      }

	    /*
	     * Destination address is a solicited node multicast address.
	     * We need to fill in
	     * the low 24 bits with low 24 bits of target's address.
	     */
	    h0->ip.dst_address.as_u8[13] = ip0->dst_address.as_u8[13];
	    h0->ip.dst_address.as_u8[14] = ip0->dst_address.as_u8[14];
	    h0->ip.dst_address.as_u8[15] = ip0->dst_address.as_u8[15];

	    h0->neighbor.target_address = ip0->dst_address;

	    clib_memcpy (h0->link_layer_option.ethernet_address,
			 hw_if0->hw_address, vec_len (hw_if0->hw_address));

	    /* $$$$ appears we need this; why is the checksum non-zero? */
	    h0->neighbor.icmp.checksum = 0;
	    h0->neighbor.icmp.checksum =
	      ip6_tcp_udp_icmp_compute_checksum (vm, 0, &h0->ip,
						 &bogus_length);

	    ASSERT (bogus_length == 0);

	    vlib_buffer_copy_trace_flag (vm, p0, bi0);
	    b0 = vlib_get_buffer (vm, bi0);
	    vnet_buffer (b0)->sw_if_index[VLIB_TX]
	      = vnet_buffer (p0)->sw_if_index[VLIB_TX];

	    vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
	      radv_info->mcast_adj_index;

	    b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	    next0 = IP6_DISCOVER_NEIGHBOR_NEXT_REPLY_TX;

	    vlib_set_next_frame_buffer (vm, node, next0, bi0);
	  }
	}

      vlib_put_next_frame (vm, node, IP6_DISCOVER_NEIGHBOR_NEXT_DROP,
			   n_left_to_next_drop);
    }

  return frame->n_vectors;
}

static uword
ip6_discover_neighbor (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (ip6_discover_neighbor_inline (vm, node, frame, 0));
}

static uword
ip6_glean (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (ip6_discover_neighbor_inline (vm, node, frame, 1));
}

static char *ip6_discover_neighbor_error_strings[] = {
  [IP6_DISCOVER_NEIGHBOR_ERROR_DROP] = "address overflow drops",
  [IP6_DISCOVER_NEIGHBOR_ERROR_REQUEST_SENT] = "neighbor solicitations sent",
  [IP6_DISCOVER_NEIGHBOR_ERROR_NO_SOURCE_ADDRESS]
    = "no source address for ND solicitation",
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_glean_node) =
{
  .function = ip6_glean,
  .name = "ip6-glean",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_forward_next_trace,
  .n_errors = ARRAY_LEN (ip6_discover_neighbor_error_strings),
  .error_strings = ip6_discover_neighbor_error_strings,
  .n_next_nodes = IP6_DISCOVER_NEIGHBOR_N_NEXT,
  .next_nodes =
  {
    [IP6_DISCOVER_NEIGHBOR_NEXT_DROP] = "ip6-drop",
    [IP6_DISCOVER_NEIGHBOR_NEXT_REPLY_TX] = "ip6-rewrite-mcast",
  },
};
VLIB_REGISTER_NODE (ip6_discover_neighbor_node) =
{
  .function = ip6_discover_neighbor,
  .name = "ip6-discover-neighbor",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_forward_next_trace,
  .n_errors = ARRAY_LEN (ip6_discover_neighbor_error_strings),
  .error_strings = ip6_discover_neighbor_error_strings,
  .n_next_nodes = IP6_DISCOVER_NEIGHBOR_N_NEXT,
  .next_nodes =
  {
    [IP6_DISCOVER_NEIGHBOR_NEXT_DROP] = "ip6-drop",
    [IP6_DISCOVER_NEIGHBOR_NEXT_REPLY_TX] = "ip6-rewrite-mcast",
  },
};
/* *INDENT-ON* */

/* API support functions */
int
ip6_neighbor_ra_config (vlib_main_t * vm, u32 sw_if_index,
			u8 suppress, u8 managed, u8 other,
			u8 ll_option, u8 send_unicast, u8 cease,
			u8 use_lifetime, u32 lifetime,
			u32 initial_count, u32 initial_interval,
			u32 max_interval, u32 min_interval, u8 is_no)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  int error;
  u32 ri;

  /* look up the radv_t  information for this interface */
  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index,
			   ~0);
  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];
  error = (ri != ~0) ? 0 : VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (!error)
    {

      ip6_radv_t *radv_info;
      radv_info = pool_elt_at_index (nm->if_radv_pool, ri);

      if ((max_interval != 0) && (min_interval == 0))
	min_interval = .75 * max_interval;

      max_interval =
	(max_interval !=
	 0) ? ((is_no) ? DEF_MAX_RADV_INTERVAL : max_interval) :
	radv_info->max_radv_interval;
      min_interval =
	(min_interval !=
	 0) ? ((is_no) ? DEF_MIN_RADV_INTERVAL : min_interval) :
	radv_info->min_radv_interval;
      lifetime =
	(use_lifetime !=
	 0) ? ((is_no) ? DEF_DEF_RTR_LIFETIME : lifetime) :
	radv_info->adv_router_lifetime_in_sec;

      if (lifetime)
	{
	  if (lifetime > MAX_DEF_RTR_LIFETIME)
	    lifetime = MAX_DEF_RTR_LIFETIME;

	  if (lifetime <= max_interval)
	    return VNET_API_ERROR_INVALID_VALUE;
	}

      if (min_interval != 0)
	{
	  if ((min_interval > .75 * max_interval) || (min_interval < 3))
	    return VNET_API_ERROR_INVALID_VALUE;
	}

      if ((initial_count > MAX_INITIAL_RTR_ADVERTISEMENTS) ||
	  (initial_interval > MAX_INITIAL_RTR_ADVERT_INTERVAL))
	return VNET_API_ERROR_INVALID_VALUE;

      /*
         if "flag" is set and is_no is true then restore default value else set value corresponding to "flag"
         if "flag" is clear  don't change corresponding value
       */
      radv_info->send_radv =
	(suppress != 0) ? ((is_no != 0) ? 1 : 0) : radv_info->send_radv;
      radv_info->adv_managed_flag =
	(managed != 0) ? ((is_no) ? 0 : 1) : radv_info->adv_managed_flag;
      radv_info->adv_other_flag =
	(other != 0) ? ((is_no) ? 0 : 1) : radv_info->adv_other_flag;
      radv_info->adv_link_layer_address =
	(ll_option !=
	 0) ? ((is_no) ? 1 : 0) : radv_info->adv_link_layer_address;
      radv_info->send_unicast =
	(send_unicast != 0) ? ((is_no) ? 0 : 1) : radv_info->send_unicast;
      radv_info->cease_radv =
	(cease != 0) ? ((is_no) ? 0 : 1) : radv_info->cease_radv;

      radv_info->min_radv_interval = min_interval;
      radv_info->max_radv_interval = max_interval;
      radv_info->adv_router_lifetime_in_sec = lifetime;

      radv_info->initial_adverts_count =
	(initial_count !=
	 0) ? ((is_no) ? MAX_INITIAL_RTR_ADVERTISEMENTS : initial_count) :
	radv_info->initial_adverts_count;
      radv_info->initial_adverts_interval =
	(initial_interval !=
	 0) ? ((is_no) ? MAX_INITIAL_RTR_ADVERT_INTERVAL : initial_interval) :
	radv_info->initial_adverts_interval;

      /* restart */
      if ((cease != 0) && (is_no))
	radv_info->send_radv = 1;

      radv_info->initial_adverts_sent = radv_info->initial_adverts_count - 1;
      radv_info->next_multicast_time = vlib_time_now (vm);
      radv_info->last_multicast_time = vlib_time_now (vm);
      radv_info->last_radv_time = 0;
    }
  return (error);
}

int
ip6_neighbor_ra_prefix (vlib_main_t * vm, u32 sw_if_index,
			ip6_address_t * prefix_addr, u8 prefix_len,
			u8 use_default, u32 val_lifetime, u32 pref_lifetime,
			u8 no_advertise, u8 off_link, u8 no_autoconfig,
			u8 no_onlink, u8 is_no)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  int error;

  u32 ri;

  /* look up the radv_t  information for this interface */
  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index,
			   ~0);

  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];

  error = (ri != ~0) ? 0 : VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (!error)
    {
      f64 now = vlib_time_now (vm);
      ip6_radv_t *radv_info;
      radv_info = pool_elt_at_index (nm->if_radv_pool, ri);

      /* prefix info add, delete or update */
      ip6_radv_prefix_t *prefix;

      /* lookup  prefix info for this  address on this interface */
      uword *p = mhash_get (&radv_info->address_to_prefix_index, prefix_addr);

      prefix = p ? pool_elt_at_index (radv_info->adv_prefixes_pool, p[0]) : 0;

      if (is_no)
	{
	  /* delete */
	  if (!prefix)
	    return VNET_API_ERROR_INVALID_VALUE;	/* invalid prefix */

	  if (prefix->prefix_len != prefix_len)
	    return VNET_API_ERROR_INVALID_VALUE_2;

	  /* FIXME - Should the DP do this or the CP ? */
	  /* do specific delete processing here before returning */
	  /* try to remove from routing table */

	  mhash_unset (&radv_info->address_to_prefix_index, prefix_addr,
		       /* old_value */ 0);
	  pool_put (radv_info->adv_prefixes_pool, prefix);

	  radv_info->initial_adverts_sent =
	    radv_info->initial_adverts_count - 1;
	  radv_info->next_multicast_time = vlib_time_now (vm);
	  radv_info->last_multicast_time = vlib_time_now (vm);
	  radv_info->last_radv_time = 0;
	  return (error);
	}

      /* adding or changing */
      if (!prefix)
	{
	  /* add */
	  u32 pi;
	  pool_get (radv_info->adv_prefixes_pool, prefix);
	  pi = prefix - radv_info->adv_prefixes_pool;
	  mhash_set (&radv_info->address_to_prefix_index, prefix_addr, pi,
		     /* old_value */ 0);

	  clib_memset (prefix, 0x0, sizeof (ip6_radv_prefix_t));

	  prefix->prefix_len = prefix_len;
	  clib_memcpy (&prefix->prefix, prefix_addr, sizeof (ip6_address_t));

	  /* initialize default values */
	  prefix->adv_on_link_flag = 1;	/* L bit set */
	  prefix->adv_autonomous_flag = 1;	/* A bit set */
	  prefix->adv_valid_lifetime_in_secs = DEF_ADV_VALID_LIFETIME;
	  prefix->adv_pref_lifetime_in_secs = DEF_ADV_PREF_LIFETIME;
	  prefix->enabled = 1;
	  prefix->decrement_lifetime_flag = 1;
	  prefix->deprecated_prefix_flag = 1;

	  if (off_link == 0)
	    {
	      /* FIXME - Should the DP do this or the CP ? */
	      /* insert prefix into routing table as a connected prefix */
	    }

	  if (use_default)
	    goto restart;
	}
      else
	{

	  if (prefix->prefix_len != prefix_len)
	    return VNET_API_ERROR_INVALID_VALUE_2;

	  if (off_link != 0)
	    {
	      /* FIXME - Should the DP do this or the CP ? */
	      /* remove from routing table if already there */
	    }
	}

      if ((val_lifetime == ~0) || (pref_lifetime == ~0))
	{
	  prefix->adv_valid_lifetime_in_secs = ~0;
	  prefix->adv_pref_lifetime_in_secs = ~0;
	  prefix->decrement_lifetime_flag = 0;
	}
      else
	{
	  prefix->adv_valid_lifetime_in_secs = val_lifetime;;
	  prefix->adv_pref_lifetime_in_secs = pref_lifetime;
	}

      /* copy  remaining */
      prefix->enabled = !(no_advertise != 0);
      prefix->adv_on_link_flag = !((off_link != 0) || (no_onlink != 0));
      prefix->adv_autonomous_flag = !(no_autoconfig != 0);

    restart:
      /* restart */
      /* fill in the expiration times  */
      prefix->valid_lifetime_expires =
	now + prefix->adv_valid_lifetime_in_secs;
      prefix->pref_lifetime_expires = now + prefix->adv_pref_lifetime_in_secs;

      radv_info->initial_adverts_sent = radv_info->initial_adverts_count - 1;
      radv_info->next_multicast_time = vlib_time_now (vm);
      radv_info->last_multicast_time = vlib_time_now (vm);
      radv_info->last_radv_time = 0;
    }
  return (error);
}

clib_error_t *
ip6_neighbor_cmd (vlib_main_t * vm, unformat_input_t * main_input,
		  vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  clib_error_t *error = 0;
  u8 is_no = 0;
  u8 suppress = 0, managed = 0, other = 0;
  u8 suppress_ll_option = 0, send_unicast = 0, cease = 0;
  u8 use_lifetime = 0;
  u32 sw_if_index, ra_lifetime = 0, ra_initial_count =
    0, ra_initial_interval = 0;
  u32 ra_max_interval = 0, ra_min_interval = 0;

  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_sw_interface_t *sw_if0;

  int add_radv_info = 1;
  __attribute__ ((unused)) ip6_radv_t *radv_info = 0;
  ip6_address_t ip6_addr;
  u32 addr_len;


  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  /* get basic radv info for this interface */
  if (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {

      if (unformat_user (line_input,
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	{
	  u32 ri;
	  ethernet_interface_t *eth_if0 = 0;

	  sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index);
	  if (sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
	    eth_if0 =
	      ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);

	  if (!eth_if0)
	    {
	      error =
		clib_error_return (0, "Interface must be of ethernet type");
	      goto done;
	    }

	  /* look up the radv_t  information for this interface */
	  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index,
				   sw_if_index, ~0);

	  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];

	  if (ri != ~0)
	    {
	      radv_info = pool_elt_at_index (nm->if_radv_pool, ri);
	    }
	  else
	    {
	      error = clib_error_return (0, "unknown interface %U'",
					 format_unformat_error, line_input);
	      goto done;
	    }
	}
      else
	{
	  error = clib_error_return (0, "invalid interface name %U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  /* get the rest of the command */
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "no"))
	is_no = 1;
      else if (unformat (line_input, "prefix %U/%d",
			 unformat_ip6_address, &ip6_addr, &addr_len))
	{
	  add_radv_info = 0;
	  break;
	}
      else if (unformat (line_input, "ra-managed-config-flag"))
	{
	  managed = 1;
	  break;
	}
      else if (unformat (line_input, "ra-other-config-flag"))
	{
	  other = 1;
	  break;
	}
      else if (unformat (line_input, "ra-suppress") ||
	       unformat (line_input, "ra-surpress"))
	{
	  suppress = 1;
	  break;
	}
      else if (unformat (line_input, "ra-suppress-link-layer") ||
	       unformat (line_input, "ra-surpress-link-layer"))
	{
	  suppress_ll_option = 1;
	  break;
	}
      else if (unformat (line_input, "ra-send-unicast"))
	{
	  send_unicast = 1;
	  break;
	}
      else if (unformat (line_input, "ra-lifetime"))
	{
	  if (!unformat (line_input, "%d", &ra_lifetime))
	    {
	      error = unformat_parse_error (line_input);
	      goto done;
	    }
	  use_lifetime = 1;
	  break;
	}
      else if (unformat (line_input, "ra-initial"))
	{
	  if (!unformat
	      (line_input, "%d %d", &ra_initial_count, &ra_initial_interval))
	    {
	      error = unformat_parse_error (line_input);
	      goto done;
	    }
	  break;
	}
      else if (unformat (line_input, "ra-interval"))
	{
	  if (!unformat (line_input, "%d", &ra_max_interval))
	    {
	      error = unformat_parse_error (line_input);
	      goto done;
	    }

	  if (!unformat (line_input, "%d", &ra_min_interval))
	    ra_min_interval = 0;
	  break;
	}
      else if (unformat (line_input, "ra-cease"))
	{
	  cease = 1;
	  break;
	}
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (add_radv_info)
    {
      ip6_neighbor_ra_config (vm, sw_if_index,
			      suppress, managed, other,
			      suppress_ll_option, send_unicast, cease,
			      use_lifetime, ra_lifetime,
			      ra_initial_count, ra_initial_interval,
			      ra_max_interval, ra_min_interval, is_no);
    }
  else
    {
      u32 valid_lifetime_in_secs = 0;
      u32 pref_lifetime_in_secs = 0;
      u8 use_prefix_default_values = 0;
      u8 no_advertise = 0;
      u8 off_link = 0;
      u8 no_autoconfig = 0;
      u8 no_onlink = 0;

      /* get the rest of the command */
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "default"))
	    {
	      use_prefix_default_values = 1;
	      break;
	    }
	  else if (unformat (line_input, "infinite"))
	    {
	      valid_lifetime_in_secs = ~0;
	      pref_lifetime_in_secs = ~0;
	      break;
	    }
	  else if (unformat (line_input, "%d %d", &valid_lifetime_in_secs,
			     &pref_lifetime_in_secs))
	    break;
	  else
	    break;
	}


      /* get the rest of the command */
      while (!use_prefix_default_values &&
	     unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "no-advertise"))
	    no_advertise = 1;
	  else if (unformat (line_input, "off-link"))
	    off_link = 1;
	  else if (unformat (line_input, "no-autoconfig"))
	    no_autoconfig = 1;
	  else if (unformat (line_input, "no-onlink"))
	    no_onlink = 1;
	  else
	    {
	      error = unformat_parse_error (line_input);
	      goto done;
	    }
	}

      ip6_neighbor_ra_prefix (vm, sw_if_index,
			      &ip6_addr, addr_len,
			      use_prefix_default_values,
			      valid_lifetime_in_secs,
			      pref_lifetime_in_secs,
			      no_advertise,
			      off_link, no_autoconfig, no_onlink, is_no);
    }

done:
  unformat_free (line_input);

  return error;
}

static void
ip6_print_addrs (vlib_main_t * vm, u32 * addrs)
{
  ip_lookup_main_t *lm = &ip6_main.lookup_main;
  u32 i;

  for (i = 0; i < vec_len (addrs); i++)
    {
      ip_interface_address_t *a =
	pool_elt_at_index (lm->if_address_pool, addrs[i]);
      ip6_address_t *address = ip_interface_address_get_address (lm, a);

      vlib_cli_output (vm, "\t\t%U/%d",
		       format_ip6_address, address, a->address_length);
    }
}

static clib_error_t *
show_ip6_interface_cmd (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  clib_error_t *error = 0;
  u32 sw_if_index;

  sw_if_index = ~0;

  if (unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      u32 ri;

      /* look up the radv_t  information for this interface */
      vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index,
			       sw_if_index, ~0);

      ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];

      if (ri != ~0)
	{
	  ip_lookup_main_t *lm = &ip6_main.lookup_main;
	  ip6_radv_t *radv_info;
	  radv_info = pool_elt_at_index (nm->if_radv_pool, ri);

	  vlib_cli_output (vm, "%U is admin %s\n",
			   format_vnet_sw_interface_name, vnm,
			   vnet_get_sw_interface (vnm, sw_if_index),
			   (vnet_sw_interface_is_admin_up (vnm, sw_if_index) ?
			    "up" : "down"));

	  u32 ai;
	  u32 *link_scope = 0, *global_scope = 0;
	  u32 *local_scope = 0, *unknown_scope = 0;
	  ip_interface_address_t *a;

	  vec_validate_init_empty (lm->if_address_pool_index_by_sw_if_index,
				   sw_if_index, ~0);
	  ai = lm->if_address_pool_index_by_sw_if_index[sw_if_index];

	  while (ai != (u32) ~ 0)
	    {
	      a = pool_elt_at_index (lm->if_address_pool, ai);
	      ip6_address_t *address =
		ip_interface_address_get_address (lm, a);

	      if (ip6_address_is_link_local_unicast (address))
		vec_add1 (link_scope, ai);
	      else if (ip6_address_is_global_unicast (address))
		vec_add1 (global_scope, ai);
	      else if (ip6_address_is_local_unicast (address))
		vec_add1 (local_scope, ai);
	      else
		vec_add1 (unknown_scope, ai);

	      ai = a->next_this_sw_interface;
	    }

	  if (vec_len (link_scope))
	    {
	      vlib_cli_output (vm, "\tLink-local address(es):\n");
	      ip6_print_addrs (vm, link_scope);
	      vec_free (link_scope);
	    }

	  if (vec_len (local_scope))
	    {
	      vlib_cli_output (vm, "\tLocal unicast address(es):\n");
	      ip6_print_addrs (vm, local_scope);
	      vec_free (local_scope);
	    }

	  if (vec_len (global_scope))
	    {
	      vlib_cli_output (vm, "\tGlobal unicast address(es):\n");
	      ip6_print_addrs (vm, global_scope);
	      vec_free (global_scope);
	    }

	  if (vec_len (unknown_scope))
	    {
	      vlib_cli_output (vm, "\tOther-scope address(es):\n");
	      ip6_print_addrs (vm, unknown_scope);
	      vec_free (unknown_scope);
	    }

	  vlib_cli_output (vm, "\tLink-local address(es):\n");
	  vlib_cli_output (vm, "\t\t%U\n", format_ip6_address,
			   &radv_info->link_local_address);

	  vlib_cli_output (vm, "\tJoined group address(es):\n");
	  ip6_mldp_group_t *m;
	  /* *INDENT-OFF* */
	  pool_foreach (m, radv_info->mldp_group_pool,
          ({
            vlib_cli_output (vm, "\t\t%U\n", format_ip6_address,
                             &m->mcast_address);
          }));
	  /* *INDENT-ON* */

	  vlib_cli_output (vm, "\tAdvertised Prefixes:\n");
	  ip6_radv_prefix_t *p;
	  /* *INDENT-OFF* */
	  pool_foreach (p, radv_info->adv_prefixes_pool,
          ({
            vlib_cli_output (vm, "\t\tprefix %U,  length %d\n",
                             format_ip6_address, &p->prefix, p->prefix_len);
          }));
	  /* *INDENT-ON* */

	  vlib_cli_output (vm, "\tMTU is %d\n", radv_info->adv_link_mtu);
	  vlib_cli_output (vm, "\tICMP error messages are unlimited\n");
	  vlib_cli_output (vm, "\tICMP redirects are disabled\n");
	  vlib_cli_output (vm, "\tICMP unreachables are not sent\n");
	  vlib_cli_output (vm, "\tND DAD is disabled\n");
	  //vlib_cli_output (vm, "\tND reachable time is %d milliseconds\n",);
	  vlib_cli_output (vm, "\tND advertised reachable time is %d\n",
			   radv_info->adv_neighbor_reachable_time_in_msec);
	  vlib_cli_output (vm,
			   "\tND advertised retransmit interval is %d (msec)\n",
			   radv_info->
			   adv_time_in_msec_between_retransmitted_neighbor_solicitations);

	  u32 ra_interval = radv_info->max_radv_interval;
	  u32 ra_interval_min = radv_info->min_radv_interval;
	  vlib_cli_output (vm,
			   "\tND router advertisements are sent every %d seconds (min interval is %d)\n",
			   ra_interval, ra_interval_min);
	  vlib_cli_output (vm,
			   "\tND router advertisements live for %d seconds\n",
			   radv_info->adv_router_lifetime_in_sec);
	  vlib_cli_output (vm,
			   "\tHosts %s stateless autoconfig for addresses\n",
			   (radv_info->adv_managed_flag) ? "use" :
			   " don't use");
	  vlib_cli_output (vm, "\tND router advertisements sent %d\n",
			   radv_info->n_advertisements_sent);
	  vlib_cli_output (vm, "\tND router solicitations received %d\n",
			   radv_info->n_solicitations_rcvd);
	  vlib_cli_output (vm, "\tND router solicitations dropped %d\n",
			   radv_info->n_solicitations_dropped);
	}
      else
	{
	  error = clib_error_return (0, "IPv6 not enabled on interface",
				     format_unformat_error, input);

	}
    }
  return error;
}

/*?
 * This command is used to display various IPv6 attributes on a given
 * interface.
 *
 * @cliexpar
 * Example of how to display IPv6 settings:
 * @cliexstart{show ip6 interface GigabitEthernet2/0/0}
 * GigabitEthernet2/0/0 is admin up
 *         Link-local address(es):
 *                 fe80::ab8/64
 *         Joined group address(es):
 *                 ff02::1
 *                 ff02::2
 *                 ff02::16
 *                 ff02::1:ff00:ab8
 *         Advertised Prefixes:
 *                 prefix fe80::fe:28ff:fe9c:75b3,  length 64
 *         MTU is 1500
 *         ICMP error messages are unlimited
 *         ICMP redirects are disabled
 *         ICMP unreachables are not sent
 *         ND DAD is disabled
 *         ND advertised reachable time is 0
 *         ND advertised retransmit interval is 0 (msec)
 *         ND router advertisements are sent every 200 seconds (min interval is 150)
 *         ND router advertisements live for 600 seconds
 *         Hosts use stateless autoconfig for addresses
 *         ND router advertisements sent 19336
 *         ND router solicitations received 0
 *         ND router solicitations dropped 0
 * @cliexend
 * Example of output if IPv6 is not enabled on the interface:
 * @cliexstart{show ip6 interface GigabitEthernet2/0/0}
 * show ip6 interface: IPv6 not enabled on interface
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip6_interface_command, static) =
{
  .path = "show ip6 interface",
  .function = show_ip6_interface_cmd,
  .short_help = "show ip6 interface <interface>",
};
/* *INDENT-ON* */

clib_error_t *
disable_ip6_interface (vlib_main_t * vm, u32 sw_if_index)
{
  clib_error_t *error = 0;
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  u32 ri;

  /* look up the radv_t  information for this interface */
  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index,
			   ~0);
  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];

  /* if not created - do nothing */
  if (ri != ~0)
    {
      ip6_radv_t *radv_info;

      radv_info = pool_elt_at_index (nm->if_radv_pool, ri);

      /* check radv_info ref count for other ip6 addresses on this interface */
      /* This implicitly excludes the link local address */
      if (radv_info->ref_count == 0)
	{
	  /* essentially "disables" ipv6 on this interface */
	  ip6_ll_prefix_t ilp = {
	    .ilp_addr = radv_info->link_local_address,
	    .ilp_sw_if_index = sw_if_index,
	  };
	  ip6_ll_table_entry_delete (&ilp);
	  ip6_sw_interface_enable_disable (sw_if_index, 0);
	  ip6_mfib_interface_enable_disable (sw_if_index, 0);
	  ip6_neighbor_sw_interface_add_del (vnet_get_main (), sw_if_index,
					     0);
	}
    }
  return error;
}

int
ip6_interface_enabled (vlib_main_t * vm, u32 sw_if_index)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  u32 ri = ~0;

  /* look up the radv_t  information for this interface */
  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index,
			   ~0);

  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];

  return ri != ~0;
}

clib_error_t *
enable_ip6_interface (vlib_main_t * vm, u32 sw_if_index)
{
  clib_error_t *error = 0;
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  u32 ri;
  int is_add = 1;

  /* look up the radv_t  information for this interface */
  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index,
			   ~0);

  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];

  /* if not created yet */
  if (ri == ~0)
    {
      vnet_main_t *vnm = vnet_get_main ();
      vnet_sw_interface_t *sw_if0;

      sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index);
      if (sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
	{
	  ethernet_interface_t *eth_if0;

	  eth_if0 =
	    ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);
	  if (eth_if0)
	    {
	      /* create radv_info. for this interface.  This holds all the info needed for router adverts */
	      ri =
		ip6_neighbor_sw_interface_add_del (vnm, sw_if_index, is_add);

	      if (ri != ~0)
		{
		  ip6_radv_t *radv_info;
		  ip6_address_t link_local_address;

		  radv_info = pool_elt_at_index (nm->if_radv_pool, ri);

		  ip6_link_local_address_from_ethernet_mac_address
		    (&link_local_address, eth_if0->address);

		  sw_if0 = vnet_get_sw_interface (vnm, sw_if_index);
		  if (sw_if0->type == VNET_SW_INTERFACE_TYPE_SUB ||
		      sw_if0->type == VNET_SW_INTERFACE_TYPE_PIPE ||
		      sw_if0->type == VNET_SW_INTERFACE_TYPE_P2P)
		    {
		      /* make up  an interface id */
		      link_local_address.as_u64[1] =
			random_u64 (&radv_info->randomizer);

		      link_local_address.as_u64[0] =
			clib_host_to_net_u64 (0xFE80000000000000ULL);
		      /* clear u bit */
		      link_local_address.as_u8[8] &= 0xfd;
		    }
		  {
		    ip6_ll_prefix_t ilp = {
		      .ilp_addr = link_local_address,
		      .ilp_sw_if_index = sw_if_index,
		    };

		    ip6_ll_table_entry_update (&ilp, FIB_ROUTE_PATH_LOCAL);
		  }

		  /* essentially "enables" ipv6 on this interface */
		  ip6_mfib_interface_enable_disable (sw_if_index, 1);
		  ip6_sw_interface_enable_disable (sw_if_index, 1);

		  if (!error)
		    {
		      radv_info->link_local_address = link_local_address;
		    }
		}
	    }
	}
    }
  return error;
}

int
ip6_get_ll_address (u32 sw_if_index, ip6_address_t * addr)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_radv_t *radv_info;
  u32 ri;

  if (vec_len (nm->if_radv_pool_index_by_sw_if_index) <= sw_if_index)
    return 0;

  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];

  if (ri == ~0)
    return 0;

  radv_info = pool_elt_at_index (nm->if_radv_pool, ri);
  *addr = radv_info->link_local_address;

  return (!0);
}

static clib_error_t *
enable_ip6_interface_cmd (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index;

  sw_if_index = ~0;

  if (unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      enable_ip6_interface (vm, sw_if_index);
    }
  else
    {
      error = clib_error_return (0, "unknown interface\n'",
				 format_unformat_error, input);

    }
  return error;
}

/*?
 * This command is used to enable IPv6 on a given interface.
 *
 * @cliexpar
 * Example of how enable IPv6 on a given interface:
 * @cliexcmd{enable ip6 interface GigabitEthernet2/0/0}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (enable_ip6_interface_command, static) =
{
  .path = "enable ip6 interface",
  .function = enable_ip6_interface_cmd,
  .short_help = "enable ip6 interface <interface>",
};
/* *INDENT-ON* */

static clib_error_t *
disable_ip6_interface_cmd (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index;

  sw_if_index = ~0;

  if (unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = disable_ip6_interface (vm, sw_if_index);
    }
  else
    {
      error = clib_error_return (0, "unknown interface\n'",
				 format_unformat_error, input);

    }
  return error;
}

/*?
 * This command is used to disable IPv6 on a given interface.
 *
 * @cliexpar
 * Example of how disable IPv6 on a given interface:
 * @cliexcmd{disable ip6 interface GigabitEthernet2/0/0}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (disable_ip6_interface_command, static) =
{
  .path = "disable ip6 interface",
  .function = disable_ip6_interface_cmd,
  .short_help = "disable ip6 interface <interface>",
};
/* *INDENT-ON* */

/*?
 * This command is used to configure the neighbor discovery
 * parameters on a given interface. Use the '<em>show ip6 interface</em>'
 * command to display some of the current neighbor discovery parameters
 * on a given interface. This command has three formats:
 *
 *
 * <b>Format 1 - Router Advertisement Options:</b> (Only one can be entered in a single command)
 *
 * '<em><b>ip6 nd <interface> [no] [ra-managed-config-flag] | [ra-other-config-flag] | [ra-suppress] | [ra-suppress-link-layer] | [ra-send-unicast] | [ra-lifetime <lifetime>] | [ra-initial <cnt> <interval>] | [ra-interval <max-interval> [<min-interval>]] | [ra-cease]</b></em>'
 *
 * Where:
 *
 * <em>[no] ra-managed-config-flag</em> - Advertises in ICMPv6
 * router-advertisement messages to use stateful address
 * auto-configuration to obtain address information (sets the M-bit).
 * Default is the M-bit is not set and the '<em>no</em>' option
 * returns it to this default state.
 *
 * <em>[no] ra-other-config-flag</em> - Indicates in ICMPv6
 * router-advertisement messages that hosts use stateful auto
 * configuration to obtain nonaddress related information (sets
 * the O-bit). Default is the O-bit is not set and the '<em>no</em>'
 * option returns it to this default state.
 *
 * <em>[no] ra-suppress</em> - Disables sending ICMPv6 router-advertisement
 * messages. The '<em>no</em>' option implies to enable sending ICMPv6
 * router-advertisement messages.
 *
 * <em>[no] ra-suppress-link-layer</em> - Indicates not to include the
 * optional source link-layer address in the ICMPv6 router-advertisement
 * messages. Default is to include the optional source link-layer address
 * and the '<em>no</em>' option returns it to this default state.
 *
 * <em>[no] ra-send-unicast</em> - Use the source address of the
 * router-solicitation message if availiable. The default is to use
 * multicast address of all nodes, and the '<em>no</em>' option returns
 * it to this default state.
 *
 * <em>[no] ra-lifetime <lifetime></em> - Advertises the lifetime of a
 * default router in ICMPv6 router-advertisement messages. The range is
 * from 0 to 9000 seconds. '<em><lifetime></em>' must be greater than
 * '<em><max-interval></em>'. The default value is 600 seconds and the
 * '<em>no</em>' option returns it to this default value.
 *
 * <em>[no] ra-initial <cnt> <interval></em> - Number of initial ICMPv6
 * router-advertisement messages sent and the interval between each
 * message. Range for count is 1 - 3 and default is 3. Range for interval
 * is 1 to 16 seconds, and default is 16 seconds. The '<em>no</em>' option
 * returns both to their default value.
 *
 * <em>[no] ra-interval <max-interval> [<min-interval>]</em> - Configures the
 * interval between sending ICMPv6 router-advertisement messages. The
 * range for max-interval is from 4 to 200 seconds. min-interval can not
 * be more than 75% of max-interval. If not set, min-interval will be
 * set to 75% of max-interval. The range for min-interval is from 3 to
 * 150 seconds.  The '<em>no</em>' option returns both to their default
 * value.
 *
 * <em>[no] ra-cease</em> - Cease sending ICMPv6 router-advertisement messages.
 * The '<em>no</em>' options implies to start (or restart) sending
 * ICMPv6 router-advertisement messages.
 *
 *
 * <b>Format 2 - Prefix Options:</b>
 *
 * '<em><b>ip6 nd <interface> [no] prefix <ip6-address>/<width> [<valid-lifetime> <pref-lifetime> | infinite] [no-advertise] [off-link] [no-autoconfig] [no-onlink]</b></em>'
 *
 * Where:
 *
 * <em>no</em> - All additional flags are ignored and the prefix is deleted.
 *
 * <em><valid-lifetime> <pref-lifetime></em> - '<em><valid-lifetime></em>' is the
 * length of time in seconds during what the prefix is valid for the purpose of
 * on-link determination. Range is 7203 to 2592000 seconds and default is 2592000
 * seconds (30 days). '<em><pref-lifetime></em>' is the prefered-lifetime and is the
 * length of time in seconds during what addresses generated from the prefix remain
 * preferred. Range is 0 to 604800 seconds and default is 604800 seconds (7 days).
 *
 * <em>infinite</em> - Both '<em><valid-lifetime></em>' and '<em><<pref-lifetime></em>'
 * are inifinte, no timeout.
 *
 * <em>no-advertise</em> - Do not send full router address in prefix
 * advertisement. Default is to advertise (i.e. - This flag is off by default).
 *
 * <em>off-link</em> - Prefix is off-link, clear L-bit in packet. Default is on-link
 * (i.e. - This flag is off and L-bit in packet is set by default and this prefix can
 * be used for on-link determination). '<em>no-onlink</em>' also controls the L-bit.
 *
 * <em>no-autoconfig</em> - Do not use prefix for autoconfiguration, clear A-bit in packet.
 * Default is autoconfig (i.e. - This flag is off and A-bit in packet is set by default.
 *
 * <em>no-onlink</em> - Do not use prefix for onlink determination, clear L-bit in packet.
 * Default is on-link (i.e. - This flag is off and L-bit in packet is set by default and
 * this prefix can be used for on-link determination). '<em>off-link</em>' also controls
 * the L-bit.
 *
 *
 * <b>Format 3: - Default of Prefix:</b>
 *
 * '<em><b>ip6 nd <interface> [no] prefix <ip6-address>/<width> default</b></em>'
 *
 * When a new prefix is added (or existing one is being overwritten) <em>default</em>
 * uses default values for the prefix. If <em>no</em> is used, the <em>default</em>
 * is ignored and the prefix is deleted.
 *
 *
 * @cliexpar
 * Example of how set a router advertisement option:
 * @cliexcmd{ip6 nd GigabitEthernet2/0/0 ra-interval 100 20}
 * Example of how to add a prefix:
 * @cliexcmd{ip6 nd GigabitEthernet2/0/0 prefix fe80::fe:28ff:fe9c:75b3/64 infinite no-advertise}
 * Example of how to delete a prefix:
 * @cliexcmd{ip6 nd GigabitEthernet2/0/0 no prefix fe80::fe:28ff:fe9c:75b3/64}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_nd_command, static) =
{
  .path = "ip6 nd",
  .short_help = "ip6 nd <interface> ...",
  .function = ip6_neighbor_cmd,
};
/* *INDENT-ON* */

clib_error_t *
ip6_neighbor_set_link_local_address (vlib_main_t * vm, u32 sw_if_index,
				     ip6_address_t * address)
{
  clib_error_t *error = 0;
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  u32 ri;
  ip6_radv_t *radv_info;
  vnet_main_t *vnm = vnet_get_main ();
  ip6_ll_prefix_t pfx = { 0, };

  if (!ip6_address_is_link_local_unicast (address))
    return (error = clib_error_return (0, "address not link-local",
				       format_unformat_error));

  /* call enable ipv6  */
  enable_ip6_interface (vm, sw_if_index);

  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];

  if (ri != ~0)
    {
      radv_info = pool_elt_at_index (nm->if_radv_pool, ri);

      pfx.ilp_sw_if_index = sw_if_index;

      pfx.ilp_addr = radv_info->link_local_address;
      ip6_ll_table_entry_delete (&pfx);

      pfx.ilp_addr = *address;
      ip6_ll_table_entry_update (&pfx, FIB_ROUTE_PATH_LOCAL);

      radv_info = pool_elt_at_index (nm->if_radv_pool, ri);
      radv_info->link_local_address = *address;
    }
  else
    {
      vnm->api_errno = VNET_API_ERROR_IP6_NOT_ENABLED;
      error = clib_error_return (0, "ip6 not enabled for interface",
				 format_unformat_error);
    }
  return error;
}

/**
 * @brief callback when an interface address is added or deleted
 */
static void
ip6_neighbor_add_del_interface_address (ip6_main_t * im,
					uword opaque,
					u32 sw_if_index,
					ip6_address_t * address,
					u32 address_length,
					u32 if_address_index, u32 is_delete)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  u32 ri;
  vlib_main_t *vm = vnm->vlib_main;
  ip6_radv_t *radv_info;
  ip6_address_t a;

  /* create solicited node multicast address for this interface adddress */
  ip6_set_solicited_node_multicast_address (&a, 0);

  a.as_u8[0xd] = address->as_u8[0xd];
  a.as_u8[0xe] = address->as_u8[0xe];
  a.as_u8[0xf] = address->as_u8[0xf];

  if (!is_delete)
    {
      /* try to  create radv_info - does nothing if ipv6 already enabled */
      enable_ip6_interface (vm, sw_if_index);

      /* look up the radv_t  information for this interface */
      vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index,
			       sw_if_index, ~0);
      ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];
      if (ri != ~0)
	{
	  /* get radv_info */
	  radv_info = pool_elt_at_index (nm->if_radv_pool, ri);

	  /* add address */
	  if (!ip6_address_is_link_local_unicast (address))
	    radv_info->ref_count++;

	  ip6_neighbor_add_mld_prefix (radv_info, &a);
	}
    }
  else
    {

      /* delete */
      /* look up the radv_t  information for this interface */
      vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index,
			       sw_if_index, ~0);
      ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];

      if (ri != ~0)
	{
	  /* get radv_info */
	  radv_info = pool_elt_at_index (nm->if_radv_pool, ri);

	  ip6_neighbor_del_mld_prefix (radv_info, &a);

	  /* if interface up send MLDP "report" */
	  radv_info->all_routers_mcast = 0;

	  /* add address */
	  if (!ip6_address_is_link_local_unicast (address))
	    radv_info->ref_count--;
	}
      /* Ensure that IPv6 is disabled, and LL removed after ref_count reaches 0 */
      disable_ip6_interface (vm, sw_if_index);
    }
}

clib_error_t *
ip6_set_neighbor_limit (u32 neighbor_limit)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;

  nm->limit_neighbor_cache_size = neighbor_limit;
  return 0;
}

static void
ip6_neighbor_table_bind (ip6_main_t * im,
			 uword opaque,
			 u32 sw_if_index,
			 u32 new_fib_index, u32 old_fib_index)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_neighbor_t *n = NULL;
  u32 i, *to_re_add = 0;

  /* *INDENT-OFF* */
  pool_foreach (n, nm->neighbor_pool,
  ({
    if (n->key.sw_if_index == sw_if_index)
      vec_add1 (to_re_add, n - nm->neighbor_pool);
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (to_re_add); i++)
    {
      n = pool_elt_at_index (nm->neighbor_pool, to_re_add[i]);
      ip6_neighbor_adj_fib_remove (n, old_fib_index);
      ip6_neighbor_adj_fib_add (n, new_fib_index);
    }
  vec_free (to_re_add);
}

static clib_error_t *
ip6_neighbor_init (vlib_main_t * vm)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_main_t *im = &ip6_main;

  mhash_init (&nm->neighbor_index_by_key,
	      /* value size */ sizeof (uword),
	      /* key size */ sizeof (ip6_neighbor_key_t));

  icmp6_register_type (vm, ICMP6_neighbor_solicitation,
		       ip6_icmp_neighbor_solicitation_node.index);
  icmp6_register_type (vm, ICMP6_neighbor_advertisement,
		       ip6_icmp_neighbor_advertisement_node.index);
  icmp6_register_type (vm, ICMP6_router_solicitation,
		       ip6_icmp_router_solicitation_node.index);
  icmp6_register_type (vm, ICMP6_router_advertisement,
		       ip6_icmp_router_advertisement_node.index);

  /* handler node for ip6 neighbor discovery events and timers */
  vlib_register_node (vm, &ip6_icmp_neighbor_discovery_event_node);

  /* add call backs */
  ip6_add_del_interface_address_callback_t cb;
  clib_memset (&cb, 0x0, sizeof (ip6_add_del_interface_address_callback_t));

  /* when an interface address changes... */
  cb.function = ip6_neighbor_add_del_interface_address;
  cb.function_opaque = 0;
  vec_add1 (im->add_del_interface_address_callbacks, cb);

  ip6_table_bind_callback_t cbt;
  cbt.function = ip6_neighbor_table_bind;
  cbt.function_opaque = 0;
  vec_add1 (im->table_bind_callbacks, cbt);

  mhash_init (&nm->pending_resolutions_by_address,
	      /* value size */ sizeof (uword),
	      /* key size */ sizeof (ip6_address_t));

  mhash_init (&nm->mac_changes_by_address,
	      /* value size */ sizeof (uword),
	      /* key size */ sizeof (ip6_address_t));

  /* default, configurable */
  nm->limit_neighbor_cache_size = 50000;

  nm->wc_ip6_nd_publisher_node = (uword) ~ 0;

  nm->ip6_ra_publisher_node = (uword) ~ 0;

#if 0
  /* $$$$ Hack fix for today */
  vec_validate_init_empty
    (im->discover_neighbor_next_index_by_hw_if_index, 32, 0 /* drop */ );
#endif

  return 0;
}

VLIB_INIT_FUNCTION (ip6_neighbor_init);


void
vnet_register_ip6_neighbor_resolution_event (vnet_main_t * vnm,
					     void *address_arg,
					     uword node_index,
					     uword type_opaque, uword data)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_address_t *address = address_arg;
  uword *p;
  pending_resolution_t *pr;

  pool_get (nm->pending_resolutions, pr);

  pr->next_index = ~0;
  pr->node_index = node_index;
  pr->type_opaque = type_opaque;
  pr->data = data;

  p = mhash_get (&nm->pending_resolutions_by_address, address);
  if (p)
    {
      /* Insert new resolution at the head of the list */
      pr->next_index = p[0];
      mhash_unset (&nm->pending_resolutions_by_address, address, 0);
    }

  mhash_set (&nm->pending_resolutions_by_address, address,
	     pr - nm->pending_resolutions, 0 /* old value */ );
}

int
vnet_add_del_ip6_nd_change_event (vnet_main_t * vnm,
				  void *data_callback,
				  u32 pid,
				  void *address_arg,
				  uword node_index,
				  uword type_opaque, uword data, int is_add)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_address_t *address = address_arg;

  /* Try to find an existing entry */
  u32 *first = (u32 *) mhash_get (&nm->mac_changes_by_address, address);
  u32 *p = first;
  pending_resolution_t *mc;
  while (p && *p != ~0)
    {
      mc = pool_elt_at_index (nm->mac_changes, *p);
      if (mc->node_index == node_index && mc->type_opaque == type_opaque
	  && mc->pid == pid)
	break;
      p = &mc->next_index;
    }

  int found = p && *p != ~0;
  if (is_add)
    {
      if (found)
	return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

      pool_get (nm->mac_changes, mc);
      /* *INDENT-OFF* */
      *mc = (pending_resolution_t)
      {
        .next_index = ~0,
        .node_index = node_index,
        .type_opaque = type_opaque,
        .data = data,
        .data_callback = data_callback,
        .pid = pid,
      };
      /* *INDENT-ON* */

      /* Insert new resolution at the end of the list */
      u32 new_idx = mc - nm->mac_changes;
      if (p)
	p[0] = new_idx;
      else
	mhash_set (&nm->mac_changes_by_address, address, new_idx, 0);
    }
  else
    {
      if (!found)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      /* Clients may need to clean up pool entries, too */
      void (*fp) (u32, u8 *) = data_callback;
      if (fp)
	(*fp) (mc->data, 0 /* no new mac addrs */ );

      /* Remove the entry from the list and delete the entry */
      *p = mc->next_index;
      pool_put (nm->mac_changes, mc);

      /* Remove from hash if we deleted the last entry */
      if (*p == ~0 && p == first)
	mhash_unset (&nm->mac_changes_by_address, address, 0);
    }
  return 0;
}

int
vnet_ip6_nd_term (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_buffer_t * p0,
		  ethernet_header_t * eth,
		  ip6_header_t * ip, u32 sw_if_index, u16 bd_index)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  icmp6_neighbor_solicitation_or_advertisement_header_t *ndh;

  ndh = ip6_next_header (ip);
  if (ndh->icmp.type != ICMP6_neighbor_solicitation &&
      ndh->icmp.type != ICMP6_neighbor_advertisement)
    return 0;

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
		     (p0->flags & VLIB_BUFFER_IS_TRACED)))
    {
      u8 *t0 = vlib_add_trace (vm, node, p0,
			       sizeof (icmp6_input_trace_t));
      clib_memcpy (t0, ip, sizeof (icmp6_input_trace_t));
    }

  /* Check if anyone want ND events for L2 BDs */
  if (PREDICT_FALSE
      (nm->wc_ip6_nd_publisher_node != (uword) ~ 0
       && !ip6_address_is_link_local_unicast (&ip->src_address)))
    {
      vnet_nd_wc_publish (sw_if_index, eth->src_address, &ip->src_address);
    }

  /* Check if MAC entry exsist for solicited target IP */
  if (ndh->icmp.type == ICMP6_neighbor_solicitation)
    {
      icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *opt;
      l2_bridge_domain_t *bd_config;
      u8 *macp;

      opt = (void *) (ndh + 1);
      if ((opt->header.type !=
	   ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address) ||
	  (opt->header.n_data_u64s != 1))
	return 0;		/* source link layer address option not present */

      bd_config = vec_elt_at_index (l2input_main.bd_configs, bd_index);
      macp =
	(u8 *) hash_get_mem (bd_config->mac_by_ip6, &ndh->target_address);
      if (macp)
	{			/* found ip-mac entry, generate eighbor advertisement response */
	  int bogus_length;
	  vlib_node_runtime_t *error_node =
	    vlib_node_get_runtime (vm, ip6_icmp_input_node.index);
	  ip->dst_address = ip->src_address;
	  ip->src_address = ndh->target_address;
	  ip->hop_limit = 255;
	  opt->header.type =
	    ICMP6_NEIGHBOR_DISCOVERY_OPTION_target_link_layer_address;
	  clib_memcpy (opt->ethernet_address, macp, 6);
	  ndh->icmp.type = ICMP6_neighbor_advertisement;
	  ndh->advertisement_flags = clib_host_to_net_u32
	    (ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_SOLICITED |
	     ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERRIDE);
	  ndh->icmp.checksum = 0;
	  ndh->icmp.checksum =
	    ip6_tcp_udp_icmp_compute_checksum (vm, p0, ip, &bogus_length);
	  clib_memcpy (eth->dst_address, eth->src_address, 6);
	  clib_memcpy (eth->src_address, macp, 6);
	  vlib_error_count (vm, error_node->node_index,
			    ICMP6_ERROR_NEIGHBOR_ADVERTISEMENTS_TX, 1);
	  return 1;
	}
    }

  return 0;

}

int
ip6_neighbor_proxy_add_del (u32 sw_if_index, ip6_address_t * addr, u8 is_del)
{
  u32 fib_index;

  fib_prefix_t pfx = {
    .fp_len = 128,
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_addr = {
		.ip6 = *addr,
		},
  };
  ip46_address_t nh = {
    .ip6 = *addr,
  };

  fib_index = ip6_fib_table_get_index_for_sw_if_index (sw_if_index);

  if (~0 == fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  if (is_del)
    {
      fib_table_entry_path_remove (fib_index,
				   &pfx,
				   FIB_SOURCE_IP6_ND_PROXY,
				   DPO_PROTO_IP6,
				   &nh,
				   sw_if_index,
				   ~0, 1, FIB_ROUTE_PATH_FLAG_NONE);
      /* flush the ND cache of this address if it's there */
      vnet_unset_ip6_ethernet_neighbor (vlib_get_main (), sw_if_index, addr);
    }
  else
    {
      fib_table_entry_path_add (fib_index,
				&pfx,
				FIB_SOURCE_IP6_ND_PROXY,
				FIB_ENTRY_FLAG_NONE,
				DPO_PROTO_IP6,
				&nh,
				sw_if_index,
				~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
    }
  return (0);
}

static clib_error_t *
set_ip6_nd_proxy_cmd (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  ip6_address_t addr;
  u32 sw_if_index;
  u8 is_del = 0;

  if (unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      /* get the rest of the command */
      while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (input, "%U", unformat_ip6_address, &addr))
	    break;
	  else if (unformat (input, "delete") || unformat (input, "del"))
	    is_del = 1;
	  else
	    return (unformat_parse_error (input));
	}
    }

  ip6_neighbor_proxy_add_del (sw_if_index, &addr, is_del);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ip6_nd_proxy_command, static) =
{
  .path = "set ip6 nd proxy",
  .short_help = "set ip6 nd proxy <HOST> <INTERFACE>",
  .function = set_ip6_nd_proxy_cmd,
};
/* *INDENT-ON* */

void
ethernet_ndp_change_mac (u32 sw_if_index)
{
  ip6_neighbor_main_t *nm = &ip6_neighbor_main;
  ip6_neighbor_t *n;
  adj_index_t ai;

  /* *INDENT-OFF* */
  pool_foreach (n, nm->neighbor_pool,
  ({
    if (n->key.sw_if_index == sw_if_index)
      {
	adj_nbr_walk_nh6 (sw_if_index,
			  &n->key.ip6_address,
			  ip6_nd_mk_complete_walk, n);
      }
  }));
  /* *INDENT-ON* */

  ai = adj_glean_get (FIB_PROTOCOL_IP6, sw_if_index);

  if (ADJ_INDEX_INVALID != ai)
    adj_glean_update_rewrite (ai);
}

void
send_ip6_na (vlib_main_t * vm, u32 sw_if_index)
{
  ip6_main_t *i6m = &ip6_main;
  ip6_address_t *ip6_addr = ip6_interface_first_address (i6m, sw_if_index);

  send_ip6_na_w_addr (vm, ip6_addr, sw_if_index);
}

void
send_ip6_na_w_addr (vlib_main_t * vm,
		    const ip6_address_t * ip6_addr, u32 sw_if_index)
{
  ip6_main_t *i6m = &ip6_main;
  vnet_main_t *vnm = vnet_get_main ();
  u8 *rewrite, rewrite_len;
  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
  u8 dst_address[6];

  if (ip6_addr)
    {
      clib_warning
	("Sending unsolicitated NA IP6 address %U on sw_if_idex %d",
	 format_ip6_address, ip6_addr, sw_if_index);

      /* Form unsolicited neighbor advertisement packet from NS pkt template */
      int bogus_length;
      u32 bi = 0;
      icmp6_neighbor_solicitation_header_t *h =
	vlib_packet_template_get_packet (vm,
					 &i6m->discover_neighbor_packet_template,
					 &bi);
      if (!h)
	return;

      ip6_set_reserved_multicast_address (&h->ip.dst_address,
					  IP6_MULTICAST_SCOPE_link_local,
					  IP6_MULTICAST_GROUP_ID_all_hosts);
      h->ip.src_address = ip6_addr[0];
      h->neighbor.icmp.type = ICMP6_neighbor_advertisement;
      h->neighbor.target_address = ip6_addr[0];
      h->neighbor.advertisement_flags = clib_host_to_net_u32
	(ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERRIDE);
      h->link_layer_option.header.type =
	ICMP6_NEIGHBOR_DISCOVERY_OPTION_target_link_layer_address;
      clib_memcpy (h->link_layer_option.ethernet_address,
		   hi->hw_address, vec_len (hi->hw_address));
      h->neighbor.icmp.checksum =
	ip6_tcp_udp_icmp_compute_checksum (vm, 0, &h->ip, &bogus_length);
      ASSERT (bogus_length == 0);

      /* Setup MAC header with IP6 Etype and mcast DMAC */
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      ip6_multicast_ethernet_address (dst_address,
				      IP6_MULTICAST_GROUP_ID_all_hosts);
      rewrite =
	ethernet_build_rewrite (vnm, sw_if_index, VNET_LINK_IP6, dst_address);
      rewrite_len = vec_len (rewrite);
      vlib_buffer_advance (b, -rewrite_len);
      ethernet_header_t *e = vlib_buffer_get_current (b);
      clib_memcpy (e->dst_address, rewrite, rewrite_len);
      vec_free (rewrite);

      /* Send unsolicited ND advertisement packet out the specified interface */
      vnet_buffer (b)->sw_if_index[VLIB_RX] =
	vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;
      vlib_frame_t *f = vlib_get_frame_to_node (vm, hi->output_node_index);
      u32 *to_next = vlib_frame_vector_args (f);
      to_next[0] = bi;
      f->n_vectors = 1;
      vlib_put_frame_to_node (vm, hi->output_node_index, f);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
