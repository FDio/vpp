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
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/mhash.h>
#include <vppinfra/md5.h>

#if DPDK==1
#include <vnet/devices/dpdk/dpdk.h>
#endif

typedef struct {
  ip6_address_t ip6_address;
  u32 sw_if_index;
  u32 pad;
} ip6_neighbor_key_t;

/* can't use sizeof link_layer_address, that's 8 */ 
#define ETHER_MAC_ADDR_LEN 6

typedef struct {
  ip6_neighbor_key_t key;
  u8 link_layer_address[8];
  u16 flags;
#define IP6_NEIGHBOR_FLAG_STATIC (1 << 0)
#define IP6_NEIGHBOR_FLAG_GLEAN  (2 << 0)
  u64 cpu_time_last_updated;
  u32 *adjacencies;
} ip6_neighbor_t;

/* advertised prefix option */ 
typedef struct {
  /* basic advertised information */
  ip6_address_t prefix;
  u8 prefix_len;
  int adv_on_link_flag;
  int adv_autonomous_flag;
  u32 adv_valid_lifetime_in_secs;
  u32 adv_pref_lifetime_in_secs;

  /* advertised values are computed from these times if decrementing */
  f64 valid_lifetime_expires;
  f64  pref_lifetime_expires;
 
  /* local information */
  int enabled;
  int deprecated_prefix_flag;
  int decrement_lifetime_flag; 

#define MIN_ADV_VALID_LIFETIME 7203	/* seconds */
#define DEF_ADV_VALID_LIFETIME  2592000
#define DEF_ADV_PREF_LIFETIME 604800

  /* extensions are added here, mobile, DNS etc.. */
} ip6_radv_prefix_t;


typedef struct {
  /* group information */
  u8 type;
  ip6_address_t mcast_address;
  u16 num_sources;
  ip6_address_t *mcast_source_address_pool;
} ip6_mldp_group_t;

/* configured router advertisement information per ipv6 interface */
typedef struct {

  /* advertised config information, zero means unspecified  */
  u8  curr_hop_limit;
  int adv_managed_flag;
  int adv_other_flag;
  u16 adv_router_lifetime_in_sec; 
  u32 adv_neighbor_reachable_time_in_msec;
  u32 adv_time_in_msec_between_retransmitted_neighbor_solicitations;

  /* mtu option */
  u32 adv_link_mtu;
  
  /* source link layer option */
  u8  link_layer_address[8];
  u8  link_layer_addr_len;

  /* prefix option */
  ip6_radv_prefix_t * adv_prefixes_pool;

  /* Hash table mapping address to index in interface advertised  prefix pool. */
  mhash_t address_to_prefix_index;

  /* MLDP  group information */
  ip6_mldp_group_t  * mldp_group_pool;

  /* Hash table mapping address to index in mldp address pool. */
  mhash_t address_to_mldp_index;

  /* local information */
  u32 sw_if_index;
  u32 fib_index;
  int send_radv;              /* radv on/off on this interface -  set by config */
  int cease_radv;           /* we are ceasing  to send  - set byf config */
  int send_unicast;
  int adv_link_layer_address;
  int prefix_option;
  int failed_device_check;
  int all_routers_mcast;
  u32 seed;
  u64 randomizer;
  int ref_count;
  u32 all_nodes_adj_index;
  u32 all_routers_adj_index;
  u32 all_mldv2_routers_adj_index;
  
  /* timing information */
#define DEF_MAX_RADV_INTERVAL 200
#define DEF_MIN_RADV_INTERVAL .75 * DEF_MAX_RADV_INTERVAL
#define DEF_CURR_HOP_LIMIT  64
#define DEF_DEF_RTR_LIFETIME   3 * DEF_MAX_RADV_INTERVAL
#define MAX_DEF_RTR_LIFETIME   9000

#define MAX_INITIAL_RTR_ADVERT_INTERVAL   16  /* seconds */
#define MAX_INITIAL_RTR_ADVERTISEMENTS        3    /*transmissions */
#define MIN_DELAY_BETWEEN_RAS                              3  /* seconds */
#define MAX_DELAY_BETWEEN_RAS                    1800  /* seconds */
#define MAX_RA_DELAY_TIME                                          .5 /* seconds */

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
  u8 link_local_prefix_len;

} ip6_radv_t;

typedef struct {
  u32 next_index;
  uword node_index;
  uword type_opaque;
  uword data;
} pending_resolution_t;


typedef struct {
  /* Hash tables mapping name to opcode. */
  uword * opcode_by_name;

  /* lite beer "glean" adjacency handling */
  mhash_t pending_resolutions_by_address;
  pending_resolution_t * pending_resolutions;

  u32 * neighbor_input_next_index_by_hw_if_index;

  ip6_neighbor_t * neighbor_pool;

  mhash_t neighbor_index_by_key;

  u32 * if_radv_pool_index_by_sw_if_index;

  ip6_radv_t * if_radv_pool;

  /* Neighbor attack mitigation */
  u32 limit_neighbor_cache_size;
  u32 neighbor_delete_rotor;

} ip6_neighbor_main_t;

static ip6_neighbor_main_t ip6_neighbor_main;

static u8 * format_ip6_neighbor_ip6_entry (u8 * s, va_list * va)
{
  vlib_main_t * vm = va_arg (*va, vlib_main_t *);
  ip6_neighbor_t * n = va_arg (*va, ip6_neighbor_t *);
  vnet_main_t * vnm = vnet_get_main();
  vnet_sw_interface_t * si;
  u8 * flags = 0;

  if (! n)
    return format (s, "%=12s%=20s%=6s%=20s%=40s", "Time", "Address", "Flags", "Link layer", "Interface");

  if (n->flags & IP6_NEIGHBOR_FLAG_GLEAN)
    flags = format(flags, "G");

  if (n->flags & IP6_NEIGHBOR_FLAG_STATIC)
    flags = format(flags, "S");

  si = vnet_get_sw_interface (vnm, n->key.sw_if_index);
  s = format (s, "%=12U%=20U%=6s%=20U%=40U",
	      format_vlib_cpu_time, vm, n->cpu_time_last_updated,
	      format_ip6_address, &n->key.ip6_address,
	      flags ? (char *)flags : "",
	      format_ethernet_address, n->link_layer_address,
	      format_vnet_sw_interface_name, vnm, si);

  vec_free(flags);
  return s;
}

static clib_error_t *
ip6_neighbor_sw_interface_up_down (vnet_main_t * vnm,
				   u32 sw_if_index,
				   u32 flags)
{
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  ip6_neighbor_t * n;
 
  if (! (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
    {
      u32 i, * to_delete = 0;

      pool_foreach (n, nm->neighbor_pool, ({
	if (n->key.sw_if_index == sw_if_index)
	  vec_add1 (to_delete, n - nm->neighbor_pool);
      }));

      for (i = 0; i < vec_len (to_delete); i++)
	{
	  n = pool_elt_at_index (nm->neighbor_pool, to_delete[i]);
	  mhash_unset (&nm->neighbor_index_by_key, &n->key, 0);
	  pool_put (nm->neighbor_pool, n);
	}

      vec_free (to_delete);
    }

  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (ip6_neighbor_sw_interface_up_down);

static void unset_random_neighbor_entry (void)
{
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  vnet_main_t * vnm = vnet_get_main();
  vlib_main_t * vm = vnm->vlib_main;
  ip6_neighbor_t * e;
  u32 index;

  index = pool_next_index (nm->neighbor_pool, nm->neighbor_delete_rotor);
  nm->neighbor_delete_rotor = index;

  /* Try again from elt 0, could happen if an intfc goes down */
  if (index == ~0)
    {
      index = pool_next_index (nm->neighbor_pool, nm->neighbor_delete_rotor);
      nm->neighbor_delete_rotor = index;
    }

  /* Nothing left in the pool */
  if (index == ~0)
    return;

  e = pool_elt_at_index (nm->neighbor_pool, index);
  
  vnet_unset_ip6_ethernet_neighbor (vm, e->key.sw_if_index,
                                    &e->key.ip6_address, 
                                    e->link_layer_address,
                                    ETHER_MAC_ADDR_LEN);
}

typedef struct {
  u8 is_add;
  u8 is_static;
  u8 link_layer_address[6];
  u32 sw_if_index;
  ip6_address_t addr;
} ip6_neighbor_set_unset_rpc_args_t;

#if DPDK > 0
static void ip6_neighbor_set_unset_rpc_callback 
( ip6_neighbor_set_unset_rpc_args_t * a);

static void set_unset_ip6_neighbor_rpc 
(vlib_main_t * vm,
 u32 sw_if_index,
 ip6_address_t * a,
 u8 *link_layer_addreess,
 int is_add, int is_static)
{
  ip6_neighbor_set_unset_rpc_args_t args;
  void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);
  
  args.sw_if_index = sw_if_index;
  args.is_add = is_add;
  args.is_static = is_static;
  clib_memcpy (&args.addr, a, sizeof (*a));
  clib_memcpy (args.link_layer_address, link_layer_addreess, 6);
  
  vl_api_rpc_call_main_thread (ip6_neighbor_set_unset_rpc_callback,
                               (u8 *) &args, sizeof (args));
}
#endif

int
vnet_set_ip6_ethernet_neighbor (vlib_main_t * vm,
                                u32 sw_if_index,
                                ip6_address_t * a,
                                u8 * link_layer_address,
                                uword n_bytes_link_layer_address,
                                int is_static)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  ip6_neighbor_key_t k;
  ip6_neighbor_t * n = 0;
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  int make_new_nd_cache_entry=1;
  uword * p;
  u32 next_index;
  u32 adj_index;
  ip_adjacency_t *existing_adj;
  pending_resolution_t * pr;

#if DPDK > 0
  if (os_get_cpu_number())
    {
      set_unset_ip6_neighbor_rpc (vm, sw_if_index, a, link_layer_address,
                                  1 /* set new neighbor */, is_static);
      return 0;
    }
#endif

  k.sw_if_index = sw_if_index;
  k.ip6_address = a[0];
  k.pad = 0;

  vlib_worker_thread_barrier_sync (vm);

  p = mhash_get (&nm->neighbor_index_by_key, &k);
  if (p) {
    n = pool_elt_at_index (nm->neighbor_pool, p[0]);
    /* Refuse to over-write static neighbor entry. */
    if (!is_static &&
        (n->flags & IP6_NEIGHBOR_FLAG_STATIC))
      return -2;
    make_new_nd_cache_entry = 0;
  }

  /* Note: always install the route. It might have been deleted */
  ip6_add_del_route_args_t args;
  ip_adjacency_t adj;

  memset (&adj, 0, sizeof(adj));
  adj.lookup_next_index = IP_LOOKUP_NEXT_REWRITE;
  adj.explicit_fib_index = ~0;

  vnet_rewrite_for_sw_interface
  (vnm,
   VNET_L3_PACKET_TYPE_IP6,
   sw_if_index,
   ip6_rewrite_node.index,
   link_layer_address,
   &adj.rewrite_header,
   sizeof (adj.rewrite_data));

  /* result of this lookup should be next-hop adjacency */
  adj_index = ip6_fib_lookup_with_table (im, im->fib_index_by_sw_if_index[sw_if_index], a);
  existing_adj = ip_get_adjacency(lm, adj_index);

  if (existing_adj->lookup_next_index == IP_LOOKUP_NEXT_ARP &&
      existing_adj->arp.next_hop.ip6.as_u64[0] == a->as_u64[0] &&
      existing_adj->arp.next_hop.ip6.as_u64[1] == a->as_u64[1])
  {
    u32 * ai;
    u32 * adjs = vec_dup(n->adjacencies);
    /* Update all adj assigned to this arp entry */
    vec_foreach(ai, adjs)
    {
      int i;
      ip_adjacency_t * uadj = ip_get_adjacency(lm, *ai);
      for (i = 0; i < uadj->n_adj; i++)
        if (uadj[i].lookup_next_index == IP_LOOKUP_NEXT_ARP &&
            uadj[i].arp.next_hop.ip6.as_u64[0] == a->as_u64[0] &&
            uadj[i].arp.next_hop.ip6.as_u64[1] == a->as_u64[1])
          ip_update_adjacency (lm, *ai + i, &adj);
    }
    vec_free(adjs);
  }
  else
  {
    /* create new adj */
    args.table_index_or_table_id = im->fib_index_by_sw_if_index[sw_if_index];
    args.flags = IP6_ROUTE_FLAG_FIB_INDEX | IP6_ROUTE_FLAG_ADD | IP6_ROUTE_FLAG_NEIGHBOR;
    args.dst_address = a[0];
    args.dst_address_length = 128;
    args.adj_index = ~0;
    args.add_adj = &adj;
    args.n_add_adj = 1;
    ip6_add_del_route (im, &args);
  }

  if (make_new_nd_cache_entry) {
    pool_get (nm->neighbor_pool, n);
    mhash_set (&nm->neighbor_index_by_key, &k, n - nm->neighbor_pool,
               /* old value */ 0);
    n->key = k;
  }

  /* Update time stamp and ethernet address. */
  clib_memcpy (n->link_layer_address, link_layer_address, n_bytes_link_layer_address);
  n->cpu_time_last_updated = clib_cpu_time_now ();
  if (is_static)
    n->flags |= IP6_NEIGHBOR_FLAG_STATIC;

  /* Customer(s) waiting for this address to be resolved? */
  p = mhash_get (&nm->pending_resolutions_by_address, a);
  if (p == 0)
      goto out;
  
  next_index = p[0];
  
  while (next_index != (u32)~0)
    {
      pr = pool_elt_at_index (nm->pending_resolutions, next_index);
      vlib_process_signal_event (vm, pr->node_index,
                                 pr->type_opaque, 
                                 pr->data);
      next_index = pr->next_index;
      pool_put (nm->pending_resolutions, pr);
    }

  mhash_unset (&nm->pending_resolutions_by_address, a, 0);
  
out:
  vlib_worker_thread_barrier_release(vm);
  return 0;
}

int
vnet_unset_ip6_ethernet_neighbor (vlib_main_t * vm,
                                  u32 sw_if_index,
                                  ip6_address_t * a,
                                  u8 * link_layer_address,
                                  uword n_bytes_link_layer_address)
{
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  ip6_neighbor_key_t k;
  ip6_neighbor_t * n;
  ip6_main_t * im = &ip6_main;
  ip6_add_del_route_args_t args;
  uword * p;
  int rv = 0;

#if DPDK > 0
  if (os_get_cpu_number())
    {
      set_unset_ip6_neighbor_rpc (vm, sw_if_index, a, link_layer_address,
                                  0 /* unset */, 0);
      return 0;
    }
#endif

  k.sw_if_index = sw_if_index;
  k.ip6_address = a[0];
  k.pad = 0;
  
  vlib_worker_thread_barrier_sync (vm);
  
  p = mhash_get (&nm->neighbor_index_by_key, &k);
  if (p == 0)
    {
      rv = -1;
      goto out;
    }
  
  n = pool_elt_at_index (nm->neighbor_pool, p[0]);
  mhash_unset (&nm->neighbor_index_by_key, &n->key, 0);
  pool_put (nm->neighbor_pool, n);
  
  args.table_index_or_table_id = im->fib_index_by_sw_if_index[sw_if_index];
  args.flags = IP6_ROUTE_FLAG_FIB_INDEX | IP6_ROUTE_FLAG_DEL 
    | IP6_ROUTE_FLAG_NEIGHBOR;
  args.dst_address = a[0];
  args.dst_address_length = 128;
  args.adj_index = ~0;
  args.add_adj = NULL;
  args.n_add_adj = 0;
  ip6_add_del_route (im, &args);
 out:
  vlib_worker_thread_barrier_release(vm);
  return rv;
}


u32
vnet_ip6_neighbor_glean_add(u32 fib_index, void * next_hop_arg)
{
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  ip6_address_t * next_hop = next_hop_arg;
  ip_adjacency_t add_adj, *adj;
  ip6_add_del_route_args_t args;
  ip6_neighbor_t * n;
  ip6_neighbor_key_t k;
  u32 adj_index;

  adj_index = ip6_fib_lookup_with_table(im, fib_index, next_hop);
  adj = ip_get_adjacency(lm, adj_index);

  if (!adj || adj->lookup_next_index != IP_LOOKUP_NEXT_ARP)
    return ~0;

  if (adj->arp.next_hop.ip6.as_u64[0] ||
      adj->arp.next_hop.ip6.as_u64[1])
    return adj_index;

  k.sw_if_index = adj->rewrite_header.sw_if_index;
  k.ip6_address = *next_hop;
  k.pad = 0;
  if (mhash_get (&nm->neighbor_index_by_key, &k))
    return adj_index;

  pool_get (nm->neighbor_pool, n);
  mhash_set (&nm->neighbor_index_by_key, &k, n - nm->neighbor_pool, /* old value */ 0);
  n->key = k;
  n->cpu_time_last_updated = clib_cpu_time_now ();
  n->flags = IP6_NEIGHBOR_FLAG_GLEAN;

  memset(&args, 0, sizeof(args));
  memcpy(&add_adj, adj, sizeof(add_adj));
  add_adj.arp.next_hop.ip6 = *next_hop; /* install neighbor /128 route */
  args.table_index_or_table_id = fib_index;
  args.flags = IP6_ROUTE_FLAG_FIB_INDEX | IP6_ROUTE_FLAG_ADD | IP6_ROUTE_FLAG_NEIGHBOR;
  args.dst_address = *next_hop;
  args.dst_address_length = 128;
  args.adj_index = ~0;
  args.add_adj = &add_adj;
  args.n_add_adj = 1;
  ip6_add_del_route (im, &args);
  return ip6_fib_lookup_with_table (im, fib_index, next_hop);
}

#if DPDK > 0
static void ip6_neighbor_set_unset_rpc_callback 
( ip6_neighbor_set_unset_rpc_args_t * a)
{
  vlib_main_t * vm = vlib_get_main();
  if (a->is_add) 
      vnet_set_ip6_ethernet_neighbor (vm, a->sw_if_index, &a->addr, 
                                      a->link_layer_address, 6, a->is_static);
  else
    vnet_unset_ip6_ethernet_neighbor (vm, a->sw_if_index, &a->addr, 
                                      a->link_layer_address, 6);
}
#endif

static int
ip6_neighbor_sort (void *a1, void *a2)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_neighbor_t * n1 = a1, * n2 = a2;
  int cmp;
  cmp = vnet_sw_interface_compare (vnm, n1->key.sw_if_index, 
                                   n2->key.sw_if_index);
  if (! cmp)
    cmp = ip6_address_compare (&n1->key.ip6_address, &n2->key.ip6_address);
  return cmp;
}

static clib_error_t *
show_ip6_neighbors (vlib_main_t * vm,
		    unformat_input_t * input,
		    vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  ip6_neighbor_t * n, * ns;
  clib_error_t * error = 0;
  u32 sw_if_index;

  /* Filter entries by interface if given. */
  sw_if_index = ~0;
  (void) unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index);

  ns = 0;
  pool_foreach (n, nm->neighbor_pool, ({ vec_add1 (ns, n[0]); }));
  vec_sort_with_function (ns, ip6_neighbor_sort);
  vlib_cli_output (vm, "%U", format_ip6_neighbor_ip6_entry, vm, 0);
  vec_foreach (n, ns) {
    if (sw_if_index != ~0 && n->key.sw_if_index != sw_if_index)
      continue;
    vlib_cli_output (vm, "%U", format_ip6_neighbor_ip6_entry, vm, n);
  }
  vec_free (ns);

  return error;
}

VLIB_CLI_COMMAND (show_ip6_neighbors_command, static) = {
  .path = "show ip6 neighbors",
  .function = show_ip6_neighbors,
  .short_help = "Show ip6 neighbors",
};

static clib_error_t *
set_ip6_neighbor (vlib_main_t * vm,
                  unformat_input_t * input,
                  vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_address_t addr;
  u8 mac_address[6];
  int addr_valid = 0;
  int is_del = 0;
  int is_static = 0;
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
      else
        break;
    }

  if (!addr_valid)
    return clib_error_return (0, "Missing interface, ip6 or hw address");
  
  if (!is_del)
    vnet_set_ip6_ethernet_neighbor (vm, sw_if_index, &addr,
                                    mac_address, sizeof(mac_address), is_static);
  else
    vnet_unset_ip6_ethernet_neighbor (vm, sw_if_index, &addr,
                                      mac_address, sizeof(mac_address));
  return 0;
}

VLIB_CLI_COMMAND (set_ip6_neighbor_command, static) = {
  .path = "set ip6 neighbor",
  .function = set_ip6_neighbor,
  .short_help = "set ip6 neighbor [del] <intfc> <ip6-address> <mac-address> [static]",
};

typedef enum {
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
  vnet_main_t * vnm = vnet_get_main();
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  uword n_packets = frame->n_vectors;
  u32 * from, * to_next;
  u32 n_left_from, n_left_to_next, next_index, n_advertisements_sent;
  icmp6_neighbor_discovery_option_type_t option_type;
  vlib_node_runtime_t * error_node = vlib_node_get_runtime (vm, ip6_icmp_input_node.index);
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
	  vlib_buffer_t * p0;
	  ip6_header_t * ip0;
	  icmp6_neighbor_solicitation_or_advertisement_header_t * h0;
	  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t * o0;
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
	  options_len0 = clib_net_to_host_u16 (ip0->payload_length) - sizeof (h0[0]);

	  error0 = ICMP6_ERROR_NONE;
	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];
          ip6_sadd_link_local = ip6_address_is_link_local_unicast(&ip0->src_address);
          ip6_sadd_unspecified = ip6_address_is_unspecified (&ip0->src_address);

	  /* Check that source address is unspecified, link-local or else on-link. */
	  if (!ip6_sadd_unspecified && !ip6_sadd_link_local)
	    {
	      u32 src_adj_index0 = ip6_src_lookup_for_packet (im, p0, ip0);
	      ip_adjacency_t * adj0 = ip_get_adjacency (&im->lookup_main, src_adj_index0);

              /* Allow all realistic-looking rewrite adjacencies to pass */
              ni0 = adj0->lookup_next_index;
              is_rewrite0 = (ni0 >= IP_LOOKUP_NEXT_ARP) &&
                (ni0 < IP6_LOOKUP_N_NEXT);

	      error0 = ((adj0->rewrite_header.sw_if_index != sw_if_index0
                         || ! is_rewrite0)
			? ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_NOT_ON_LINK
			: error0);
            }
	      
	  o0 = (void *) (h0 + 1);
	  o0 = ((options_len0 == 8 && o0->header.type == option_type
		 && o0->header.n_data_u64s == 1) ? o0 : 0);

	  /* If src address unspecified or link local, donot learn neighbor MAC */
	  if (PREDICT_TRUE (error0 == ICMP6_ERROR_NONE && o0 != 0 && 
                            !ip6_sadd_unspecified && !ip6_sadd_link_local)) 
            { 
              ip6_neighbor_main_t * nm = &ip6_neighbor_main;
              if (nm->limit_neighbor_cache_size && 
                  pool_elts (nm->neighbor_pool) >= nm->limit_neighbor_cache_size)
                  unset_random_neighbor_entry();
              vnet_set_ip6_ethernet_neighbor (
                  vm, sw_if_index0,
                  is_solicitation ? &ip0->src_address : &h0->target_address,
                  o0->ethernet_address, sizeof (o0->ethernet_address), 0);
            }

	  if (is_solicitation && error0 == ICMP6_ERROR_NONE)
	    {
	      /* Check that target address is one that we know about. */
	      ip_interface_address_t * ia0;
	      ip6_address_fib_t ip6_af0;
              void * oldheap;

	      ip6_addr_fib_init (&ip6_af0, &h0->target_address,
				 vec_elt (im->fib_index_by_sw_if_index,
					  sw_if_index0));

              /* Gross kludge, "thank you" MJ, don't even ask */
              oldheap = clib_mem_set_heap (clib_per_cpu_mheaps[0]);
	      ia0 = ip_get_interface_address (lm, &ip6_af0);
              clib_mem_set_heap (oldheap);
	      error0 = ia0 == 0 ? 
                  ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_UNKNOWN : error0;
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
	      vnet_sw_interface_t * sw_if0;
	      ethernet_interface_t * eth_if0;
              ethernet_header_t *eth0;

	      /* dst address is either source address or the all-nodes mcast addr */		      
	      if(!ip6_sadd_unspecified)
		  ip0->dst_address = ip0->src_address;
	      else
		  ip6_set_reserved_multicast_address(&ip0->dst_address, 
						     IP6_MULTICAST_SCOPE_link_local,
						     IP6_MULTICAST_GROUP_ID_all_hosts);

	      ip0->src_address = h0->target_address;
              ip0->hop_limit = 255;
	      h0->icmp.type = ICMP6_neighbor_advertisement;

	      sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index0);
	      ASSERT (sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
	      eth_if0 = ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);
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
              ASSERT(bogus_length == 0);

              /* Reuse current MAC header, copy SMAC to DMAC and 
               * interface MAC to SMAC */
              vlib_buffer_advance(p0, - ethernet_buffer_header_size(p0));
              eth0 = vlib_buffer_get_current(p0);
              clib_memcpy(eth0->dst_address, eth0->src_address, 6);
              clib_memcpy(eth0->src_address, eth_if0->address, 6);

              /* Setup input and output sw_if_index for packet */
              ASSERT(vnet_buffer(p0)->sw_if_index[VLIB_RX] == sw_if_index0);
              vnet_buffer(p0)->sw_if_index[VLIB_TX] = sw_if_index0;
              vnet_buffer(p0)->sw_if_index[VLIB_RX] = 
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
  vlib_error_count (vm, error_node->node_index, ICMP6_ERROR_NEIGHBOR_ADVERTISEMENTS_TX, n_advertisements_sent);

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

typedef enum {
#define _(f,s) LOG_##f,
  foreach_log_level
#undef _
} log_level_t;

static char * log_level_strings[] = {
#define _(f,s) s,
  foreach_log_level
#undef _
};

static  int logmask = 1 << LOG_DEBUG;

static void
ip6_neighbor_syslog(vlib_main_t *vm,  int priority,  char * fmt, ...)
{
  /* just use elog for now */
  u8 *what;
  va_list va;

  if( (priority > LOG_EMERG) ||
      !(logmask & (1 << priority)))
      return;

  va_start (va, fmt);
  if(fmt)
    {
      what = va_format (0, fmt, &va);

      ELOG_TYPE_DECLARE (e) = {
	.format = "ip6 nd:  (%s): %s",
	.format_args = "T4T4",
      };
      struct { u32 s[2]; } * ed;
      ed = ELOG_DATA (&vm->elog_main, e);
      ed->s[0] = elog_string(&vm->elog_main,  log_level_strings[priority]);
      ed->s[1] = elog_string(&vm->elog_main,  (char *)what);
    }
  va_end (va);
  return;
}

/* ipv6 neighbor discovery - router advertisements */
typedef enum {
  ICMP6_ROUTER_SOLICITATION_NEXT_DROP,
  ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_RW,
  ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_TX,
  ICMP6_ROUTER_SOLICITATION_N_NEXT,
} icmp6_router_solicitation_or_advertisement_next_t;

static_always_inline uword
icmp6_router_solicitation(vlib_main_t * vm,
			  vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_main_t * im = &ip6_main;
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  uword n_packets = frame->n_vectors;
  u32 * from, * to_next;
  u32 n_left_from, n_left_to_next, next_index;
  u32  n_advertisements_sent = 0;
  int bogus_length;

  icmp6_neighbor_discovery_option_type_t option_type;

  vlib_node_runtime_t * error_node = vlib_node_get_runtime (vm, ip6_icmp_input_node.index);

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
	  vlib_buffer_t * p0;
	  ip6_header_t * ip0;
	  ip6_radv_t *radv_info = 0;

	  icmp6_neighbor_discovery_header_t * h0;  
	  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t * o0;
	  
	  u32 bi0, options_len0, sw_if_index0, next0, error0;
	  u32 is_solicitation = 1, is_dropped  = 0;
          u32 is_unspecified, is_link_local;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
      
	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  h0 = ip6_next_header (ip0);
	  options_len0 = clib_net_to_host_u16 (ip0->payload_length) - sizeof (h0[0]);
          is_unspecified = ip6_address_is_unspecified (&ip0->src_address);
          is_link_local = ip6_address_is_link_local_unicast (&ip0->src_address);

	  error0 = ICMP6_ERROR_NONE;
	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];
	  
	  /* check if solicitation  (not from nd_timer node) */
	  if (ip6_address_is_unspecified (&ip0->dst_address))
	    is_solicitation = 0;

	  /* Check that source address is unspecified, link-local or else on-link. */
	  if (!is_unspecified && !is_link_local)
	    {
	      u32 src_adj_index0 = ip6_src_lookup_for_packet (im, p0, ip0);
	      ip_adjacency_t * adj0 = ip_get_adjacency (&im->lookup_main, src_adj_index0);

	      error0 = ((adj0->rewrite_header.sw_if_index != sw_if_index0
                         || (adj0->lookup_next_index != IP_LOOKUP_NEXT_ARP
                             && adj0->lookup_next_index != IP_LOOKUP_NEXT_REWRITE))
			? ICMP6_ERROR_ROUTER_SOLICITATION_SOURCE_NOT_ON_LINK
			: error0);
	  }
	  
	  /* check for source LL option and process */
	  o0 = (void *) (h0 + 1);
	  o0 = ((options_len0 == 8
		 && o0->header.type == option_type
		 && o0->header.n_data_u64s == 1)
		? o0
		: 0);
	  	      
	  /* if src address unspecified IGNORE any options */
	  if (PREDICT_TRUE (error0 == ICMP6_ERROR_NONE && o0 != 0 && 
                            !is_unspecified && !is_link_local)) {
              ip6_neighbor_main_t * nm = &ip6_neighbor_main;
              if (nm->limit_neighbor_cache_size && 
                  pool_elts (nm->neighbor_pool) >= nm->limit_neighbor_cache_size)
                      unset_random_neighbor_entry();
              
              vnet_set_ip6_ethernet_neighbor (vm, sw_if_index0,
                                              &ip0->src_address,
                                              o0->ethernet_address,
                                              sizeof (o0->ethernet_address), 0);
          }
	      
	  /* default is to drop */
	  next0 = ICMP6_ROUTER_SOLICITATION_NEXT_DROP;
	  
	  if (error0 == ICMP6_ERROR_NONE)
	    {
	      vnet_sw_interface_t * sw_if0;
	      ethernet_interface_t * eth_if0;
              u32 adj_index0;

	      sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index0);
	      ASSERT (sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
	      eth_if0 = ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);

	      /* only support ethernet interface type for now */
	      error0 = (!eth_if0) ?  ICMP6_ERROR_ROUTER_SOLICITATION_UNSUPPORTED_INTF : error0;

	      if (error0 == ICMP6_ERROR_NONE)
		{
		  u32 ri;

		  /* adjust the sizeof the buffer to just include the ipv6 header */
		  p0->current_length -= (options_len0 + sizeof(icmp6_neighbor_discovery_header_t));

		  /* look up the radv_t information for this interface */
		  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index0, ~0);

		  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index0];

		  if(ri != ~0)
		      radv_info = pool_elt_at_index (nm->if_radv_pool, ri);
			
		  error0 = ((!radv_info) ?  ICMP6_ERROR_ROUTER_SOLICITATION_RADV_NOT_CONFIG : error0);

		  if (error0 == ICMP6_ERROR_NONE)
		    {
		      f64 now = vlib_time_now (vm);

		      /* for solicited adverts - need to rate limit */
		      if(is_solicitation)
			{
			  if( (now - radv_info->last_radv_time)  <  MIN_DELAY_BETWEEN_RAS )
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
		      rh.router_lifetime_in_sec = clib_host_to_net_u16(radv_info->adv_router_lifetime_in_sec);
		      rh.time_in_msec_between_retransmitted_neighbor_solicitations = 
			clib_host_to_net_u32(radv_info->adv_time_in_msec_between_retransmitted_neighbor_solicitations);
		      rh.neighbor_reachable_time_in_msec = 
			clib_host_to_net_u32(radv_info->adv_neighbor_reachable_time_in_msec);
		      
		      rh.flags = (radv_info->adv_managed_flag) ? ICMP6_ROUTER_DISCOVERY_FLAG_ADDRESS_CONFIG_VIA_DHCP : 0;
		      rh.flags |= ( (radv_info->adv_other_flag) ? ICMP6_ROUTER_DISCOVERY_FLAG_OTHER_CONFIG_VIA_DHCP : 0);


		      u16 payload_length = sizeof(icmp6_router_advertisement_header_t);

		      vlib_buffer_add_data (vm,
					    p0->free_list_index,
					    bi0,
					    (void *)&rh, sizeof(icmp6_router_advertisement_header_t));

		      if(radv_info->adv_link_layer_address)
			{
			  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t h;

			  h.header.type = ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address;
			  h.header.n_data_u64s = 1;

			  /* copy ll address */
			  clib_memcpy(&h.ethernet_address[0], eth_if0->address,  6);

			  vlib_buffer_add_data (vm,
						p0->free_list_index,
						bi0,
						(void *)&h, sizeof(icmp6_neighbor_discovery_ethernet_link_layer_address_option_t));

			  payload_length += sizeof(icmp6_neighbor_discovery_ethernet_link_layer_address_option_t);
			}
		      
		      /* add MTU option */
		      if(radv_info->adv_link_mtu)
			{
			  icmp6_neighbor_discovery_mtu_option_t h;

			  h.unused = 0;
			  h.mtu =  clib_host_to_net_u32(radv_info->adv_link_mtu);
			  h.header.type = ICMP6_NEIGHBOR_DISCOVERY_OPTION_mtu;
			  h.header.n_data_u64s = 1;
			  
			  payload_length += sizeof( icmp6_neighbor_discovery_mtu_option_t);

			  vlib_buffer_add_data (vm,
						p0->free_list_index,
						bi0,
						(void *)&h, sizeof(icmp6_neighbor_discovery_mtu_option_t));
			}
		      
		      /* add advertised prefix options  */
		      ip6_radv_prefix_t *pr_info; 

		      pool_foreach (pr_info, radv_info->adv_prefixes_pool, ({

			    if(pr_info->enabled &&
			       (!pr_info->decrement_lifetime_flag  || (pr_info->pref_lifetime_expires >0)))
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
						      p0->free_list_index,
						      bi0,
						      (void *)&h, sizeof(icmp6_neighbor_discovery_prefix_information_option_t));

			      } 
			  }));

		      /* add additional options before here */

		      /* finish building the router advertisement... */
		      if(!is_unspecified && radv_info->send_unicast)
			{
			  ip0->dst_address = ip0->src_address;
			}
		      else
			{			      
			  /* target address is all-nodes mcast addr */ 
			  ip6_set_reserved_multicast_address(&ip0->dst_address, 
							     IP6_MULTICAST_SCOPE_link_local,
							     IP6_MULTICAST_GROUP_ID_all_hosts);
			}
		      
		      /* source address MUST be the link-local address */
		      ip0->src_address = radv_info->link_local_address;
		      
		      ip0->hop_limit = 255;
		      ip0->payload_length = clib_host_to_net_u16 (payload_length);

		      icmp6_router_advertisement_header_t * rh0 = (icmp6_router_advertisement_header_t *)(ip0 + 1);
		      rh0->icmp.checksum = 
                          ip6_tcp_udp_icmp_compute_checksum (vm, p0, ip0, 
                                                             &bogus_length);
                      ASSERT(bogus_length == 0);
		      
		      /* setup output if and adjacency */
		      vnet_buffer (p0)->sw_if_index[VLIB_RX] = 
			vnet_main.local_interface_sw_if_index;
		      
                      if (is_solicitation) 
                        {
                          ethernet_header_t *eth0;
                          /* Reuse current MAC header, copy SMAC to DMAC and 
                           * interface MAC to SMAC */
                          vlib_buffer_reset (p0);
                          eth0 = vlib_buffer_get_current(p0);
                          clib_memcpy(eth0->dst_address, eth0->src_address, 6);
                          clib_memcpy(eth0->src_address, eth_if0->address, 6);
			  next0 = is_dropped ? 
                              next0 : ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_TX;
                          vnet_buffer(p0)->sw_if_index[VLIB_TX] = sw_if_index0;
                        }
                      else 
                        {
                          adj_index0 = radv_info->all_nodes_adj_index;
                          if (adj_index0 == 0)
                              error0 = ICMP6_ERROR_DST_LOOKUP_MISS;
                          else
                            {
                              ip_adjacency_t * adj0 = ip_get_adjacency (&im->lookup_main, adj_index0);
                              error0 = 
                                  ((adj0->rewrite_header.sw_if_index != sw_if_index0
                                    || adj0->lookup_next_index != IP_LOOKUP_NEXT_REWRITE)
                                   ? ICMP6_ERROR_ROUTER_SOLICITATION_DEST_UNKNOWN
                                   : error0);
                              next0 = is_dropped ? 
                                  next0 : ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_RW;
                              vnet_buffer (p0)->ip.adj_index[VLIB_RX] = adj_index0;
                           }
                        }
		      
		      radv_info->n_solicitations_dropped  += is_dropped;
		      radv_info->n_solicitations_rcvd  += is_solicitation;
		      
		      if((error0 ==  ICMP6_ERROR_NONE) && !is_dropped)
			{
			  radv_info->n_advertisements_sent++;
			  n_advertisements_sent++;
			}
		    }
		}
	    }

	  p0->error = error_node->errors[error0];

	  if(error0 != ICMP6_ERROR_NONE)
	    vlib_error_count (vm, error_node->node_index, error0, 1);
	  
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	  
	}
      
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Account for router advertisements sent. */
  vlib_error_count (vm, error_node->node_index, ICMP6_ERROR_ROUTER_ADVERTISEMENTS_TX, n_advertisements_sent);

  return frame->n_vectors;
}

 /* validate advertised info for consistancy (see RFC-4861 section 6.2.7) - log any inconsistencies, packet will always  be dropped  */
static_always_inline uword
icmp6_router_advertisement(vlib_main_t * vm,
			   vlib_node_runtime_t * node,
			   vlib_frame_t * frame)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  uword n_packets = frame->n_vectors;
  u32 * from, * to_next;
  u32 n_left_from, n_left_to_next, next_index;
  u32 n_advertisements_rcvd = 0;

  vlib_node_runtime_t * error_node = vlib_node_get_runtime (vm, ip6_icmp_input_node.index);

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
	  vlib_buffer_t * p0;
	  ip6_header_t * ip0;
	  ip6_radv_t *radv_info = 0;
	  icmp6_router_advertisement_header_t * h0;  
	  u32 bi0, options_len0, sw_if_index0, next0, error0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
      
	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  h0 = ip6_next_header (ip0);
	  options_len0 = clib_net_to_host_u16 (ip0->payload_length) - sizeof (h0[0]);

	  error0 = ICMP6_ERROR_NONE;
	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];

	  /* Check that source address is link-local*/
	  error0 = (!ip6_address_is_link_local_unicast (&ip0->src_address)) ? 
	    ICMP6_ERROR_ROUTER_ADVERTISEMENT_SOURCE_NOT_LINK_LOCAL : error0;

	  /* default is to drop */
	  next0 = ICMP6_ROUTER_SOLICITATION_NEXT_DROP;
	  
	  n_advertisements_rcvd++;

	  if (error0 == ICMP6_ERROR_NONE)
	    {
	      vnet_sw_interface_t * sw_if0;
	      ethernet_interface_t * eth_if0;
    
	      sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index0);
	      ASSERT (sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
	      eth_if0 = ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);

	      /* only support ethernet interface type for now */
	      error0 = (!eth_if0) ?  ICMP6_ERROR_ROUTER_SOLICITATION_UNSUPPORTED_INTF : error0;

	      if (error0 == ICMP6_ERROR_NONE)
		{
		  u32 ri;

		  /* look up the radv_t information for this interface */
		  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index0, ~0);

		  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index0];

		  if(ri != ~0)
		      radv_info = pool_elt_at_index (nm->if_radv_pool, ri);
			
		  error0 = ((!radv_info) ?  ICMP6_ERROR_ROUTER_SOLICITATION_RADV_NOT_CONFIG : error0);

		  if (error0 == ICMP6_ERROR_NONE)
		    {
		      /* validate advertised information */
		      if((h0->current_hop_limit && radv_info->curr_hop_limit) &&
			 (h0->current_hop_limit != radv_info->curr_hop_limit))
			{
			  ip6_neighbor_syslog(vm,  LOG_WARNING,  
					      "our AdvCurHopLimit on %U doesn't agree with %U", 
					      format_vnet_sw_if_index_name, vnm, sw_if_index0, format_ip6_address, &ip0->src_address);
			}

		      if((h0->flags &  ICMP6_ROUTER_DISCOVERY_FLAG_ADDRESS_CONFIG_VIA_DHCP)  != 
			 radv_info->adv_managed_flag)
			{
			  ip6_neighbor_syslog(vm,  LOG_WARNING,  
					      "our AdvManagedFlag on %U doesn't agree with %U", 
					      format_vnet_sw_if_index_name, vnm, sw_if_index0, format_ip6_address, &ip0->src_address);
			}

		      if((h0->flags &   ICMP6_ROUTER_DISCOVERY_FLAG_OTHER_CONFIG_VIA_DHCP)   != 
			 radv_info->adv_other_flag)
			{
			  ip6_neighbor_syslog(vm,  LOG_WARNING,  
					      "our AdvOtherConfigFlag on %U doesn't agree with %U", 
					      format_vnet_sw_if_index_name, vnm, sw_if_index0, format_ip6_address, &ip0->src_address);
			}

		      if((h0->time_in_msec_between_retransmitted_neighbor_solicitations && 
			  radv_info->adv_time_in_msec_between_retransmitted_neighbor_solicitations) &&
			 (h0->time_in_msec_between_retransmitted_neighbor_solicitations !=
			  clib_host_to_net_u32(radv_info->adv_time_in_msec_between_retransmitted_neighbor_solicitations)))
			{
			  ip6_neighbor_syslog(vm,  LOG_WARNING,  
					      "our AdvRetransTimer on %U doesn't agree with %U", 
					      format_vnet_sw_if_index_name, vnm, sw_if_index0, format_ip6_address, &ip0->src_address);
			}

		      if((h0->neighbor_reachable_time_in_msec && 
			  radv_info->adv_neighbor_reachable_time_in_msec) &&
			 (h0->neighbor_reachable_time_in_msec !=
			  clib_host_to_net_u32(radv_info->adv_neighbor_reachable_time_in_msec)))
			{
			  ip6_neighbor_syslog(vm,  LOG_WARNING,  
					      "our AdvReachableTime on %U doesn't agree with %U", 
					      format_vnet_sw_if_index_name, vnm, sw_if_index0, format_ip6_address, &ip0->src_address);
			}

		      /* check for MTU or prefix options or .. */
		      u8 * opt_hdr = (u8 *)(h0 + 1);
		      while( options_len0 > 0)
			{
			  icmp6_neighbor_discovery_option_header_t *o0 = ( icmp6_neighbor_discovery_option_header_t *)opt_hdr;
			  int opt_len = o0->n_data_u64s << 3;
			  icmp6_neighbor_discovery_option_type_t option_type = o0->type;

			  if(options_len0 < 2)
			    {
			      ip6_neighbor_syslog(vm,  LOG_ERR,  
						  "malformed RA packet on %U from %U", 
						  format_vnet_sw_if_index_name, vnm, sw_if_index0, format_ip6_address, &ip0->src_address);
			      break;
			    }

			  if(opt_len == 0)
			    {
			      ip6_neighbor_syslog(vm,  LOG_ERR,  
						  " zero length option in RA on %U from %U", 
						  format_vnet_sw_if_index_name, vnm, sw_if_index0, format_ip6_address, &ip0->src_address);
			      break;
			    }
			  else if( opt_len > options_len0)
			    {
			      ip6_neighbor_syslog(vm,  LOG_ERR,  
						  "option length in RA packet  greater than total length on %U from %U", 
						  format_vnet_sw_if_index_name, vnm, sw_if_index0, format_ip6_address, &ip0->src_address);
			      break;
			    }

			  options_len0 -= opt_len;
			  opt_hdr += opt_len;

			  switch(option_type)
			    {
			    case ICMP6_NEIGHBOR_DISCOVERY_OPTION_mtu:
			      {			      
				icmp6_neighbor_discovery_mtu_option_t *h =
				  (icmp6_neighbor_discovery_mtu_option_t *)(o0);

				if(opt_len < sizeof(*h))
				  break;

				if((h->mtu && radv_info->adv_link_mtu) &&
				   (h->mtu != clib_host_to_net_u32(radv_info->adv_link_mtu)))
				  {
				    ip6_neighbor_syslog(vm,  LOG_WARNING,  
							"our AdvLinkMTU on %U doesn't agree with %U", 
							format_vnet_sw_if_index_name, vnm, sw_if_index0, format_ip6_address, &ip0->src_address);
				  }
			      }
			      break;
			      
			    case ICMP6_NEIGHBOR_DISCOVERY_OPTION_prefix_information:
			      {
				icmp6_neighbor_discovery_prefix_information_option_t *h =
				  (icmp6_neighbor_discovery_prefix_information_option_t *)(o0);
			      
				/* validate advertised prefix options  */
				ip6_radv_prefix_t *pr_info; 
				u32 preferred, valid;

				if(opt_len < sizeof(*h))
				  break;

				preferred =  clib_net_to_host_u32(h->preferred_time);
				valid =  clib_net_to_host_u32(h->valid_time);

				/* look for matching prefix - if we our advertising it, it better be consistant */
				pool_foreach (pr_info, radv_info->adv_prefixes_pool, ({
				      
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
				break;
			      }
			    default:
			      /* skip this one */
			      break;
			    }
			}
		    }
		}
	    }

	  p0->error = error_node->errors[error0];

	  if(error0 != ICMP6_ERROR_NONE)
	    vlib_error_count (vm, error_node->node_index, error0, 1);
	  
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Account for router advertisements sent. */
  vlib_error_count (vm, error_node->node_index, ICMP6_ERROR_ROUTER_ADVERTISEMENTS_RX, n_advertisements_rcvd);

  return frame->n_vectors;
}

/* create and initialize router advertisement parameters with default values for this intfc */
static u32
ip6_neighbor_sw_interface_add_del (vnet_main_t * vnm,
				   u32 sw_if_index,
				   u32 is_add)
{
  ip6_main_t * im = &ip6_main;
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;  
  ip_lookup_main_t * lm = &im->lookup_main;
  ip6_radv_t * a= 0;  
  u32 ri = ~0;;
  vnet_sw_interface_t * sw_if0;
  ethernet_interface_t * eth_if0 = 0; 

  /* lookup radv container  - ethernet interfaces only */
  sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index);
  if(sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
    eth_if0 = ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);

  if(!eth_if0)
    return ri;
   
  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index, ~0);
  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];

  if(ri != ~0)
    {
      a = pool_elt_at_index (nm->if_radv_pool, ri);

      if(!is_add)
	{
	  u32 i, * to_delete = 0;
	  ip6_radv_prefix_t  *p;
	  ip6_mldp_group_t *m;
	  
	  /* remove adjacencies */
	  ip_del_adjacency (lm,  a->all_nodes_adj_index); 
	  ip_del_adjacency (lm,  a->all_routers_adj_index);	      
	  ip_del_adjacency (lm,  a->all_mldv2_routers_adj_index);	      
	  
	  /* clean up prefix_pool */
	  pool_foreach (p, a->adv_prefixes_pool, ({
		vec_add1 (to_delete, p  -  a->adv_prefixes_pool);
	      }));
	  
	  for (i = 0; i < vec_len (to_delete); i++)
	    {
	      p = pool_elt_at_index (a->adv_prefixes_pool, to_delete[i]);
	      mhash_unset (&a->address_to_prefix_index, &p->prefix, 0);
	      pool_put (a->adv_prefixes_pool, p);
	    }
	  
	  vec_free (to_delete);
	  to_delete = 0;
	  
	  /* clean up mldp group pool */
	  pool_foreach (m, a->mldp_group_pool, ({
		vec_add1 (to_delete, m  -  a->mldp_group_pool);
	      }));
	  
	  for (i = 0; i < vec_len (to_delete); i++)
	    {
	      m = pool_elt_at_index (a->mldp_group_pool, to_delete[i]);
	      mhash_unset (&a->address_to_mldp_index, &m->mcast_address, 0);
	      pool_put (a->mldp_group_pool, m);
	    }
	  
	  vec_free (to_delete);
	  
	  pool_put (nm->if_radv_pool,  a);
	  nm->if_radv_pool_index_by_sw_if_index[sw_if_index] = ~0;
	  ri = ~0;
	}
    }
 else
   {
     if(is_add)
       {
	 vnet_hw_interface_t * hw_if0;
     
	 hw_if0 = vnet_get_sup_hw_interface (vnm, sw_if_index);
	 
	 pool_get (nm->if_radv_pool, a);
	 
	 ri = a - nm->if_radv_pool;
	 nm->if_radv_pool_index_by_sw_if_index[sw_if_index] = ri;
	 
	 /* initialize default values (most of which are zero) */
	 memset (a, 0, sizeof (a[0]));
	 
	 a->sw_if_index = sw_if_index;
	 a->fib_index = ~0;
	 a->max_radv_interval = DEF_MAX_RADV_INTERVAL;    
	 a->min_radv_interval =  DEF_MIN_RADV_INTERVAL;    
	 a->curr_hop_limit = DEF_CURR_HOP_LIMIT;                         
	 a->adv_router_lifetime_in_sec = DEF_DEF_RTR_LIFETIME;   
	 
	 a->adv_link_layer_address = 1;  /* send ll address source address option */
	 
	 a->min_delay_between_radv = MIN_DELAY_BETWEEN_RAS;
	 a->max_delay_between_radv = MAX_DELAY_BETWEEN_RAS;
	 a->max_rtr_default_lifetime = MAX_DEF_RTR_LIFETIME;
	 a->seed = random_default_seed();
	 
	 /* for generating random interface ids */
	 a->randomizer = 0x1119194911191949;
	 a->randomizer = random_u64 ((u32 *)&a->randomizer);
	 
	 a->initial_adverts_count = MAX_INITIAL_RTR_ADVERTISEMENTS ; 
	 a->initial_adverts_sent = a->initial_adverts_count-1;
	 a->initial_adverts_interval = MAX_INITIAL_RTR_ADVERT_INTERVAL;      
	 
	 /* deafult is to send */
	 a->send_radv = 1;
	 
	 /* fill in radv_info for this interface that will be needed later */
	 a->adv_link_mtu = hw_if0->max_l3_packet_bytes[VLIB_RX];
	 
	 clib_memcpy (a->link_layer_address, eth_if0->address, 6);
	 
	 /* fill in default link-local address  (this may be overridden) */
	 ip6_link_local_address_from_ethernet_address (&a->link_local_address, eth_if0->address);
	 a->link_local_prefix_len = 64;

	 mhash_init (&a->address_to_prefix_index, sizeof (uword), sizeof (ip6_address_t));
	 mhash_init (&a->address_to_mldp_index, sizeof (uword), sizeof (ip6_address_t)); 
	 
	 {
	   ip_adjacency_t *adj;
	   u8 link_layer_address[6] = 
	     {0x33, 0x33, 0x00, 0x00, 0x00, IP6_MULTICAST_GROUP_ID_all_hosts};
	   
	   adj = ip_add_adjacency (lm, /* template */ 0, /* block size */ 1,
				   &a->all_nodes_adj_index);
	   
	   adj->lookup_next_index = IP_LOOKUP_NEXT_REWRITE;
	   adj->if_address_index = ~0;
	   
	   vnet_rewrite_for_sw_interface
	     (vnm,
	      VNET_L3_PACKET_TYPE_IP6,
	      sw_if_index,
	      ip6_rewrite_node.index,
	      link_layer_address,
	      &adj->rewrite_header,
	      sizeof (adj->rewrite_data));
	 } 
	 
	 {
	   ip_adjacency_t *adj;
	   u8 link_layer_address[6] = 
	     {0x33, 0x33, 0x00, 0x00, 0x00, IP6_MULTICAST_GROUP_ID_all_routers};
	
	   adj = ip_add_adjacency (lm, /* template */ 0, /* block size */ 1,
				   &a->all_routers_adj_index);
	   
	   adj->lookup_next_index = IP_LOOKUP_NEXT_REWRITE;
	   adj->if_address_index = ~0;
	   
	   vnet_rewrite_for_sw_interface
	     (vnm,
	      VNET_L3_PACKET_TYPE_IP6,
	      sw_if_index,
	      ip6_rewrite_node.index,
	      link_layer_address,
	      &adj->rewrite_header,
	      sizeof (adj->rewrite_data));
	 } 
	 
	 {
	   ip_adjacency_t *adj;
	   u8 link_layer_address[6] = 
	     {0x33, 0x33, 0x00, 0x00, 0x00, IP6_MULTICAST_GROUP_ID_mldv2_routers};
	   
	   adj = ip_add_adjacency (lm, /* template */ 0, /* block size */ 1,
				   &a->all_mldv2_routers_adj_index);
	   
	   adj->lookup_next_index = IP_LOOKUP_NEXT_REWRITE;
	   adj->if_address_index = ~0;
	   
	   vnet_rewrite_for_sw_interface
	     (vnm,
	      VNET_L3_PACKET_TYPE_IP6,
	      sw_if_index,
	      ip6_rewrite_node.index,
	      link_layer_address,
	      &adj->rewrite_header,
	      sizeof (adj->rewrite_data));
	 } 
	 
	 /* add multicast groups we will always be reporting  */
	 ip6_address_t addr;
	 ip6_mldp_group_t  *mcast_group_info;
	 
	 ip6_set_reserved_multicast_address (&addr,
					     IP6_MULTICAST_SCOPE_link_local,
					     IP6_MULTICAST_GROUP_ID_all_hosts);
	 
	 /* lookup  mldp info for this interface */
	 
	 uword * p = mhash_get (&a->address_to_mldp_index,  &addr);
	 mcast_group_info = p ? pool_elt_at_index (a->mldp_group_pool, p[0]) : 0;
	 
	 /* add address */
	 if(!mcast_group_info)
	   {
	     /* add */
	     u32 mi;
	     pool_get (a->mldp_group_pool, mcast_group_info);
	  
	     mi = mcast_group_info - a->mldp_group_pool;
	     mhash_set (&a->address_to_mldp_index,  &addr,  mi, /* old_value */ 0);
	     
	     mcast_group_info->type = 4;
	     mcast_group_info->mcast_source_address_pool = 0;
	     mcast_group_info->num_sources = 0;
	     clib_memcpy(&mcast_group_info->mcast_address, &addr, sizeof(ip6_address_t));
	   } 
	 
	 ip6_set_reserved_multicast_address (&addr,
					     IP6_MULTICAST_SCOPE_link_local,
					     IP6_MULTICAST_GROUP_ID_all_routers);
	 
	 p = mhash_get (&a->address_to_mldp_index,  &addr);
	 mcast_group_info = p ? pool_elt_at_index (a->mldp_group_pool, p[0]) : 0;
	 
	 if(!mcast_group_info)
	   {
	     /* add */
	     u32 mi;
	     pool_get (a->mldp_group_pool, mcast_group_info);
	     
	     mi = mcast_group_info - a->mldp_group_pool;
	     mhash_set (&a->address_to_mldp_index,  &addr,  mi, /* old_value */ 0);
	     
	     mcast_group_info->type = 4;
	     mcast_group_info->mcast_source_address_pool = 0;
	     mcast_group_info->num_sources = 0;
	     clib_memcpy(&mcast_group_info->mcast_address, &addr, sizeof(ip6_address_t));
	   } 
	 
	 ip6_set_reserved_multicast_address (&addr,
					     IP6_MULTICAST_SCOPE_link_local,
					     IP6_MULTICAST_GROUP_ID_mldv2_routers);
	 
	 p = mhash_get (&a->address_to_mldp_index,  &addr);
	 mcast_group_info = p ? pool_elt_at_index (a->mldp_group_pool, p[0]) : 0;
	 
	 if(!mcast_group_info)
	   {
	     /* add */
	     u32 mi;
	     pool_get (a->mldp_group_pool, mcast_group_info);
	     
	     mi = mcast_group_info - a->mldp_group_pool;
	     mhash_set (&a->address_to_mldp_index,  &addr,  mi, /* old_value */ 0);
	     
	     mcast_group_info->type = 4;
	     mcast_group_info->mcast_source_address_pool = 0;
	     mcast_group_info->num_sources = 0;
	     clib_memcpy(&mcast_group_info->mcast_address, &addr, sizeof(ip6_address_t));
	   } 
       }
   } 
  return  ri;
}

/* send an mldpv2 report  */
static void
ip6_neighbor_send_mldpv2_report(u32 sw_if_index)
{
  vnet_main_t * vnm = vnet_get_main();
  vlib_main_t * vm = vnm->vlib_main;
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  vnet_sw_interface_t * sw_if0;
  ethernet_interface_t * eth_if0;
  u32 ri;
  int bogus_length;

  ip6_radv_t *radv_info; 
  u16 payload_length;
  vlib_buffer_t * b0;
  ip6_header_t * ip0;
  u32 * to_next;
  vlib_frame_t * f;
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
  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index, ~0);
  
  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];
  
  if(ri == ~0)
    return;
	      	
  /* send report now - build a mldpv2 report packet  */
  n_allocated = vlib_buffer_alloc_from_free_list(vm, 
						 &bo0, 
						 n_to_alloc,
						 VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
  if (PREDICT_FALSE(n_allocated == 0))
    {
      clib_warning ("buffer allocation failure");
      return;
    }

  b0 = vlib_get_buffer (vm, bo0);

  /* adjust the sizeof the buffer to just include the ipv6 header */
  b0->current_length  = sizeof(icmp6_multicast_listener_report_packet_t);

  payload_length = sizeof(icmp6_multicast_listener_report_header_t);

  b0->error = ICMP6_ERROR_NONE;

  rp0 = vlib_buffer_get_current (b0);
  ip0 = (ip6_header_t *)&rp0-> ip;
  rh0 = (icmp6_multicast_listener_report_header_t *)&rp0-> report_hdr;
  
  memset (rp0 , 0x0, sizeof (icmp6_multicast_listener_report_packet_t));
  
  ip0->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (0x6 << 28);

  ip0->protocol = IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS;  
  /* for DEBUG - vnet driver won't seem to emit router alerts */
  /* ip0->protocol = IP_PROTOCOL_ICMP6; */
  ip0->hop_limit = 1;
 
  rh0->icmp.type = ICMP6_multicast_listener_report_v2;
  
  /* source address MUST be the link-local address */
  radv_info = pool_elt_at_index (nm->if_radv_pool,  ri);
  ip0->src_address = radv_info->link_local_address;  

  /* destination is all mldpv2 routers */
  ip6_set_reserved_multicast_address(&ip0->dst_address, 
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

  pool_foreach (m, radv_info->mldp_group_pool, ({

	rr.type = m->type;
	rr.aux_data_len_u32s = 0;
	rr.num_sources = clib_host_to_net_u16 (m->num_sources);
	clib_memcpy(&rr.mcast_addr, &m->mcast_address, sizeof(ip6_address_t));

	num_addr_records++;

	vlib_buffer_add_data (vm,
			      b0->free_list_index,
			      bo0,
			      (void *)&rr, sizeof(icmp6_multicast_address_record_t));
	
	payload_length += sizeof( icmp6_multicast_address_record_t);
      }));

  rh0->rsvd = 0;
  rh0->num_addr_records =  clib_host_to_net_u16(num_addr_records);
  
  /* update lengths */
  ip0->payload_length = clib_host_to_net_u16 (payload_length);

  rh0->icmp.checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip0, 
                                                          &bogus_length);
  ASSERT(bogus_length == 0);

  /* 
   * OK to override w/ no regard for actual FIB, because
   * ip6-rewrite-local only looks at the adjacency.
   */
  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 
    vnet_main.local_interface_sw_if_index;
  
  vnet_buffer (b0)->ip.adj_index[VLIB_RX]  = 
    radv_info->all_mldv2_routers_adj_index;

  vlib_node_t * node = vlib_get_node_by_name (vm, (u8 *) "ip6-rewrite-local");
  
  f = vlib_get_frame_to_node (vm, node->index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bo0;
  f->n_vectors = 1;
  
  vlib_put_frame_to_node (vm, node->index, f);
  return;
}

VLIB_REGISTER_NODE (ip6_icmp_router_solicitation_node,static) = {
  .function = icmp6_router_solicitation,
  .name = "icmp6-router-solicitation",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_next_nodes = ICMP6_ROUTER_SOLICITATION_N_NEXT,
  .next_nodes = {
    [ICMP6_ROUTER_SOLICITATION_NEXT_DROP] = "error-drop",
    [ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_RW] = "ip6-rewrite-local",
    [ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_TX] = "interface-output",
  },
};

/* send a RA or update the timer info etc.. */
static uword
ip6_neighbor_process_timer_event (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * frame)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  ip6_radv_t *radv_info; 
  vlib_frame_t * f = 0; 
  u32 n_this_frame = 0;
  u32 n_left_to_next = 0;
  u32 * to_next = 0;
  u32 bo0; 
  icmp6_router_solicitation_header_t * h0;
  vlib_buffer_t * b0;
  f64 now = vlib_time_now (vm);

  /* Interface ip6 radv info list */
  pool_foreach (radv_info, nm->if_radv_pool, ({

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
	    n_allocated = vlib_buffer_alloc_from_free_list(vm, 
							   &bo0, 
							   n_to_alloc,
							   VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
	    
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
	    
	    memset (h0, 0, sizeof (icmp6_router_solicitation_header_t));
	    
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

  if (f)
    {
      ASSERT(n_this_frame);
      f->n_vectors = n_this_frame;
      vlib_put_frame_to_node (vm, ip6_icmp_router_solicitation_node.index, f);
    }
  return  0;
}

static uword
ip6_icmp_neighbor_discovery_event_process (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * frame)
{
  uword event_type;
  ip6_icmp_neighbor_discovery_event_data_t * event_data;

  /* init code here */
 
  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm,  1. /* seconds */);

      event_data = vlib_process_get_event_data (vm,  &event_type);

      if(!event_data)
	{
	  /* No events found: timer expired. */
	  /* process interface list and send RAs as appropriate, update timer info */
	  ip6_neighbor_process_timer_event (vm,  node,  frame); 
	}
      else
	{
	  switch (event_type) {

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

VLIB_REGISTER_NODE (ip6_icmp_router_advertisement_node,static) = {
  .function = icmp6_router_advertisement,
  .name = "icmp6-router-advertisement",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

vlib_node_registration_t ip6_icmp_neighbor_discovery_event_node = {

  .function = ip6_icmp_neighbor_discovery_event_process,
  .name = "ip6-icmp-neighbor-discovery-event-process",
  .type = VLIB_NODE_TYPE_PROCESS,
};

static uword
icmp6_neighbor_solicitation (vlib_main_t * vm,
			     vlib_node_runtime_t * node,
			     vlib_frame_t * frame)
{ return icmp6_neighbor_solicitation_or_advertisement (vm, node, frame, /* is_solicitation */ 1); }

static uword
icmp6_neighbor_advertisement (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
{ return icmp6_neighbor_solicitation_or_advertisement (vm, node, frame, /* is_solicitation */ 0); }

VLIB_REGISTER_NODE (ip6_icmp_neighbor_solicitation_node,static) = {
  .function = icmp6_neighbor_solicitation,
  .name = "icmp6-neighbor-solicitation",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_next_nodes = ICMP6_NEIGHBOR_SOLICITATION_N_NEXT,
  .next_nodes = {
    [ICMP6_NEIGHBOR_SOLICITATION_NEXT_DROP] = "error-drop",
    [ICMP6_NEIGHBOR_SOLICITATION_NEXT_REPLY] = "interface-output",
  },
};

VLIB_REGISTER_NODE (ip6_icmp_neighbor_advertisement_node,static) = {
  .function = icmp6_neighbor_advertisement,
  .name = "icmp6-neighbor-advertisement",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

/* API  support functions */
int
ip6_neighbor_ra_config(vlib_main_t * vm, u32 sw_if_index, 
		       u8 suppress, u8 managed, u8 other,
		       u8 ll_option,  u8 send_unicast,  u8 cease, 
		       u8 use_lifetime,  u32 lifetime,
		       u32 initial_count,  u32 initial_interval,  
		       u32 max_interval,  u32 min_interval,
		       u8 is_no)
{
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  int  error;
  u32 ri;

  /* look up the radv_t  information for this interface */
  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index, ~0);
  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];
  error = (ri != ~0) ? 0 :  VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if(!error)
    {

      ip6_radv_t * radv_info;
      radv_info = pool_elt_at_index (nm->if_radv_pool,  ri);
  
      if((max_interval != 0) && (min_interval ==0))
	min_interval =  .75 * max_interval;

      max_interval  = (max_interval != 0) ? ( (is_no) ?  DEF_MAX_RADV_INTERVAL :  max_interval) :  radv_info->max_radv_interval;
      min_interval  = (min_interval != 0) ? ( (is_no) ?  DEF_MIN_RADV_INTERVAL :  min_interval) :  radv_info->min_radv_interval; 
      lifetime  = (use_lifetime != 0) ? ( (is_no) ?  DEF_DEF_RTR_LIFETIME :  lifetime) :  radv_info->adv_router_lifetime_in_sec;

      if(lifetime)
	{
	  if(lifetime  > MAX_DEF_RTR_LIFETIME)
	    lifetime = MAX_DEF_RTR_LIFETIME;
	  
	  if(lifetime <= max_interval)
            return VNET_API_ERROR_INVALID_VALUE;
	}
      
      if(min_interval  != 0)
	{
	  if((min_interval > .75 * max_interval) ||
	     (min_interval  < 3))
            return VNET_API_ERROR_INVALID_VALUE;
	}

      if((initial_count  > MAX_INITIAL_RTR_ADVERTISEMENTS) ||
	 (initial_interval  > MAX_INITIAL_RTR_ADVERT_INTERVAL))
        return VNET_API_ERROR_INVALID_VALUE;

      /* 
	 if "flag" is set and is_no is true then restore default value else set value corresponding to "flag" 
	 if "flag" is clear  don't change corresponding value  
      */
      radv_info->send_radv =  (suppress != 0) ? ( (is_no  != 0) ? 1 : 0 ) : radv_info->send_radv;
      radv_info->adv_managed_flag = ( managed  != 0) ? ( (is_no) ? 0 : 1) : radv_info->adv_managed_flag;
      radv_info->adv_other_flag  = (other  != 0) ? ( (is_no) ?  0: 1) : radv_info->adv_other_flag;
      radv_info->adv_link_layer_address = ( ll_option != 0) ? ( (is_no) ? 1 : 0) : radv_info->adv_link_layer_address;
      radv_info->send_unicast  = (send_unicast  != 0) ? ( (is_no) ? 0 : 1) : radv_info->send_unicast;
      radv_info->cease_radv = ( cease != 0) ? ( (is_no) ?  0 : 1) : radv_info->cease_radv;
      
      radv_info->min_radv_interval  =  min_interval;
      radv_info->max_radv_interval = max_interval;
      radv_info->adv_router_lifetime_in_sec = lifetime;

      radv_info->initial_adverts_count = 
	(initial_count  != 0) ? ( (is_no) ?   MAX_INITIAL_RTR_ADVERTISEMENTS  :  initial_count) : radv_info->initial_adverts_count ;
      radv_info->initial_adverts_interval = 
	(initial_interval  != 0) ? ( (is_no) ?  MAX_INITIAL_RTR_ADVERT_INTERVAL  :  initial_interval) : radv_info->initial_adverts_interval;

      /* restart */
      if((cease != 0) && (is_no))
	 radv_info-> send_radv = 1;

      radv_info->initial_adverts_sent  = radv_info->initial_adverts_count -1;
      radv_info->next_multicast_time =  vlib_time_now (vm);    
      radv_info->last_multicast_time = vlib_time_now (vm);
      radv_info->last_radv_time = 0;	
    }
  return(error);
}

int
ip6_neighbor_ra_prefix(vlib_main_t * vm, u32 sw_if_index,  
		       ip6_address_t *prefix_addr,  u8 prefix_len,
		       u8 use_default,  u32 val_lifetime, u32 pref_lifetime,
		       u8 no_advertise,  u8 off_link, u8 no_autoconfig, u8 no_onlink,
		       u8 is_no)
{
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  int error;
  
  u32 ri;

  /* look up the radv_t  information for this interface */
  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index, ~0);
  
  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];

  error = (ri != ~0) ? 0 : VNET_API_ERROR_INVALID_SW_IF_INDEX;
  
  if(!error)
    {
      f64 now = vlib_time_now (vm);
      ip6_radv_t * radv_info;
      radv_info = pool_elt_at_index (nm->if_radv_pool,  ri);

      /* prefix info add, delete or update */
      ip6_radv_prefix_t * prefix; 
	
      /* lookup  prefix info for this  address on this interface */
      uword * p = mhash_get (&radv_info->address_to_prefix_index,  prefix_addr);
      
      prefix = p ? pool_elt_at_index (radv_info->adv_prefixes_pool, p[0]) : 0;

      if(is_no)
	{
	  /* delete */
	  if(!prefix)
	    return VNET_API_ERROR_INVALID_VALUE; /* invalid prefix */
    
	  if(prefix->prefix_len != prefix_len)
	    return VNET_API_ERROR_INVALID_VALUE_2;

	  /* FIXME - Should the DP do this or the CP ?*/
	  /* do specific delete processing here before returning */
	  /* try to remove from routing table */

	  mhash_unset (&radv_info->address_to_prefix_index, prefix_addr,/* old_value */ 0);
	  pool_put (radv_info->adv_prefixes_pool, prefix);

	  radv_info->initial_adverts_sent  = radv_info->initial_adverts_count -1;
	  radv_info->next_multicast_time =  vlib_time_now (vm);    
	  radv_info->last_multicast_time = vlib_time_now (vm);
	  radv_info->last_radv_time = 0;	
	  return(error);
	}

      /* adding or changing */
      if(!prefix)
	{
	  /* add */
	  u32 pi;
	  pool_get (radv_info->adv_prefixes_pool, prefix);
	  pi = prefix - radv_info->adv_prefixes_pool;
	  mhash_set (&radv_info->address_to_prefix_index,  prefix_addr,  pi, /* old_value */ 0);
	  
	  memset(prefix, 0x0, sizeof(ip6_radv_prefix_t));
	  
	  prefix->prefix_len = prefix_len;
	  clib_memcpy(&prefix->prefix,  prefix_addr, sizeof(ip6_address_t));
	  
	  /* initialize default values */
	  prefix->adv_on_link_flag = 1;      /* L bit set */
	  prefix->adv_autonomous_flag = 1;  /* A bit set */
	  prefix->adv_valid_lifetime_in_secs =  DEF_ADV_VALID_LIFETIME;
	  prefix->adv_pref_lifetime_in_secs = DEF_ADV_PREF_LIFETIME;
	  prefix->enabled = 1;
	  prefix->decrement_lifetime_flag = 1;
	  prefix->deprecated_prefix_flag = 1;

	  if(off_link == 0)
	    {
	      /* FIXME - Should the DP do this or the CP ?*/
	      /* insert prefix into routing table as a connected prefix */
	    }

	  if(use_default)
	    goto restart;
	}
      else
	{
	  
	  if(prefix->prefix_len != prefix_len)
	    return VNET_API_ERROR_INVALID_VALUE_2;

	  if(off_link  != 0)
	    {
	      /* FIXME - Should the DP do this or the CP ?*/
	      /* remove from routing table if already there */
	    }	  
	}

      if((val_lifetime == ~0) || (pref_lifetime == ~0))
	{
	  prefix->adv_valid_lifetime_in_secs =  ~0;
	  prefix->adv_pref_lifetime_in_secs = ~0;
	  prefix->decrement_lifetime_flag = 0;
	}
      else
	{
	  prefix->adv_valid_lifetime_in_secs =  val_lifetime;;
	  prefix->adv_pref_lifetime_in_secs =  pref_lifetime;
	}
      
      /* copy  remaining */
      prefix->enabled = !(no_advertise != 0);
      prefix->adv_on_link_flag = !((off_link != 0) || (no_onlink != 0));
      prefix->adv_autonomous_flag = !(no_autoconfig != 0);

 restart:
      /* restart */
      /* fill in the expiration times  */
      prefix->valid_lifetime_expires = now + prefix->adv_valid_lifetime_in_secs;
      prefix->pref_lifetime_expires = now + prefix->adv_pref_lifetime_in_secs;
	  
      radv_info->initial_adverts_sent  = radv_info->initial_adverts_count -1;
      radv_info->next_multicast_time =  vlib_time_now (vm);    
      radv_info->last_multicast_time = vlib_time_now (vm);
      radv_info->last_radv_time = 0;	
    }
  return(error);
}

clib_error_t *
ip6_neighbor_cmd(vlib_main_t * vm, unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  clib_error_t * error = 0;
  u8 is_no = 0;
  u8 suppress = 0,  managed = 0,  other = 0;
  u8 suppress_ll_option = 0,  send_unicast = 0,  cease= 0; 
  u8 use_lifetime = 0;
  u32 sw_if_index, ra_lifetime = 0, ra_initial_count = 0, ra_initial_interval = 0;
  u32 ra_max_interval = 0 , ra_min_interval = 0;

  unformat_input_t _line_input, * line_input = &_line_input;
  vnet_sw_interface_t * sw_if0;

  int add_radv_info = 1;
  __attribute__((unused)) ip6_radv_t * radv_info = 0;
  ip6_address_t ip6_addr;
  u32 addr_len;
 

  /* Get a line of input. */
  if (! unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  /* get basic radv info for this interface */
  if(unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {

      if (unformat_user (line_input, 
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	{
	  u32 ri;
	  ethernet_interface_t * eth_if0 = 0;
	  
	  sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index);
	  if(sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
	    eth_if0 = ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);
	  
	  if(!eth_if0)
	    {
	      error = clib_error_return (0, "Interface must be of ethernet type");
	      goto done;
	    }
	  
	  /* look up the radv_t  information for this interface */
	  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index, ~0);
	  
	  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];
	  
	  if(ri != ~0)
	    {
	      radv_info = pool_elt_at_index (nm->if_radv_pool,  ri);
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
      else if(unformat (line_input, "prefix %U/%d",
			unformat_ip6_address, &ip6_addr,
			&addr_len))
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
	    return(error = unformat_parse_error (line_input));
	  use_lifetime = 1;
	  break;
	}  
      else if (unformat (line_input, "ra-initial"))
	{
	  if (!unformat (line_input, "%d %d", &ra_initial_count, &ra_initial_interval))
	    return(error = unformat_parse_error (line_input));
	  break;
	}
      else if (unformat (line_input, "ra-interval"))
	{
	  if (!unformat (line_input, "%d", &ra_max_interval))
	    return(error = unformat_parse_error (line_input));

	  if (!unformat (line_input, "%d", &ra_min_interval))
	    ra_min_interval = 0;
	  break;
	}
      else if(unformat (line_input, "ra-cease"))
	{
	  cease = 1;
	  break;
	}
      else
	return(unformat_parse_error (line_input));
    }

  if(add_radv_info)
    {
      ip6_neighbor_ra_config(vm,  sw_if_index, 
			     suppress, managed, other,
			     suppress_ll_option,  send_unicast,  cease, 
			     use_lifetime,  ra_lifetime,
			     ra_initial_count,  ra_initial_interval,  
			     ra_max_interval,  ra_min_interval,
			     is_no);
    }
  else
    {
      u32 valid_lifetime_in_secs =  0;
      u32 pref_lifetime_in_secs = 0;
      u8 use_prefix_default_values = 0;
      u8  no_advertise = 0;
      u8 off_link= 0;
      u8 no_autoconfig = 0;
      u8 no_onlink= 0;

      /* get the rest of the command */
      while(unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if(unformat (line_input, "default"))
	    {
	      use_prefix_default_values = 1;
	      break;
	    }
	  else if(unformat (line_input, "infinite"))
	    {
	      valid_lifetime_in_secs =  ~0;
	      pref_lifetime_in_secs = ~0;
	      break;
	    }
	  else if(unformat (line_input, "%d %d", &valid_lifetime_in_secs, 
			    &pref_lifetime_in_secs))
	    break;
	  else
	    break;
	}


      /* get the rest of the command */
      while (!use_prefix_default_values &&
	     unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if(unformat (line_input, "no-advertise"))
	    no_advertise = 1;
	  else if(unformat (line_input, "off-link"))
	    off_link = 1;
	  else if(unformat (line_input, "no-autoconfig"))
	    no_autoconfig = 1;
	  else if(unformat (line_input, "no-onlink"))
	    no_onlink = 1;
	  else
	    return(unformat_parse_error (line_input));
	}
	
      ip6_neighbor_ra_prefix(vm, sw_if_index,  
			     &ip6_addr,  addr_len,
			     use_prefix_default_values,  
			     valid_lifetime_in_secs,
			     pref_lifetime_in_secs,
			     no_advertise,
			     off_link,
			     no_autoconfig,
			     no_onlink,
			     is_no);
    }

  unformat_free (line_input);
  
 done:
  return error;
}

static void
ip6_print_addrs(vlib_main_t * vm,
                u32 *addrs)
{
  ip_lookup_main_t * lm = &ip6_main.lookup_main;
  u32 i;

  for (i = 0; i < vec_len (addrs); i++)
    {
      ip_interface_address_t * a = pool_elt_at_index(lm->if_address_pool, addrs[i]);
      ip6_address_t * address = ip_interface_address_get_address (lm, a);

      vlib_cli_output (vm, "\t\t%U/%d",
                       format_ip6_address, address,
                       a->address_length);
    }
}

static clib_error_t *
show_ip6_interface_cmd (vlib_main_t * vm,
		    unformat_input_t * input,
		    vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  clib_error_t * error = 0;
  u32 sw_if_index;

  sw_if_index = ~0;

 if (unformat_user (input, 
		      unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      u32 ri;
      
      /* look up the radv_t  information for this interface */
      vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index, ~0);
      
      ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];
      
      if(ri != ~0)
	{
	  ip_lookup_main_t * lm = &ip6_main.lookup_main;
	  ip6_radv_t * radv_info;
	  radv_info = pool_elt_at_index (nm->if_radv_pool,  ri);

	  vlib_cli_output (vm, "%U is admin %s\n", format_vnet_sw_interface_name, vnm, 
			   vnet_get_sw_interface (vnm, sw_if_index),
			   (vnet_sw_interface_is_admin_up (vnm, sw_if_index) ? "up" : "down"));
      
	  u32 ai;
	  u32 *link_scope = 0, *global_scope = 0;
	  u32 *local_scope = 0, *unknown_scope = 0;
	  ip_interface_address_t * a;

	  vec_validate_init_empty (lm->if_address_pool_index_by_sw_if_index, sw_if_index, ~0);
	  ai = lm->if_address_pool_index_by_sw_if_index[sw_if_index];

	  while (ai != (u32)~0)
	    {
	      a = pool_elt_at_index(lm->if_address_pool, ai);
	      ip6_address_t * address = ip_interface_address_get_address (lm, a);

	      if (ip6_address_is_link_local_unicast (address))
		vec_add1 (link_scope, ai);
	      else if(ip6_address_is_global_unicast (address))
		vec_add1 (global_scope, ai);
	      else if(ip6_address_is_local_unicast (address))
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

	  vlib_cli_output (vm, "\tJoined group address(es):\n");
	  ip6_mldp_group_t *m;
	  pool_foreach (m, radv_info->mldp_group_pool, ({
		vlib_cli_output (vm, "\t\t%U\n", format_ip6_address, &m->mcast_address);
	      }));

	  vlib_cli_output (vm, "\tAdvertised Prefixes:\n");
	  ip6_radv_prefix_t * p;
	  pool_foreach (p, radv_info->adv_prefixes_pool, ({
		vlib_cli_output (vm, "\t\tprefix %U,  length %d\n", 
				 format_ip6_address, &p->prefix, p->prefix_len);
	      }));

	  vlib_cli_output (vm, "\tMTU is %d\n",  radv_info->adv_link_mtu);
	  vlib_cli_output (vm, "\tICMP error messages are unlimited\n");
	  vlib_cli_output (vm, "\tICMP redirects are disabled\n");
	  vlib_cli_output (vm, "\tICMP unreachables are not sent\n");
	  vlib_cli_output (vm, "\tND DAD is disabled\n");
	  //vlib_cli_output (vm, "\tND reachable time is %d milliseconds\n",);
	  vlib_cli_output (vm, "\tND advertised reachable time is %d\n",
			   radv_info->adv_neighbor_reachable_time_in_msec);
	  vlib_cli_output (vm, "\tND advertised retransmit interval is %d (msec)\n",
			   radv_info->adv_time_in_msec_between_retransmitted_neighbor_solicitations);

	  u32 ra_interval = radv_info->max_radv_interval;
	  u32 ra_interval_min = radv_info->min_radv_interval;
	  vlib_cli_output (vm, "\tND router advertisements are sent every %d seconds (min interval is %d)\n", 
			   ra_interval, ra_interval_min);
	  vlib_cli_output (vm, "\tND router advertisements live for %d seconds\n",
			   radv_info->adv_router_lifetime_in_sec);
	  vlib_cli_output (vm, "\tHosts %s stateless autoconfig for addresses\n",
			     (radv_info->adv_managed_flag) ? "use" :" don't use");
	  vlib_cli_output (vm, "\tND router advertisements sent %d\n",  radv_info->n_advertisements_sent);
	  vlib_cli_output (vm, "\tND router solicitations received %d\n",  radv_info->n_solicitations_rcvd);
	  vlib_cli_output (vm, "\tND router solicitations dropped %d\n",  radv_info->n_solicitations_dropped);
	}
      else
	{
	  error = clib_error_return (0, "IPv6 not enabled on interface",
				     format_unformat_error, input);

	}
    }
  return error;
}

VLIB_CLI_COMMAND (show_ip6_interface_command, static) = {
  .path = "show ip6 interface",
  .function = show_ip6_interface_cmd,
  .short_help = "show ip6 interface <iface name>",
};

clib_error_t *
disable_ip6_interface(vlib_main_t * vm,
		      u32 sw_if_index)
{
  clib_error_t * error = 0;
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  u32 ri;

  /* look up the radv_t  information for this interface */
  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index, ~0);      
  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];
  
  /* if not created - do nothing */
  if(ri != ~0)
    {
      vnet_main_t * vnm = vnet_get_main();
      ip6_radv_t * radv_info;
  
      radv_info = pool_elt_at_index (nm->if_radv_pool,  ri);

      /* check radv_info ref count for other ip6 addresses on this interface */
      if(radv_info->ref_count == 0 )
	{
	  /* essentially "disables" ipv6 on this interface */
	  error = ip6_add_del_interface_address (vm, sw_if_index,
						 &radv_info->link_local_address, 
						 radv_info->link_local_prefix_len,
						 1 /* is_del */);

	  ip6_neighbor_sw_interface_add_del (vnm, sw_if_index,  0/* is_add */);
	}
    }
  return error;
}

int
ip6_interface_enabled(vlib_main_t * vm,
                      u32 sw_if_index)
{
    ip6_neighbor_main_t * nm = &ip6_neighbor_main;
    u32 ri = ~0;

    /* look up the radv_t  information for this interface */
    vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index, ~0);

    ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];

    return ri != ~0;
}

clib_error_t * 
enable_ip6_interface(vlib_main_t * vm,
		    u32 sw_if_index)
{
  clib_error_t * error = 0;
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  u32 ri;
  int is_add = 1;

  /* look up the radv_t  information for this interface */
  vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index, ~0);
      
  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];
  
  /* if not created yet */
  if(ri == ~0)
    {
      vnet_main_t * vnm = vnet_get_main();
      vnet_sw_interface_t * sw_if0;
 
      sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index);
      if(sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
	{
	  ethernet_interface_t * eth_if0;

	  eth_if0 = ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);	  
	  if(eth_if0)
	    {
	      /* create radv_info. for this interface.  This holds all the info needed for router adverts */
	      ri = ip6_neighbor_sw_interface_add_del (vnm, sw_if_index, is_add);

	      if(ri != ~0)
		{
		  ip6_radv_t * radv_info;
		  ip6_address_t link_local_address;

		  radv_info = pool_elt_at_index (nm->if_radv_pool,  ri);

		  ip6_link_local_address_from_ethernet_mac_address (&link_local_address,
								    eth_if0->address);

		  sw_if0 = vnet_get_sw_interface (vnm, sw_if_index);
		  if(sw_if0->type == VNET_SW_INTERFACE_TYPE_SUB)
		    {
		      /* make up  an interface id */
		      md5_context_t m;
		      u8 digest[16];
		      
		      link_local_address.as_u64[0] = radv_info->randomizer;
		      
		      md5_init (&m);
		      md5_add (&m, &link_local_address, 16);
		      md5_finish (&m,  digest);
		      
		      clib_memcpy(&link_local_address, digest, 16);
		      
		      radv_info->randomizer = link_local_address.as_u64[0];
		      
		      link_local_address.as_u64[0] = clib_host_to_net_u64 (0xFE80000000000000ULL);
		      /* clear u bit */
		      link_local_address.as_u8[8] &= 0xfd;
		    }
		  
		  /* essentially "enables" ipv6 on this interface */
		  error = ip6_add_del_interface_address (vm, sw_if_index,
							 &link_local_address, 64 /* address width */,
							 0 /* is_del */);
		  
		  if(error)
		      ip6_neighbor_sw_interface_add_del (vnm, sw_if_index, !is_add);
		  else
		    {
		      radv_info->link_local_address =  link_local_address;
		      radv_info->link_local_prefix_len  = 64;
		    }
		}
	    } 
	}
    }
  return error;
}

static clib_error_t *
enable_ip6_interface_cmd (vlib_main_t * vm,
		    unformat_input_t * input,
		    vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 sw_if_index;

  sw_if_index = ~0;

 if (unformat_user (input, 
		      unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      enable_ip6_interface(vm, sw_if_index);
    }
 else
   {
     error = clib_error_return (0, "unknown interface\n'",
				format_unformat_error, input);
     
   }
  return error;
}

VLIB_CLI_COMMAND (enable_ip6_interface_command, static) = {
  .path = "enable ip6 interface",
  .function = enable_ip6_interface_cmd,
  .short_help = "enable ip6 interface <iface name>",
};

static clib_error_t *
disable_ip6_interface_cmd (vlib_main_t * vm,
		    unformat_input_t * input,
		    vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 sw_if_index;

  sw_if_index = ~0;

 if (unformat_user (input, 
		      unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = disable_ip6_interface(vm, sw_if_index);
    }
 else
   {
     error = clib_error_return (0, "unknown interface\n'",
				format_unformat_error, input);
     
   }
  return error;
}

VLIB_CLI_COMMAND (disable_ip6_interface_command, static) = {
  .path = "disable  ip6 interface",
  .function = disable_ip6_interface_cmd,
  .short_help = "disable ip6 interface <iface name>",
};

VLIB_CLI_COMMAND (ip6_nd_command, static) = {
  .path = "ip6 nd",
  .short_help = "Set ip6 neighbor discovery parameters",
  .function = ip6_neighbor_cmd,
};

clib_error_t *
set_ip6_link_local_address(vlib_main_t * vm,
			   u32 sw_if_index,
			   ip6_address_t *address,
			   u8 address_length)
{
  clib_error_t * error = 0;
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  u32 ri;
  ip6_radv_t * radv_info;
  vnet_main_t * vnm = vnet_get_main();

  if( !ip6_address_is_link_local_unicast (address))
    {
      vnm->api_errno = VNET_API_ERROR_ADDRESS_NOT_LINK_LOCAL;
      return(error = clib_error_return (0, "address not link-local",
                                        format_unformat_error));
    }

  /* call enable ipv6  */
  enable_ip6_interface(vm, sw_if_index);
	  
  ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];
	 
  if(ri != ~0)
    {
      radv_info = pool_elt_at_index (nm->if_radv_pool,  ri);

      /* save if link local address (overwrite default) */
   
      /* delete the old one */
      error = ip6_add_del_interface_address (vm, sw_if_index,
					     &radv_info->link_local_address,
					     radv_info->link_local_prefix_len  /* address width */,
					     1 /* is_del */);
      
      if(!error)
	{
	  /* add the new one */
	  error = ip6_add_del_interface_address (vm, sw_if_index,
						 address ,
						 address_length  /* address width */,
						 0/* is_del */);
	  
	  if(!error)
	    {
	      radv_info->link_local_address = *address;
	      radv_info->link_local_prefix_len  = address_length;
	    }
	}
    }
  else
    {
      vnm->api_errno = VNET_API_ERROR_IP6_NOT_ENABLED;
      error = clib_error_return (0, "ip6 not enabled for interface",
				 format_unformat_error);
    }
  return error;
}
  
clib_error_t *
set_ip6_link_local_address_cmd (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 sw_if_index;
  ip6_address_t ip6_addr;
  u32 addr_len = 0;
 
  if (unformat_user (input, 
		     unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      /* get the rest of the command */
      while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
	{
	  if(unformat (input, "%U/%d",
		       unformat_ip6_address, &ip6_addr,
		       &addr_len))
	    break;
	  else
	    return(unformat_parse_error (input));
	}
    }
  error = set_ip6_link_local_address(vm,
				     sw_if_index,
				     &ip6_addr,
				     addr_len);
  return error;
}

VLIB_CLI_COMMAND (set_ip6_link_local_address_command, static) = {
  .path = "set ip6 link-local address",
  .short_help = "Set ip6 interface link-local address <intfc> <address.>",
  .function = set_ip6_link_local_address_cmd,
};

/* callback when an interface address is added or deleted */
static void
ip6_neighbor_add_del_interface_address (ip6_main_t * im,
					uword opaque,
					u32 sw_if_index,
					ip6_address_t * address,
					u32 address_length,
					u32 if_address_index,
					u32 is_delete)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  u32 ri;
  vlib_main_t * vm = vnm->vlib_main;
  ip6_radv_t * radv_info;
  ip6_address_t a;
  ip6_mldp_group_t  *mcast_group_info;

  /* create solicited node multicast address for this interface adddress */
  ip6_set_solicited_node_multicast_address (&a, 0);
 
  a.as_u8[0xd] = address->as_u8[0xd];
  a.as_u8[0xe] = address->as_u8[0xe];
  a.as_u8[0xf] = address->as_u8[0xf];
  
  if(!is_delete)
    {
      /* try to  create radv_info - does nothing if ipv6 already enabled */
      enable_ip6_interface(vm, sw_if_index);

      /* look up the radv_t  information for this interface */
      vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index, ~0);
      ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];
      if(ri != ~0)
	{
	  /* get radv_info */
	  radv_info = pool_elt_at_index (nm->if_radv_pool, ri);

	  /* add address */
	  if( !ip6_address_is_link_local_unicast (address))
	    radv_info->ref_count++;

	  /* lookup  prefix info for this  address on this interface */
	  uword * p = mhash_get (&radv_info->address_to_mldp_index,  &a);
	  mcast_group_info = p ? pool_elt_at_index (radv_info->mldp_group_pool, p[0]) : 0;

	  /* add -solicted node multicast address  */
	  if(!mcast_group_info)
	    {
	      /* add */
	      u32 mi;
	      pool_get (radv_info->mldp_group_pool, mcast_group_info);
	      
	      mi = mcast_group_info - radv_info->mldp_group_pool;
	      mhash_set (&radv_info->address_to_mldp_index,  &a,  mi, /* old_value */ 0);
	      
	      mcast_group_info->type = 4;
	      mcast_group_info->mcast_source_address_pool = 0;
	      mcast_group_info->num_sources = 0;
	      clib_memcpy(&mcast_group_info->mcast_address, &a, sizeof(ip6_address_t));
	    } 
	}
    }
  else
    {

      /* delete */
      /* look up the radv_t  information for this interface */
      vec_validate_init_empty (nm->if_radv_pool_index_by_sw_if_index, sw_if_index, ~0);
      ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index];
      if(ri != ~0)
	{
	  /* get radv_info */
	  radv_info = pool_elt_at_index (nm->if_radv_pool, ri);

	  /* lookup  prefix info for this  address on this interface */
	  uword * p = mhash_get (&radv_info->address_to_mldp_index,  &a);
	  mcast_group_info = p ? pool_elt_at_index (radv_info->mldp_group_pool, p[0]) : 0;
	  
	  if(mcast_group_info)
	    {
	      mhash_unset (&radv_info->address_to_mldp_index, &a,/* old_value */ 0);
	      pool_put (radv_info->mldp_group_pool, mcast_group_info);
	    }

	  /* if interface up send MLDP "report" */
	  radv_info->all_routers_mcast = 0;

	  /* add address */
	  if( !ip6_address_is_link_local_unicast (address))
	    radv_info->ref_count--;
	}
    }
}

clib_error_t *ip6_set_neighbor_limit (u32 neighbor_limit)
{
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;

  nm->limit_neighbor_cache_size = neighbor_limit;
  return 0;
}


static void
ip6_neighbor_entry_del_adj(ip6_neighbor_t *n, u32 adj_index)
{
  int done = 0;
  int i;
  while (!done)
    {
      vec_foreach_index(i, n->adjacencies)
        if (vec_elt(n->adjacencies, i) == adj_index)
          {
            vec_del1(n->adjacencies, i);
            continue;
          }
      done = 1;
    }
}

static void
ip6_neighbor_entry_add_adj(ip6_neighbor_t *n, u32 adj_index)
{
  int i;
  vec_foreach_index(i, n->adjacencies)
    if (vec_elt(n->adjacencies, i) == adj_index)
      return;
  vec_add1(n->adjacencies, adj_index);
}

static void
ip6_neighbor_add_del_adj_cb (struct ip_lookup_main_t * lm,
                    u32 adj_index,
                    ip_adjacency_t * adj,
                    u32 is_del)
{
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  ip6_neighbor_key_t k;
  ip6_neighbor_t *n = 0;
  uword * p;
  u32 ai;

  for(ai = adj->heap_handle; ai < adj->heap_handle + adj->n_adj ; ai++)
    {
      adj = ip_get_adjacency (lm, ai);
      if (adj->lookup_next_index == IP_LOOKUP_NEXT_ARP &&
          (adj->arp.next_hop.ip6.as_u64[0] || adj->arp.next_hop.ip6.as_u64[1]))
        {
          k.sw_if_index = adj->rewrite_header.sw_if_index;
          k.ip6_address.as_u64[0] = adj->arp.next_hop.ip6.as_u64[0];
          k.ip6_address.as_u64[1] = adj->arp.next_hop.ip6.as_u64[1];
          k.pad = 0;
          p = mhash_get (&nm->neighbor_index_by_key, &k);
          if (p)
            n = pool_elt_at_index (nm->neighbor_pool, p[0]);
        }
      else
        continue;

      if (is_del)
        {
          if (!n)
            clib_warning("Adjacency contains unknown ND next hop %U (del)",
                         format_ip46_address, &adj->arp.next_hop, IP46_TYPE_IP6);
          else
            ip6_neighbor_entry_del_adj(n, adj->heap_handle);
        }
      else /* add */
        {
          if (!n)
            clib_warning("Adjacency contains unknown ND next hop %U (add)",
                         format_ip46_address, &adj->arp.next_hop, IP46_TYPE_IP6);
          else
            ip6_neighbor_entry_add_adj(n, adj->heap_handle);
        }
    }
}

static clib_error_t * ip6_neighbor_init (vlib_main_t * vm)
{
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
 
  mhash_init (&nm->neighbor_index_by_key,
	      /* value size */ sizeof (uword),
	      /* key size */ sizeof (ip6_neighbor_key_t));

  icmp6_register_type (vm, ICMP6_neighbor_solicitation, ip6_icmp_neighbor_solicitation_node.index);
  icmp6_register_type (vm, ICMP6_neighbor_advertisement, ip6_icmp_neighbor_advertisement_node.index);
  icmp6_register_type (vm, ICMP6_router_solicitation, ip6_icmp_router_solicitation_node.index);
  icmp6_register_type (vm, ICMP6_router_advertisement, ip6_icmp_router_advertisement_node.index);

  /* handler node for ip6 neighbor discovery events and timers */
  vlib_register_node (vm, &ip6_icmp_neighbor_discovery_event_node);

  /* add call backs */
  ip6_add_del_interface_address_callback_t cb; 
  memset(&cb, 0x0, sizeof(ip6_add_del_interface_address_callback_t));
  
  /* when an interface address changes... */
  cb.function = ip6_neighbor_add_del_interface_address;
  cb.function_opaque = 0;
  vec_add1 (im->add_del_interface_address_callbacks, cb);

  mhash_init (&nm->pending_resolutions_by_address,
	      /* value size */ sizeof (uword),
	      /* key size */ sizeof (ip6_address_t));

  /* default, configurable */
  nm->limit_neighbor_cache_size = 50000;

#if 0
  /* $$$$ Hack fix for today */
  vec_validate_init_empty 
      (im->discover_neighbor_next_index_by_hw_if_index, 32, 0 /* drop */);
#endif

  ip_register_add_del_adjacency_callback(lm, ip6_neighbor_add_del_adj_cb);

  return 0;
}

VLIB_INIT_FUNCTION (ip6_neighbor_init);


void vnet_register_ip6_neighbor_resolution_event (vnet_main_t * vnm, 
                                                  void * address_arg,
                                                  uword node_index,
                                                  uword type_opaque,
                                                  uword data)
{
  ip6_neighbor_main_t * nm = &ip6_neighbor_main;
  ip6_address_t * address = address_arg;
  uword * p;
  pending_resolution_t * pr;
  
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
             pr - nm->pending_resolutions, 0 /* old value */);
}

