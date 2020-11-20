/*
 * src/vnet/ip/ip_neighboor.c: ip neighbor generic handling
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vppinfra/llist.h>

#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/ip-neighbor/ip4_neighbor.h>
#include <vnet/ip-neighbor/ip6_neighbor.h>
#include <vnet/ip-neighbor/ip_neighbor_watch.h>

#include <vnet/ip/ip6_ll_table.h>
#include <vnet/fib/fib_table.h>
#include <vnet/adj/adj_mcast.h>

/** Pool for All IP neighbors */
static ip_neighbor_t *ip_neighbor_pool;

/** protocol specific lists of time sorted neighbors */
index_t ip_neighbor_list_head[IP46_N_TYPES];

typedef struct ip_neighbor_elt_t_
{
  clib_llist_anchor_t ipne_anchor;
  index_t ipne_index;
} ip_neighbor_elt_t;

/** Pool of linked list elemeents */
ip_neighbor_elt_t *ip_neighbor_elt_pool;

typedef struct ip_neighbor_db_t_
{
  /** per interface hash */
  uword **ipndb_hash;
  /** per-protocol limit - max number of neighbors*/
  u32 ipndb_limit;
  /** max age of a neighbor before it's forcibly evicted */
  u32 ipndb_age;
  /** when the limit is reached and new neighbors are created, should
   * we recycle an old one */
  bool ipndb_recycle;
  /** per-protocol number of elements */
  u32 ipndb_n_elts;
  /** per-protocol number of elements per-fib-index*/
  u32 *ipndb_n_elts_per_fib;
} ip_neighbor_db_t;

static vlib_log_class_t ipn_logger;

/* DBs of neighbours one per AF */
/* *INDENT-OFF* */
static ip_neighbor_db_t ip_neighbor_db[IP46_N_TYPES] = {
  [IP46_TYPE_IP4] = {
    .ipndb_limit = 50000,
    /* Default to not aging and not recycling */
    .ipndb_age = 0,
    .ipndb_recycle = false,
  },
  [IP46_TYPE_IP6] = {
    .ipndb_limit = 50000,
    /* Default to not aging and not recycling */
    .ipndb_age = 0,
    .ipndb_recycle = false,
  }
};
/* *INDENT-ON* */

#define IP_NEIGHBOR_DBG(...)                           \
    vlib_log_debug (ipn_logger, __VA_ARGS__);

#define IP_NEIGHBOR_INFO(...)                          \
    vlib_log_notice (ipn_logger, __VA_ARGS__);

ip_neighbor_t *
ip_neighbor_get (index_t ipni)
{
  if (pool_is_free_index (ip_neighbor_pool, ipni))
    return (NULL);

  return (pool_elt_at_index (ip_neighbor_pool, ipni));
}

static index_t
ip_neighbor_get_index (const ip_neighbor_t * ipn)
{
  return (ipn - ip_neighbor_pool);
}

static void
ip_neighbor_touch (ip_neighbor_t * ipn)
{
  ipn->ipn_flags &= ~IP_NEIGHBOR_FLAG_STALE;
}

static bool
ip_neighbor_is_dynamic (const ip_neighbor_t * ipn)
{
  return (ipn->ipn_flags & IP_NEIGHBOR_FLAG_DYNAMIC);
}

const ip46_address_t *
ip_neighbor_get_ip (const ip_neighbor_t * ipn)
{
  return (&ipn->ipn_key->ipnk_ip);
}

const mac_address_t *
ip_neighbor_get_mac (const ip_neighbor_t * ipn)
{
  return (&ipn->ipn_mac);
}

const u32
ip_neighbor_get_sw_if_index (const ip_neighbor_t * ipn)
{
  return (ipn->ipn_key->ipnk_sw_if_index);
}

static void
ip_neighbor_list_remove (ip_neighbor_t * ipn)
{
  /* new neighbours, are added to the head of the list, since the
   * list is time sorted, newest first */
  ip_neighbor_elt_t *elt;

  if (~0 != ipn->ipn_elt)
    {
      elt = pool_elt_at_index (ip_neighbor_elt_pool, ipn->ipn_elt);

      clib_llist_remove (ip_neighbor_elt_pool, ipne_anchor, elt);

      ipn->ipn_elt = ~0;
    }
}

static void
ip_neighbor_refresh (ip_neighbor_t * ipn)
{
  /* new neighbours, are added to the head of the list, since the
   * list is time sorted, newest first */
  ip_neighbor_elt_t *elt, *head;

  ip_neighbor_touch (ipn);
  ipn->ipn_time_last_updated = vlib_time_now (vlib_get_main ());
  ipn->ipn_n_probes = 0;

  if (ip_neighbor_is_dynamic (ipn))
    {
      if (~0 == ipn->ipn_elt)
	/* first time insertion */
	pool_get_zero (ip_neighbor_elt_pool, elt);
      else
	{
	  /* already inserted - extract first */
	  elt = pool_elt_at_index (ip_neighbor_elt_pool, ipn->ipn_elt);

	  clib_llist_remove (ip_neighbor_elt_pool, ipne_anchor, elt);
	}
      head = pool_elt_at_index (ip_neighbor_elt_pool,
				ip_neighbor_list_head[ipn->
						      ipn_key->ipnk_type]);

      elt->ipne_index = ip_neighbor_get_index (ipn);
      clib_llist_add (ip_neighbor_elt_pool, ipne_anchor, elt, head);
      ipn->ipn_elt = elt - ip_neighbor_elt_pool;
    }
}

static void
ip_neighbor_db_add (const ip_neighbor_t * ipn)
{
  vec_validate (ip_neighbor_db[ipn->ipn_key->ipnk_type].ipndb_hash,
		ipn->ipn_key->ipnk_sw_if_index);

  if (!ip_neighbor_db[ipn->ipn_key->ipnk_type].ipndb_hash
      [ipn->ipn_key->ipnk_sw_if_index])
    ip_neighbor_db[ipn->ipn_key->ipnk_type].ipndb_hash[ipn->
						       ipn_key->ipnk_sw_if_index]
      = hash_create_mem (0, sizeof (ip_neighbor_key_t), sizeof (index_t));

  hash_set_mem (ip_neighbor_db[ipn->ipn_key->ipnk_type].ipndb_hash
		[ipn->ipn_key->ipnk_sw_if_index], ipn->ipn_key,
		ip_neighbor_get_index (ipn));

  ip_neighbor_db[ipn->ipn_key->ipnk_type].ipndb_n_elts++;
}

static void
ip_neighbor_db_remove (const ip_neighbor_key_t * key)
{
  vec_validate (ip_neighbor_db[key->ipnk_type].ipndb_hash,
		key->ipnk_sw_if_index);

  hash_unset_mem (ip_neighbor_db[key->ipnk_type].ipndb_hash
		  [key->ipnk_sw_if_index], key);

  ip_neighbor_db[key->ipnk_type].ipndb_n_elts--;
}

static ip_neighbor_t *
ip_neighbor_db_find (const ip_neighbor_key_t * key)
{
  uword *p;

  if (key->ipnk_sw_if_index >=
      vec_len (ip_neighbor_db[key->ipnk_type].ipndb_hash))
    return NULL;

  p =
    hash_get_mem (ip_neighbor_db[key->ipnk_type].ipndb_hash
		  [key->ipnk_sw_if_index], key);

  if (p)
    return ip_neighbor_get (p[0]);

  return (NULL);
}

static u8
ip46_type_pfx_len (ip46_type_t type)
{
  return (type == IP46_TYPE_IP4 ? 32 : 128);
}

static void
ip_neighbor_adj_fib_add (ip_neighbor_t * ipn, u32 fib_index)
{
  if (ipn->ipn_key->ipnk_type == IP46_TYPE_IP6 &&
      ip6_address_is_link_local_unicast (&ipn->ipn_key->ipnk_ip.ip6))
    {
      ip6_ll_prefix_t pfx = {
	.ilp_addr = ipn->ipn_key->ipnk_ip.ip6,
	.ilp_sw_if_index = ipn->ipn_key->ipnk_sw_if_index,
      };
      ipn->ipn_fib_entry_index =
	ip6_ll_table_entry_update (&pfx, FIB_ROUTE_PATH_FLAG_NONE);
    }
  else
    {
      fib_protocol_t fproto;

      fproto = fib_proto_from_ip46 (ipn->ipn_key->ipnk_type);

      fib_prefix_t pfx = {
	.fp_len = ip46_type_pfx_len (ipn->ipn_key->ipnk_type),
	.fp_proto = fproto,
	.fp_addr = ipn->ipn_key->ipnk_ip,
      };

      ipn->ipn_fib_entry_index =
	fib_table_entry_path_add (fib_index, &pfx, FIB_SOURCE_ADJ,
				  FIB_ENTRY_FLAG_ATTACHED,
				  fib_proto_to_dpo (fproto),
				  &pfx.fp_addr,
				  ipn->ipn_key->ipnk_sw_if_index,
				  ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);

      vec_validate (ip_neighbor_db
		    [ipn->ipn_key->ipnk_type].ipndb_n_elts_per_fib,
		    fib_index);

      ip_neighbor_db[ipn->ipn_key->
		     ipnk_type].ipndb_n_elts_per_fib[fib_index]++;

      if (1 ==
	  ip_neighbor_db[ipn->ipn_key->
			 ipnk_type].ipndb_n_elts_per_fib[fib_index])
	fib_table_lock (fib_index, fproto, FIB_SOURCE_ADJ);
    }
}

static void
ip_neighbor_adj_fib_remove (ip_neighbor_t * ipn, u32 fib_index)
{
  if (FIB_NODE_INDEX_INVALID != ipn->ipn_fib_entry_index)
    {
      if (ipn->ipn_key->ipnk_type == IP46_TYPE_IP6 &&
	  ip6_address_is_link_local_unicast (&ipn->ipn_key->ipnk_ip.ip6))
	{
	  ip6_ll_prefix_t pfx = {
	    .ilp_addr = ipn->ipn_key->ipnk_ip.ip6,
	    .ilp_sw_if_index = ipn->ipn_key->ipnk_sw_if_index,
	  };
	  ip6_ll_table_entry_delete (&pfx);
	}
      else
	{
	  fib_protocol_t fproto;

	  fproto = fib_proto_from_ip46 (ipn->ipn_key->ipnk_type);

	  fib_prefix_t pfx = {
	    .fp_len = ip46_type_pfx_len (ipn->ipn_key->ipnk_type),
	    .fp_proto = fproto,
	    .fp_addr = ipn->ipn_key->ipnk_ip,
	  };

	  fib_table_entry_path_remove (fib_index,
				       &pfx,
				       FIB_SOURCE_ADJ,
				       fib_proto_to_dpo (fproto),
				       &pfx.fp_addr,
				       ipn->ipn_key->ipnk_sw_if_index,
				       ~0, 1, FIB_ROUTE_PATH_FLAG_NONE);

	  ip_neighbor_db[ipn->ipn_key->
			 ipnk_type].ipndb_n_elts_per_fib[fib_index]--;

	  if (0 ==
	      ip_neighbor_db[ipn->ipn_key->
			     ipnk_type].ipndb_n_elts_per_fib[fib_index])
	    fib_table_unlock (fib_index, fproto, FIB_SOURCE_ADJ);
	}
    }
}

static void
ip_neighbor_mk_complete (adj_index_t ai, ip_neighbor_t * ipn)
{
  adj_nbr_update_rewrite (ai, ADJ_NBR_REWRITE_FLAG_COMPLETE,
			  ethernet_build_rewrite (vnet_get_main (),
						  ipn->
						  ipn_key->ipnk_sw_if_index,
						  adj_get_link_type (ai),
						  ipn->ipn_mac.bytes));
}

static void
ip_neighbor_mk_incomplete (adj_index_t ai)
{
  ip_adjacency_t *adj = adj_get (ai);

  adj_nbr_update_rewrite (ai,
			  ADJ_NBR_REWRITE_FLAG_INCOMPLETE,
			  ethernet_build_rewrite (vnet_get_main (),
						  adj->
						  rewrite_header.sw_if_index,
						  VNET_LINK_ARP,
						  VNET_REWRITE_FOR_SW_INTERFACE_ADDRESS_BROADCAST));
}

static adj_walk_rc_t
ip_neighbor_mk_complete_walk (adj_index_t ai, void *ctx)
{
  ip_neighbor_t *ipn = ctx;

  ip_neighbor_mk_complete (ai, ipn);

  return (ADJ_WALK_RC_CONTINUE);
}

static adj_walk_rc_t
ip_neighbor_mk_incomplete_walk (adj_index_t ai, void *ctx)
{
  ip_neighbor_mk_incomplete (ai);

  return (ADJ_WALK_RC_CONTINUE);
}

static void
ip_neighbor_destroy (ip_neighbor_t * ipn)
{
  IP_NEIGHBOR_DBG ("free: %U", format_ip_neighbor,
		   ip_neighbor_get_index (ipn));

  ip_neighbor_publish (ip_neighbor_get_index (ipn),
		       IP_NEIGHBOR_EVENT_REMOVED);

  adj_nbr_walk_nh (ipn->ipn_key->ipnk_sw_if_index,
		   fib_proto_from_ip46 (ipn->ipn_key->ipnk_type),
		   &ipn->ipn_key->ipnk_ip,
		   ip_neighbor_mk_incomplete_walk, ipn);
  ip_neighbor_adj_fib_remove
    (ipn,
     fib_table_get_index_for_sw_if_index
     (fib_proto_from_ip46 (ipn->ipn_key->ipnk_type),
      ipn->ipn_key->ipnk_sw_if_index));

  ip_neighbor_list_remove (ipn);
  ip_neighbor_db_remove (ipn->ipn_key);
  clib_mem_free (ipn->ipn_key);

  pool_put (ip_neighbor_pool, ipn);
}

static bool
ip_neighbor_force_reuse (ip46_type_t type)
{
  if (!ip_neighbor_db[type].ipndb_recycle)
    return false;

  /* pluck the oldest entry, which is the one from the end of the list */
  ip_neighbor_elt_t *elt, *head;

  head =
    pool_elt_at_index (ip_neighbor_elt_pool, ip_neighbor_list_head[type]);

  if (clib_llist_is_empty (ip_neighbor_elt_pool, ipne_anchor, head))
    return (false);

  elt = clib_llist_prev (ip_neighbor_elt_pool, ipne_anchor, head);
  ip_neighbor_destroy (ip_neighbor_get (elt->ipne_index));

  return (true);
}

static ip_neighbor_t *
ip_neighbor_alloc (const ip_neighbor_key_t * key,
		   const mac_address_t * mac, ip_neighbor_flags_t flags)
{
  ip_neighbor_t *ipn;

  if (ip_neighbor_db[key->ipnk_type].ipndb_limit &&
      (ip_neighbor_db[key->ipnk_type].ipndb_n_elts >=
       ip_neighbor_db[key->ipnk_type].ipndb_limit))
    {
      if (!ip_neighbor_force_reuse (key->ipnk_type))
	return (NULL);
    }

  pool_get_zero (ip_neighbor_pool, ipn);

  ipn->ipn_key = clib_mem_alloc (sizeof (*ipn->ipn_key));
  clib_memcpy (ipn->ipn_key, key, sizeof (*ipn->ipn_key));

  ipn->ipn_fib_entry_index = FIB_NODE_INDEX_INVALID;
  ipn->ipn_flags = flags;
  ipn->ipn_elt = ~0;

  mac_address_copy (&ipn->ipn_mac, mac);

  ip_neighbor_db_add (ipn);

  /* create the adj-fib. the entry in the FIB table for the peer's interface */
  if (!(ipn->ipn_flags & IP_NEIGHBOR_FLAG_NO_FIB_ENTRY))
    ip_neighbor_adj_fib_add
      (ipn, fib_table_get_index_for_sw_if_index
       (fib_proto_from_ip46 (ipn->ipn_key->ipnk_type),
	ipn->ipn_key->ipnk_sw_if_index));

  return (ipn);
}

int
ip_neighbor_add (const ip46_address_t * ip,
		 ip46_type_t type,
		 const mac_address_t * mac,
		 u32 sw_if_index,
		 ip_neighbor_flags_t flags, u32 * stats_index)
{
  fib_protocol_t fproto;
  ip_neighbor_t *ipn;

  /* main thread only */
  ASSERT (0 == vlib_get_thread_index ());

  fproto = fib_proto_from_ip46 (type);

  const ip_neighbor_key_t key = {
    .ipnk_ip = *ip,
    .ipnk_sw_if_index = sw_if_index,
    .ipnk_type = type,
  };

  ipn = ip_neighbor_db_find (&key);

  if (ipn)
    {
      IP_NEIGHBOR_DBG ("update: %U, %U",
		       format_vnet_sw_if_index_name, vnet_get_main (),
		       sw_if_index, format_ip46_address, ip, type,
		       format_ip_neighbor_flags, flags, format_mac_address_t,
		       mac);

      ip_neighbor_touch (ipn);

      /* Refuse to over-write static neighbor entry. */
      if (!(flags & IP_NEIGHBOR_FLAG_STATIC) &&
	  (ipn->ipn_flags & IP_NEIGHBOR_FLAG_STATIC))
	{
	  /* if MAC address match, still check to send event */
	  if (0 == mac_address_cmp (&ipn->ipn_mac, mac))
	    goto check_customers;
	  return -2;
	}

      /* A dynamic entry can become static, but not vice-versa.
       * i.e. since if it was programmed by the CP then it must
       * be removed by the CP */
      if ((flags & IP_NEIGHBOR_FLAG_STATIC) &&
	  !(ipn->ipn_flags & IP_NEIGHBOR_FLAG_STATIC))
	{
	  ip_neighbor_list_remove (ipn);
	  ipn->ipn_flags |= IP_NEIGHBOR_FLAG_STATIC;
	  ipn->ipn_flags &= ~IP_NEIGHBOR_FLAG_DYNAMIC;
	}

      /*
       * prevent a DoS attack from the data-plane that
       * spams us with no-op updates to the MAC address
       */
      if (0 == mac_address_cmp (&ipn->ipn_mac, mac))
	{
	  ip_neighbor_refresh (ipn);
	  goto check_customers;
	}

      mac_address_copy (&ipn->ipn_mac, mac);
    }
  else
    {
      IP_NEIGHBOR_INFO ("add: %U, %U",
			format_vnet_sw_if_index_name, vnet_get_main (),
			sw_if_index, format_ip46_address, ip, type,
			format_ip_neighbor_flags, flags, format_mac_address_t,
			mac);

      ipn = ip_neighbor_alloc (&key, mac, flags);

      if (NULL == ipn)
	return VNET_API_ERROR_LIMIT_EXCEEDED;
    }

  /* Update time stamp and flags. */
  ip_neighbor_refresh (ipn);

  adj_nbr_walk_nh (ipn->ipn_key->ipnk_sw_if_index,
		   fproto, &ipn->ipn_key->ipnk_ip,
		   ip_neighbor_mk_complete_walk, ipn);

check_customers:
  /* Customer(s) requesting event for this address? */
  ip_neighbor_publish (ip_neighbor_get_index (ipn), IP_NEIGHBOR_EVENT_ADDED);

  if (stats_index)
    *stats_index = adj_nbr_find (fproto,
				 fib_proto_to_link (fproto),
				 &ipn->ipn_key->ipnk_ip,
				 ipn->ipn_key->ipnk_sw_if_index);
  return 0;
}

int
ip_neighbor_del (const ip46_address_t * ip, ip46_type_t type, u32 sw_if_index)
{
  ip_neighbor_t *ipn;

  /* main thread only */
  ASSERT (0 == vlib_get_thread_index ());

  IP_NEIGHBOR_INFO ("delete: %U, %U",
		    format_vnet_sw_if_index_name, vnet_get_main (),
		    sw_if_index, format_ip46_address, ip, type);

  const ip_neighbor_key_t key = {
    .ipnk_ip = *ip,
    .ipnk_sw_if_index = sw_if_index,
    .ipnk_type = type,
  };

  ipn = ip_neighbor_db_find (&key);

  if (NULL == ipn)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  ip_neighbor_destroy (ipn);

  return (0);
}

typedef struct ip_neighbor_del_all_ctx_t_
{
  index_t *ipn_del;
} ip_neighbor_del_all_ctx_t;

static walk_rc_t
ip_neighbor_del_all_walk_cb (index_t ipni, void *arg)
{
  ip_neighbor_del_all_ctx_t *ctx = arg;

  vec_add1 (ctx->ipn_del, ipni);

  return (WALK_CONTINUE);
}

void
ip_neighbor_del_all (ip46_type_t type, u32 sw_if_index)
{
  IP_NEIGHBOR_INFO ("delete-all: %U, %U",
		    format_ip46_type, type,
		    format_vnet_sw_if_index_name, vnet_get_main (),
		    sw_if_index);

  ip_neighbor_del_all_ctx_t ctx = {
    .ipn_del = NULL,
  };
  index_t *ipni;

  ip_neighbor_walk (type, sw_if_index, ip_neighbor_del_all_walk_cb, &ctx);

  vec_foreach (ipni,
	       ctx.ipn_del) ip_neighbor_destroy (ip_neighbor_get (*ipni));
  vec_free (ctx.ipn_del);
}

void
ip_neighbor_update (vnet_main_t * vnm, adj_index_t ai)
{
  ip_neighbor_t *ipn;
  ip_adjacency_t *adj;

  adj = adj_get (ai);

  ip_neighbor_key_t key = {
    .ipnk_ip = adj->sub_type.nbr.next_hop,
    .ipnk_type = fib_proto_to_ip46 (adj->ia_nh_proto),
    .ipnk_sw_if_index = adj->rewrite_header.sw_if_index,
  };
  ipn = ip_neighbor_db_find (&key);

  switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_ARP:
      if (NULL != ipn)
	{
	  adj_nbr_walk_nh (adj->rewrite_header.sw_if_index,
			   adj->ia_nh_proto,
			   &ipn->ipn_key->ipnk_ip,
			   ip_neighbor_mk_complete_walk, ipn);
	}
      else
	{
	  /*
	   * no matching ARP entry.
	   * construct the rewrite required to for an ARP packet, and stick
	   * that in the adj's pipe to smoke.
	   */
	  adj_nbr_update_rewrite
	    (ai,
	     ADJ_NBR_REWRITE_FLAG_INCOMPLETE,
	     ethernet_build_rewrite
	     (vnm,
	      adj->rewrite_header.sw_if_index,
	      VNET_LINK_ARP,
	      VNET_REWRITE_FOR_SW_INTERFACE_ADDRESS_BROADCAST));

	  /*
	   * since the FIB has added this adj for a route, it makes sense it
	   * may want to forward traffic sometime soon. Let's send a
	   * speculative ARP. just one. If we were to do periodically that
	   * wouldn't be bad either, but that's more code than i'm prepared to
	   * write at this time for relatively little reward.
	   */
	  /*
	   * adj_nbr_update_rewrite may actually call fib_walk_sync.
	   * fib_walk_sync may allocate a new adjacency and potentially cause
	   * a realloc for adj_pool. When that happens, adj pointer is no
	   * longer valid here.x We refresh adj pointer accordingly.
	   */
	  adj = adj_get (ai);
	  ip_neighbor_probe (adj);
	}
      break;
    case IP_LOOKUP_NEXT_GLEAN:
    case IP_LOOKUP_NEXT_BCAST:
    case IP_LOOKUP_NEXT_MCAST:
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

void
ip_neighbor_learn (const ip_neighbor_learn_t * l)
{
  ip_neighbor_add (&l->ip, l->type, &l->mac, l->sw_if_index,
		   IP_NEIGHBOR_FLAG_DYNAMIC, NULL);
}

static clib_error_t *
ip_neighbor_cmd (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip46_address_t ip = ip46_address_initializer;
  mac_address_t mac = ZERO_MAC_ADDRESS;
  vnet_main_t *vnm = vnet_get_main ();
  ip_neighbor_flags_t flags;
  u32 sw_if_index = ~0;
  int is_add = 1;
  int count = 1;

  flags = IP_NEIGHBOR_FLAG_DYNAMIC;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      /* set ip arp TenGigE1/1/0/1 1.2.3.4 aa:bb:... or aabb.ccdd... */
      if (unformat (input, "%U %U %U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index,
		    unformat_ip46_address, &ip, IP46_TYPE_ANY,
		    unformat_mac_address_t, &mac))
	;
      else if (unformat (input, "delete") || unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "static"))
	{
	  flags |= IP_NEIGHBOR_FLAG_STATIC;
	  flags &= ~IP_NEIGHBOR_FLAG_DYNAMIC;
	}
      else if (unformat (input, "no-fib-entry"))
	flags |= IP_NEIGHBOR_FLAG_NO_FIB_ENTRY;
      else if (unformat (input, "count %d", &count))
	;
      else
	break;
    }

  if (sw_if_index == ~0 ||
      ip46_address_is_zero (&ip) || mac_address_is_zero (&mac))
    return clib_error_return (0,
			      "specify interface, IP address and MAC: `%U'",
			      format_unformat_error, input);

  while (count)
    {
      if (is_add)
	ip_neighbor_add (&ip, ip46_address_get_type (&ip), &mac, sw_if_index,
			 flags, NULL);
      else
	ip_neighbor_del (&ip, ip46_address_get_type (&ip), sw_if_index);

      ip46_address_increment (ip46_address_get_type (&ip), &ip);
      mac_address_increment (&mac);

      --count;
    }

  return NULL;
}

/* *INDENT-OFF* */
/*?
 * Add or delete IPv4 ARP cache entries.
 *
 * @note 'set ip neighbor' options (e.g. delete, static, 'fib-id <id>',
 * 'count <number>', 'interface ip4_addr mac_addr') can be added in
 * any order and combination.
 *
 * @cliexpar
 * @parblock
 * Add or delete IPv4 ARP cache entries as follows. MAC Address can be in
 * either aa:bb:cc:dd:ee:ff format or aabb.ccdd.eeff format.
 * @cliexcmd{set ip neighbor GigabitEthernet2/0/0 6.0.0.3 dead.beef.babe}
 * @cliexcmd{set ip neighbor delete GigabitEthernet2/0/0 6.0.0.3 de:ad:be:ef:ba:be}
 *
 * To add or delete an IPv4 ARP cache entry to or from a specific fib
 * table:
 * @cliexcmd{set ip neighbor fib-id 1 GigabitEthernet2/0/0 6.0.0.3 dead.beef.babe}
 * @cliexcmd{set ip neighbor fib-id 1 delete GigabitEthernet2/0/0 6.0.0.3 dead.beef.babe}
 *
 * Add or delete IPv4 static ARP cache entries as follows:
 * @cliexcmd{set ip neighbor static GigabitEthernet2/0/0 6.0.0.3 dead.beef.babe}
 * @cliexcmd{set ip neighbor static delete GigabitEthernet2/0/0 6.0.0.3 dead.beef.babe}
 *
 * For testing / debugging purposes, the 'set ip neighbor' command can add or
 * delete multiple entries. Supply the 'count N' parameter:
 * @cliexcmd{set ip neighbor count 10 GigabitEthernet2/0/0 6.0.0.3 dead.beef.babe}
 * @endparblock
 ?*/
VLIB_CLI_COMMAND (ip_neighbor_command, static) = {
  .path = "set ip neighbor",
  .short_help =
  "set ip neighbor [del] <intfc> <ip-address> <mac-address> [static] [no-fib-entry] [count <count>] [fib-id <fib-id>] [proxy <lo-addr> - <hi-addr>]",
  .function = ip_neighbor_cmd,
};
VLIB_CLI_COMMAND (ip_neighbor_command2, static) = {
  .path = "ip neighbor",
  .short_help =
  "ip neighbor [del] <intfc> <ip-address> <mac-address> [static] [no-fib-entry] [count <count>] [fib-id <fib-id>] [proxy <lo-addr> - <hi-addr>]",
  .function = ip_neighbor_cmd,
};
/* *INDENT-ON* */

static int
ip_neighbor_sort (void *a1, void *a2)
{
  index_t *ipni1 = a1, *ipni2 = a2;
  ip_neighbor_t *ipn1, *ipn2;
  int cmp;

  ipn1 = ip_neighbor_get (*ipni1);
  ipn2 = ip_neighbor_get (*ipni2);

  cmp = vnet_sw_interface_compare (vnet_get_main (),
				   ipn1->ipn_key->ipnk_sw_if_index,
				   ipn2->ipn_key->ipnk_sw_if_index);
  if (!cmp)
    cmp = ip46_address_cmp (&ipn1->ipn_key->ipnk_ip, &ipn2->ipn_key->ipnk_ip);
  return cmp;
}

static index_t *
ip_neighbor_entries (u32 sw_if_index, ip46_type_t type)
{
  index_t *ipnis = NULL;
  ip_neighbor_t *ipn;

  /* *INDENT-OFF* */
  pool_foreach (ipn, ip_neighbor_pool,
  ({
    if ((sw_if_index == ~0 ||
        ipn->ipn_key->ipnk_sw_if_index == sw_if_index) &&
        (IP46_TYPE_ANY == type ||
         ipn->ipn_key->ipnk_type == type))
       vec_add1 (ipnis, ip_neighbor_get_index(ipn));
  }));

  /* *INDENT-ON* */

  if (ipnis)
    vec_sort_with_function (ipnis, ip_neighbor_sort);
  return ipnis;
}

static clib_error_t *
ip_neighbor_show_sorted_i (vlib_main_t * vm,
			   unformat_input_t * input,
			   vlib_cli_command_t * cmd, ip46_type_t type)
{
  ip_neighbor_elt_t *elt, *head;

  head = pool_elt_at_index (ip_neighbor_elt_pool,
			    ip_neighbor_list_head[type]);


  vlib_cli_output (vm, "%=12s%=40s%=6s%=20s%=24s", "Time", "IP",
		   "Flags", "Ethernet", "Interface");

  /* *INDENT-OFF*/
  /* the list is time sorted, newest first, so start from the back
   * and work forwards. Stop when we get to one that is alive */
  clib_llist_foreach_reverse(ip_neighbor_elt_pool,
                             ipne_anchor, head, elt,
  ({
    vlib_cli_output (vm, "%U", format_ip_neighbor, elt->ipne_index);
  }));
  /* *INDENT-ON*/

  return (NULL);
}

static clib_error_t *
ip_neighbor_show_i (vlib_main_t * vm,
		    unformat_input_t * input,
		    vlib_cli_command_t * cmd, ip46_type_t type)
{
  index_t *ipni, *ipnis = NULL;
  u32 sw_if_index;

  /* Filter entries by interface if given. */
  sw_if_index = ~0;
  (void) unformat_user (input, unformat_vnet_sw_interface, vnet_get_main (),
			&sw_if_index);

  ipnis = ip_neighbor_entries (sw_if_index, type);

  if (ipnis)
    vlib_cli_output (vm, "%=12s%=40s%=6s%=20s%=24s", "Time", "IP",
		     "Flags", "Ethernet", "Interface");

  vec_foreach (ipni, ipnis)
  {
    vlib_cli_output (vm, "%U", format_ip_neighbor, *ipni);
  }
  vec_free (ipnis);

  return (NULL);
}

static clib_error_t *
ip_neighbor_show (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return (ip_neighbor_show_i (vm, input, cmd, IP46_TYPE_ANY));
}

static clib_error_t *
ip6_neighbor_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return (ip_neighbor_show_i (vm, input, cmd, IP46_TYPE_IP6));
}

static clib_error_t *
ip4_neighbor_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return (ip_neighbor_show_i (vm, input, cmd, IP46_TYPE_IP4));
}

static clib_error_t *
ip6_neighbor_show_sorted (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return (ip_neighbor_show_sorted_i (vm, input, cmd, IP46_TYPE_IP6));
}

static clib_error_t *
ip4_neighbor_show_sorted (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return (ip_neighbor_show_sorted_i (vm, input, cmd, IP46_TYPE_IP4));
}

/*?
 * Display all the IP neighbor entries.
 *
 * @cliexpar
 * Example of how to display the IPv4 ARP table:
 * @cliexstart{show ip neighbor}
 *    Time      FIB        IP4       Flags      Ethernet              Interface
 *    346.3028   0       6.1.1.3            de:ad:be:ef:ba:be   GigabitEthernet2/0/0
 *   3077.4271   0       6.1.1.4       S    de:ad:be:ef:ff:ff   GigabitEthernet2/0/0
 *   2998.6409   1       6.2.2.3            de:ad:be:ef:00:01   GigabitEthernet2/0/0
 * Proxy arps enabled for:
 * Fib_index 0   6.0.0.1 - 6.0.0.11
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip_neighbors_cmd_node, static) = {
  .path = "show ip neighbors",
  .function = ip_neighbor_show,
  .short_help = "show ip neighbors [interface]",
};
VLIB_CLI_COMMAND (show_ip4_neighbors_cmd_node, static) = {
  .path = "show ip4 neighbors",
  .function = ip4_neighbor_show,
  .short_help = "show ip4 neighbors [interface]",
};
VLIB_CLI_COMMAND (show_ip6_neighbors_cmd_node, static) = {
  .path = "show ip6 neighbors",
  .function = ip6_neighbor_show,
  .short_help = "show ip6 neighbors [interface]",
};
VLIB_CLI_COMMAND (show_ip_neighbor_cmd_node, static) = {
  .path = "show ip neighbor",
  .function = ip_neighbor_show,
  .short_help = "show ip neighbor [interface]",
};
VLIB_CLI_COMMAND (show_ip4_neighbor_cmd_node, static) = {
  .path = "show ip4 neighbor",
  .function = ip4_neighbor_show,
  .short_help = "show ip4 neighbor [interface]",
};
VLIB_CLI_COMMAND (show_ip6_neighbor_cmd_node, static) = {
  .path = "show ip6 neighbor",
  .function = ip6_neighbor_show,
  .short_help = "show ip6 neighbor [interface]",
};
VLIB_CLI_COMMAND (show_ip4_neighbor_sorted_cmd_node, static) = {
  .path = "show ip4 neighbor-sorted",
  .function = ip4_neighbor_show_sorted,
  .short_help = "show ip4 neighbor-sorted",
};
VLIB_CLI_COMMAND (show_ip6_neighbor_sorted_cmd_node, static) = {
  .path = "show ip6 neighbor-sorted",
  .function = ip6_neighbor_show_sorted,
  .short_help = "show ip6 neighbor-sorted",
};
/* *INDENT-ON* */

static ip_neighbor_vft_t ip_nbr_vfts[IP46_N_TYPES];

void
ip_neighbor_register (ip46_type_t type, const ip_neighbor_vft_t * vft)
{
  ip_nbr_vfts[type] = *vft;
}

void
ip_neighbor_probe_dst (const ip_adjacency_t * adj, const ip46_address_t * dst)
{
  if (!vnet_sw_interface_is_admin_up (vnet_get_main (),
				      adj->rewrite_header.sw_if_index))
    return;

  switch (adj->ia_nh_proto)
    {
    case FIB_PROTOCOL_IP6:
      ip6_neighbor_probe_dst (adj, &dst->ip6);
      break;
    case FIB_PROTOCOL_IP4:
      ip4_neighbor_probe_dst (adj, &dst->ip4);
      break;
    case FIB_PROTOCOL_MPLS:
      ASSERT (0);
      break;
    }
}

void
ip_neighbor_probe (const ip_adjacency_t * adj)
{
  ip_neighbor_probe_dst (adj, &adj->sub_type.nbr.next_hop);
}

void
ip_neighbor_advertise (vlib_main_t * vm,
		       ip46_type_t type,
		       const ip46_address_t * addr, u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();

  if (type == IP46_TYPE_IP4 || type == IP46_TYPE_BOTH)
    ip4_neighbor_advertise (vm, vnm, sw_if_index, (addr) ? &addr->ip4 : NULL);
  if (type == IP46_TYPE_IP6 || type == IP46_TYPE_BOTH)
    ip6_neighbor_advertise (vm, vnm, sw_if_index, (addr) ? &addr->ip6 : NULL);
}

void
ip_neighbor_walk (ip46_type_t type,
		  u32 sw_if_index, ip_neighbor_walk_cb_t cb, void *ctx)
{
  ip_neighbor_key_t *key;
  index_t ipni;

  if (~0 == sw_if_index)
    {
      uword **hash;

      vec_foreach (hash, ip_neighbor_db[type].ipndb_hash)
      {
          /* *INDENT-OFF* */
          hash_foreach (key, ipni, *hash,
          ({
            if (WALK_STOP == cb (ipni, ctx))
	      break;
          }));
          /* *INDENT-ON* */
      }
    }
  else
    {
      uword *hash;

      if (vec_len (ip_neighbor_db[type].ipndb_hash) <= sw_if_index)
	return;
      hash = ip_neighbor_db[type].ipndb_hash[sw_if_index];

      /* *INDENT-OFF* */
      hash_foreach (key, ipni, hash,
      ({
        if (WALK_STOP == cb (ipni, ctx))
	  break;
      }));
      /* *INDENT-ON* */
    }
}

int
ip4_neighbor_proxy_add (u32 fib_index,
			const ip4_address_t * start,
			const ip4_address_t * end)
{
  if (ip_nbr_vfts[IP46_TYPE_IP4].inv_proxy4_add)
    {
      return (ip_nbr_vfts[IP46_TYPE_IP4].inv_proxy4_add
	      (fib_index, start, end));
    }

  return (-1);
}

int
ip4_neighbor_proxy_delete (u32 fib_index,
			   const ip4_address_t * start,
			   const ip4_address_t * end)
{
  if (ip_nbr_vfts[IP46_TYPE_IP4].inv_proxy4_del)
    {
      return (ip_nbr_vfts[IP46_TYPE_IP4].inv_proxy4_del
	      (fib_index, start, end));
    }
  return -1;
}

int
ip4_neighbor_proxy_enable (u32 sw_if_index)
{
  if (ip_nbr_vfts[IP46_TYPE_IP4].inv_proxy4_enable)
    {
      return (ip_nbr_vfts[IP46_TYPE_IP4].inv_proxy4_enable (sw_if_index));
    }
  return -1;
}

int
ip4_neighbor_proxy_disable (u32 sw_if_index)
{
  if (ip_nbr_vfts[IP46_TYPE_IP4].inv_proxy4_disable)
    {
      return (ip_nbr_vfts[IP46_TYPE_IP4].inv_proxy4_disable (sw_if_index));
    }
  return -1;
}

int
ip6_neighbor_proxy_add (u32 sw_if_index, const ip6_address_t * addr)
{
  if (ip_nbr_vfts[IP46_TYPE_IP6].inv_proxy6_add)
    {
      return (ip_nbr_vfts[IP46_TYPE_IP6].inv_proxy6_add (sw_if_index, addr));
    }
  return -1;
}

int
ip6_neighbor_proxy_del (u32 sw_if_index, const ip6_address_t * addr)
{
  if (ip_nbr_vfts[IP46_TYPE_IP6].inv_proxy6_del)
    {
      return (ip_nbr_vfts[IP46_TYPE_IP6].inv_proxy6_del (sw_if_index, addr));
    }
  return -1;
}

static void
ip_neighbor_ethernet_change_mac (ethernet_main_t * em,
				 u32 sw_if_index, uword opaque)
{
  ip_neighbor_t *ipn;
  adj_index_t ai;

  IP_NEIGHBOR_DBG ("mac-change: %U",
		   format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);

  /* *INDENT-OFF* */
  pool_foreach (ipn, ip_neighbor_pool,
  ({
    if (ipn->ipn_key->ipnk_sw_if_index == sw_if_index)
      adj_nbr_walk_nh (ipn->ipn_key->ipnk_sw_if_index,
                       fib_proto_from_ip46(ipn->ipn_key->ipnk_type),
                       &ipn->ipn_key->ipnk_ip,
                       ip_neighbor_mk_complete_walk,
                       ipn);
  }));
  /* *INDENT-ON* */

  ai = adj_glean_get (FIB_PROTOCOL_IP4, sw_if_index);

  if (ADJ_INDEX_INVALID != ai)
    adj_glean_update_rewrite (ai);
}

void
ip_neighbor_populate (ip46_type_t type, u32 sw_if_index)
{
  index_t *ipnis = NULL, *ipni;
  ip_neighbor_t *ipn;

  IP_NEIGHBOR_DBG ("populate: %U %U",
		   format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index, format_ip46_type, type);

  /* *INDENT-OFF* */
  pool_foreach (ipn, ip_neighbor_pool,
  ({
    if (ipn->ipn_key->ipnk_type == type &&
        ipn->ipn_key->ipnk_sw_if_index == sw_if_index)
      vec_add1 (ipnis, ipn - ip_neighbor_pool);
  }));
  /* *INDENT-ON* */

  vec_foreach (ipni, ipnis)
  {
    ipn = ip_neighbor_get (*ipni);

    adj_nbr_walk_nh (ipn->ipn_key->ipnk_sw_if_index,
		     fib_proto_from_ip46 (ipn->ipn_key->ipnk_type),
		     &ipn->ipn_key->ipnk_ip,
		     ip_neighbor_mk_complete_walk, ipn);
  }
  vec_free (ipnis);
}

void
ip_neighbor_flush (ip46_type_t type, u32 sw_if_index)
{
  index_t *ipnis = NULL, *ipni;
  ip_neighbor_t *ipn;

  IP_NEIGHBOR_DBG ("flush: %U %U",
		   format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index, format_ip46_type, type);

  /* *INDENT-OFF* */
  pool_foreach (ipn, ip_neighbor_pool,
  ({
    if (ipn->ipn_key->ipnk_type == type &&
        ipn->ipn_key->ipnk_sw_if_index == sw_if_index &&
        ip_neighbor_is_dynamic (ipn))
      vec_add1 (ipnis, ipn - ip_neighbor_pool);
  }));
  /* *INDENT-ON* */

  vec_foreach (ipni, ipnis) ip_neighbor_destroy (ip_neighbor_get (*ipni));
  vec_free (ipnis);
}

static walk_rc_t
ip_neighbor_mark_one (index_t ipni, void *ctx)
{
  ip_neighbor_t *ipn;

  ipn = ip_neighbor_get (ipni);

  ipn->ipn_flags |= IP_NEIGHBOR_FLAG_STALE;

  return (WALK_CONTINUE);
}

void
ip_neighbor_mark (ip46_type_t type)
{
  ip_neighbor_walk (type, ~0, ip_neighbor_mark_one, NULL);
}

typedef struct ip_neighbor_sweep_ctx_t_
{
  index_t *ipnsc_stale;
} ip_neighbor_sweep_ctx_t;

static walk_rc_t
ip_neighbor_sweep_one (index_t ipni, void *arg)
{
  ip_neighbor_sweep_ctx_t *ctx = arg;
  ip_neighbor_t *ipn;

  ipn = ip_neighbor_get (ipni);

  if (ipn->ipn_flags & IP_NEIGHBOR_FLAG_STALE)
    {
      vec_add1 (ctx->ipnsc_stale, ipni);
    }

  return (WALK_CONTINUE);
}

void
ip_neighbor_sweep (ip46_type_t type)
{
  ip_neighbor_sweep_ctx_t ctx = { };
  index_t *ipni;

  ip_neighbor_walk (type, ~0, ip_neighbor_sweep_one, &ctx);

  vec_foreach (ipni, ctx.ipnsc_stale)
  {
    ip_neighbor_destroy (ip_neighbor_get (*ipni));
  }
  vec_free (ctx.ipnsc_stale);
}

/*
 * Remove any arp entries associated with the specified interface
 */
static clib_error_t *
ip_neighbor_interface_admin_change (vnet_main_t * vnm,
				    u32 sw_if_index, u32 flags)
{
  ip46_type_t type;

  IP_NEIGHBOR_DBG ("interface-admin: %U  %s",
		   format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index,
		   (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP ? "up" : "down"));

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    {
      FOREACH_IP46_TYPE (type) ip_neighbor_populate (type, sw_if_index);
    }
  else
    {
      /* admin down, flush all neighbours */
      FOREACH_IP46_TYPE (type) ip_neighbor_flush (type, sw_if_index);
    }

  return (NULL);
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (ip_neighbor_interface_admin_change);

/*
 * Remove any arp entries associated with the specified interface
 */
static clib_error_t *
ip_neighbor_delete_sw_interface (vnet_main_t * vnm,
				 u32 sw_if_index, u32 is_add)
{
  IP_NEIGHBOR_DBG ("interface-change: %U  %s",
		   format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index, (is_add ? "add" : "del"));

  if (!is_add && sw_if_index != ~0)
    {
      ip46_type_t type;

      FOREACH_IP46_TYPE (type) ip_neighbor_flush (type, sw_if_index);
    }

  return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ip_neighbor_delete_sw_interface);

typedef struct ip_neighbor_walk_covered_ctx_t_
{
  ip46_type_t type;
  ip46_address_t addr;
  u32 length;
  index_t *ipnis;
} ip_neighbor_walk_covered_ctx_t;

static walk_rc_t
ip_neighbor_walk_covered (index_t ipni, void *arg)
{
  ip_neighbor_walk_covered_ctx_t *ctx = arg;
  ip_neighbor_t *ipn;

  ipn = ip_neighbor_get (ipni);

  ASSERT (ipn->ipn_key->ipnk_type == ctx->type);

  if (IP46_TYPE_IP4 == ctx->type)
    {
      if (ip4_destination_matches_route (&ip4_main,
					 &ipn->ipn_key->ipnk_ip.ip4,
					 &ctx->addr.ip4,
					 ctx->length) &&
	  ip_neighbor_is_dynamic (ipn))
	{
	  vec_add1 (ctx->ipnis, ip_neighbor_get_index (ipn));
	}
    }
  return (WALK_CONTINUE);
}


/*
 * callback when an interface address is added or deleted
 */
static void
ip_neighbor_add_del_interface_address_v4 (ip4_main_t * im,
					  uword opaque,
					  u32 sw_if_index,
					  ip4_address_t * address,
					  u32 address_length,
					  u32 if_address_index, u32 is_del)
{
  /*
   * Flush the ARP cache of all entries covered by the address
   * that is being removed.
   */
  IP_NEIGHBOR_DBG ("addr-%d: %U, %U/%d",
		   (is_del ? "del" : "add"),
		   format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index, format_ip4_address, address, address_length);

  if (is_del)
    {
      ip_neighbor_walk_covered_ctx_t ctx = {
	.addr.ip4 = *address,
	.type = IP46_TYPE_IP4,
	.length = address_length,
      };
      index_t *ipni;

      ip_neighbor_walk (IP46_TYPE_IP4, sw_if_index,
			ip_neighbor_walk_covered, &ctx);

      vec_foreach (ipni, ctx.ipnis)
	ip_neighbor_destroy (ip_neighbor_get (*ipni));

      vec_free (ctx.ipnis);
    }
}

/*
 * callback when an interface address is added or deleted
 */
static void
ip_neighbor_add_del_interface_address_v6 (ip6_main_t * im,
					  uword opaque,
					  u32 sw_if_index,
					  ip6_address_t * address,
					  u32 address_length,
					  u32 if_address_index, u32 is_del)
{
  /*
   * Flush the ARP cache of all entries covered by the address
   * that is being removed.
   */
  IP_NEIGHBOR_DBG ("addr-change: %U, %U/%d %s",
		   format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index, format_ip6_address, address, address_length,
		   (is_del ? "del" : "add"));

  if (is_del)
    {
      ip_neighbor_walk_covered_ctx_t ctx = {
	.addr.ip6 = *address,
	.type = IP46_TYPE_IP6,
	.length = address_length,
      };
      index_t *ipni;

      ip_neighbor_walk (IP46_TYPE_IP6, sw_if_index,
			ip_neighbor_walk_covered, &ctx);

      vec_foreach (ipni, ctx.ipnis)
	ip_neighbor_destroy (ip_neighbor_get (*ipni));

      vec_free (ctx.ipnis);
    }
}

typedef struct ip_neighbor_table_bind_ctx_t_
{
  u32 new_fib_index;
  u32 old_fib_index;
} ip_neighbor_table_bind_ctx_t;

static walk_rc_t
ip_neighbor_walk_table_bind (index_t ipni, void *arg)
{
  ip_neighbor_table_bind_ctx_t *ctx = arg;
  ip_neighbor_t *ipn;

  ipn = ip_neighbor_get (ipni);
  ip_neighbor_adj_fib_remove (ipn, ctx->old_fib_index);
  ip_neighbor_adj_fib_add (ipn, ctx->new_fib_index);

  return (WALK_CONTINUE);
}

static void
ip_neighbor_table_bind_v4 (ip4_main_t * im,
			   uword opaque,
			   u32 sw_if_index,
			   u32 new_fib_index, u32 old_fib_index)
{
  ip_neighbor_table_bind_ctx_t ctx = {
    .old_fib_index = old_fib_index,
    .new_fib_index = new_fib_index,
  };

  ip_neighbor_walk (IP46_TYPE_IP4, sw_if_index,
		    ip_neighbor_walk_table_bind, &ctx);
}

static void
ip_neighbor_table_bind_v6 (ip6_main_t * im,
			   uword opaque,
			   u32 sw_if_index,
			   u32 new_fib_index, u32 old_fib_index)
{
  ip_neighbor_table_bind_ctx_t ctx = {
    .old_fib_index = old_fib_index,
    .new_fib_index = new_fib_index,
  };

  ip_neighbor_walk (IP46_TYPE_IP6, sw_if_index,
		    ip_neighbor_walk_table_bind, &ctx);
}

typedef enum ip_neighbor_age_state_t_
{
  IP_NEIGHBOR_AGE_ALIVE,
  IP_NEIGHBOR_AGE_PROBE,
  IP_NEIGHBOR_AGE_DEAD,
} ip_neighbor_age_state_t;

#define IP_NEIGHBOR_PROCESS_SLEEP_LONG (0)

static ip_neighbor_age_state_t
ip_neighbour_age_out (index_t ipni, f64 now, f64 * wait)
{
  ip_neighbor_t *ipn;
  u32 ipndb_age;
  u32 ttl;

  ipn = ip_neighbor_get (ipni);
  ipndb_age = ip_neighbor_db[ipn->ipn_key->ipnk_type].ipndb_age;
  ttl = now - ipn->ipn_time_last_updated;
  *wait = ipndb_age;

  if (ttl > ipndb_age)
    {
      IP_NEIGHBOR_DBG ("aged: %U @%f - %f > %d",
		       format_ip_neighbor, ipni, now,
		       ipn->ipn_time_last_updated, ipndb_age);
      if (ipn->ipn_n_probes > 2)
	{
	  /* 3 strikes and yea-re out */
	  IP_NEIGHBOR_DBG ("dead: %U", format_ip_neighbor, ipni);
	  *wait = 1;
	  return (IP_NEIGHBOR_AGE_DEAD);
	}
      else
	{
	  adj_index_t ai;

	  ai = adj_glean_get (fib_proto_from_ip46 (ipn->ipn_key->ipnk_type),
			      ip_neighbor_get_sw_if_index (ipn));

	  if (ADJ_INDEX_INVALID != ai)
	    ip_neighbor_probe_dst (adj_get (ai), ip_neighbor_get_ip (ipn));

	  ipn->ipn_n_probes++;
	  *wait = 1;
	}
    }
  else
    {
      /* here we are sure that ttl <= ipndb_age */
      *wait = ipndb_age - ttl + 1;
      return (IP_NEIGHBOR_AGE_ALIVE);
    }

  return (IP_NEIGHBOR_AGE_PROBE);
}

typedef enum ip_neighbor_process_event_t_
{
  IP_NEIGHBOR_AGE_PROCESS_WAKEUP,
} ip_neighbor_process_event_t;

static uword
ip_neighbor_age_loop (vlib_main_t * vm,
		      vlib_node_runtime_t * rt,
		      vlib_frame_t * f, ip46_type_t type)
{
  uword event_type, *event_data = NULL;
  f64 timeout;

  /* Set the timeout to an effectively infinite value when the process starts */
  timeout = IP_NEIGHBOR_PROCESS_SLEEP_LONG;

  while (1)
    {
      f64 now;

      if (!timeout)
	vlib_process_wait_for_event (vm);
      else
	vlib_process_wait_for_event_or_clock (vm, timeout);

      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      now = vlib_time_now (vm);

      switch (event_type)
	{
	case ~0:
	  {
	    /* timer expired */
	    ip_neighbor_elt_t *elt, *head;
	    f64 wait;

	    timeout = ip_neighbor_db[type].ipndb_age;
	    head = pool_elt_at_index (ip_neighbor_elt_pool,
				      ip_neighbor_list_head[type]);

          /* *INDENT-OFF*/
          /* the list is time sorted, newest first, so start from the back
           * and work forwards. Stop when we get to one that is alive */
          restart:
          clib_llist_foreach_reverse(ip_neighbor_elt_pool,
                                     ipne_anchor, head, elt,
          ({
            ip_neighbor_age_state_t res;

            res = ip_neighbour_age_out(elt->ipne_index, now, &wait);

            if (IP_NEIGHBOR_AGE_ALIVE == res) {
              /* the oldest neighbor has not yet expired, go back to sleep */
              timeout = clib_min (wait, timeout);
              break;
            }
            else if (IP_NEIGHBOR_AGE_DEAD == res) {
              /* the oldest neighbor is dead, pop it, then restart the walk
               * again from the back */
              ip_neighbor_destroy (ip_neighbor_get(elt->ipne_index));
              goto restart;
            }

            timeout = clib_min (wait, timeout);
          }));
          /* *INDENT-ON* */
	    break;
	  }
	case IP_NEIGHBOR_AGE_PROCESS_WAKEUP:
	  {

	    if (!ip_neighbor_db[type].ipndb_age)
	      {
		/* aging has been disabled */
		timeout = 0;
		break;
	      }
	    ip_neighbor_elt_t *elt, *head;

	    head = pool_elt_at_index (ip_neighbor_elt_pool,
				      ip_neighbor_list_head[type]);
	    /* no neighbors yet */
	    if (clib_llist_is_empty (ip_neighbor_elt_pool, ipne_anchor, head))
	      {
		timeout = ip_neighbor_db[type].ipndb_age;
		break;
	      }

	    /* poke the oldset neighbour for aging, which returns how long we sleep for */
	    elt = clib_llist_prev (ip_neighbor_elt_pool, ipne_anchor, head);
	    ip_neighbour_age_out (elt->ipne_index, now, &timeout);
	    break;
	  }
	}
    }
  return 0;
}

static uword
ip4_neighbor_age_process (vlib_main_t * vm,
			  vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  return (ip_neighbor_age_loop (vm, rt, f, IP46_TYPE_IP4));
}

static uword
ip6_neighbor_age_process (vlib_main_t * vm,
			  vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  return (ip_neighbor_age_loop (vm, rt, f, IP46_TYPE_IP6));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_neighbor_age_process_node,static) = {
  .function = ip4_neighbor_age_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ip4-neighbor-age-process",
};
VLIB_REGISTER_NODE (ip6_neighbor_age_process_node,static) = {
  .function = ip6_neighbor_age_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ip6-neighbor-age-process",
};
/* *INDENT-ON* */

int
ip_neighbor_config (ip46_type_t type, u32 limit, u32 age, bool recycle)
{
  ip_neighbor_db[type].ipndb_limit = limit;
  ip_neighbor_db[type].ipndb_recycle = recycle;
  ip_neighbor_db[type].ipndb_age = age;

  vlib_process_signal_event (vlib_get_main (),
			     (IP46_TYPE_IP4 == type ?
			      ip4_neighbor_age_process_node.index :
			      ip6_neighbor_age_process_node.index),
			     IP_NEIGHBOR_AGE_PROCESS_WAKEUP, 0);

  return (0);
}

static clib_error_t *
ip_neighbor_config_show (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip46_type_t type;

  /* *INDENT-OFF* */
  FOREACH_IP46_TYPE(type) {
    vlib_cli_output (vm, "%U:", format_ip46_type, type);
    vlib_cli_output (vm, "  limit:%d, age:%d, recycle:%d",
                     ip_neighbor_db[type].ipndb_limit,
                     ip_neighbor_db[type].ipndb_age,
                     ip_neighbor_db[type].ipndb_recycle);
  }

  /* *INDENT-ON* */
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip_neighbor_cfg_cmd_node, static) = {
  .path = "show ip neighbor-config",
  .function = ip_neighbor_config_show,
  .short_help = "show ip neighbor-config",
};
/* *INDENT-ON* */

static clib_error_t *
ip_neighbor_init (vlib_main_t * vm)
{
  {
    ip4_add_del_interface_address_callback_t cb = {
      .function = ip_neighbor_add_del_interface_address_v4,
    };
    vec_add1 (ip4_main.add_del_interface_address_callbacks, cb);
  }
  {
    ip6_add_del_interface_address_callback_t cb = {
      .function = ip_neighbor_add_del_interface_address_v6,
    };
    vec_add1 (ip6_main.add_del_interface_address_callbacks, cb);
  }
  {
    ip4_table_bind_callback_t cb = {
      .function = ip_neighbor_table_bind_v4,
    };
    vec_add1 (ip4_main.table_bind_callbacks, cb);
  }
  {
    ip6_table_bind_callback_t cb = {
      .function = ip_neighbor_table_bind_v6,
    };
    vec_add1 (ip6_main.table_bind_callbacks, cb);
  }
  {
    ethernet_address_change_ctx_t ctx = {
      .function = ip_neighbor_ethernet_change_mac,
      .function_opaque = 0,
    };
    vec_add1 (ethernet_main.address_change_callbacks, ctx);
  }

  ipn_logger = vlib_log_register_class ("ip", "neighbor");

  ip46_type_t type;

  FOREACH_IP46_TYPE (type)
    ip_neighbor_list_head[type] =
    clib_llist_make_head (ip_neighbor_elt_pool, ipne_anchor);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (ip_neighbor_init) =
{
  .runs_after = VLIB_INITS("ip_main_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
