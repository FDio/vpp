/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/adj/adj.h>
#include <vnet/adj/adj_alloc.h>
#include <vnet/adj/adj_internal.h>
#include <vnet/adj/adj_glean.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/fib/fib_node_list.h>

/*
 * Special Adj with index zero. we need to define this since the v4 mtrie
 * assumes an index of 0 implies the ply is empty. therefore all 'real'
 * adjs need a non-zero index.
 */
static ip_adjacency_t *special_v4_miss_adj_with_index_zero;

/* Adjacency packet/byte counters indexed by adjacency index. */
vlib_combined_counter_main_t adjacency_counters;

always_inline void
adj_poison (ip_adjacency_t * adj)
{
    if (CLIB_DEBUG > 0)
    {
	u32 save_handle = adj->heap_handle;;

	memset (adj, 0xfe, sizeof (adj[0]));

	adj->heap_handle = save_handle;
    }
}

ip_adjacency_t *
adj_alloc (fib_protocol_t proto)
{
    ip_adjacency_t *adj;

    adj = aa_alloc();

    adj_poison(adj);

    /* Make sure certain fields are always initialized. */
    /* Validate adjacency counters. */
    vlib_validate_combined_counter(&adjacency_counters,
                                   adj->heap_handle);

    adj->rewrite_header.sw_if_index = ~0;
    adj->mcast_group_index = ~0;
    adj->saved_lookup_next_index = 0;
    adj->n_adj = 1;

    fib_node_init(&adj->ia_node,
                  FIB_NODE_TYPE_ADJ);
    adj->ia_nh_proto = proto;

    return (adj);
}

static int
adj_index_is_special (adj_index_t adj_index)
{
    if (ADJ_INDEX_INVALID == adj_index)
	return (!0);

    return (0);
}

/**
 * @brief Pretty print helper function for formatting specific adjacencies.
 * @param s - input string to format
 * @param args - other args passed to format function such as:
 *                 - vnet_main_t
 *                 - ip_lookup_main_t
 *                 - adj_index
 */
u8 *
format_ip_adjacency (u8 * s, va_list * args)
{
  vnet_main_t * vnm = va_arg (*args, vnet_main_t *);
  u32 adj_index = va_arg (*args, u32);
  format_ip_adjacency_flags_t fiaf = va_arg (*args, format_ip_adjacency_flags_t);
  ip_adjacency_t * adj = adj_get(adj_index);
  
  switch (adj->lookup_next_index)
  {
  case IP_LOOKUP_NEXT_REWRITE:
      s = format (s, "%U", format_adj_nbr, adj_index, 0);
      break;
  case IP_LOOKUP_NEXT_ARP:
      s = format (s, "%U", format_adj_nbr_incomplete, adj_index, 0);
      break;
  case IP_LOOKUP_NEXT_GLEAN:
      s = format (s, " %U",
		  format_vnet_sw_interface_name,
		  vnm,
		  vnet_get_sw_interface(vnm,
					adj->rewrite_header.sw_if_index));
      break;

  case IP_LOOKUP_NEXT_MIDCHAIN:
      s = format (s, "%U", format_adj_midchain, adj_index, 2);
      break;
  default:
      break;
  }
  s = format (s, " index:%d", adj_index);

  if (fiaf & FORMAT_IP_ADJACENCY_DETAIL)
  {
      s = format (s, " locks:%d", adj->ia_node.fn_locks);
      s = format(s, "\nchildren:\n ");
      s = fib_node_children_format(adj->ia_node.fn_children, s);
  }

  return s;
}

/*
 * adj_last_lock_gone
 *
 * last lock/reference to the adj has gone, we no longer need it.
 */
static void
adj_last_lock_gone (ip_adjacency_t *adj)
{
    ASSERT(0 == fib_node_list_get_size(adj->ia_node.fn_children));
    ADJ_DBG(adj, "last-lock-gone");

    switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_MIDCHAIN:
        dpo_reset(&adj->sub_type.midchain.next_dpo);
        /* FALL THROUGH */
    case IP_LOOKUP_NEXT_ARP:
    case IP_LOOKUP_NEXT_REWRITE:
	/*
	 * complete and incomplete nbr adjs
	 */
	adj_nbr_remove(adj->ia_nh_proto,
		       adj->ia_link,
		       &adj->sub_type.nbr.next_hop,
		       adj->rewrite_header.sw_if_index);
	break;
    case IP_LOOKUP_NEXT_GLEAN:
	adj_glean_remove(adj->ia_nh_proto,
			 adj->rewrite_header.sw_if_index);
	break;
    default:
	/*
	 * type not stored in any DB from which we need to remove it
	 */
	break;
    }

    fib_node_deinit(&adj->ia_node);
    aa_free(adj);
}

void
adj_lock (adj_index_t adj_index)
{
    ip_adjacency_t *adj;

    if (adj_index_is_special(adj_index))
    {
	return;
    }

    adj = adj_get(adj_index);
    ASSERT(adj);
    ASSERT(adj->heap_handle!=0);

    ADJ_DBG(adj, "lock");
    fib_node_lock(&adj->ia_node);
}

void
adj_unlock (adj_index_t adj_index)
{
    ip_adjacency_t *adj;

    if (adj_index_is_special(adj_index))
    {
	return;
    }

    adj = adj_get(adj_index);
    ASSERT(adj);
    ASSERT(adj->heap_handle!=0);

    ADJ_DBG(adj, "unlock");
    ASSERT(adj);
    ASSERT(adj->heap_handle!=0);

    fib_node_unlock(&adj->ia_node);
}

u32
adj_child_add (adj_index_t adj_index,
	       fib_node_type_t child_type,
	       fib_node_index_t child_index)
{
    ASSERT(ADJ_INDEX_INVALID != adj_index);
    if (adj_index_is_special(adj_index))
    {
	return (~0);
    }

    return (fib_node_child_add(FIB_NODE_TYPE_ADJ,
                               adj_index,
                               child_type,
                               child_index));
}

void
adj_child_remove (adj_index_t adj_index,
		  u32 sibling_index)
{
    if (adj_index_is_special(adj_index))
    {
	return;
    }

    fib_node_child_remove(FIB_NODE_TYPE_ADJ,
                          adj_index,
                          sibling_index);
}

static fib_node_t *
adj_get_node (fib_node_index_t index)
{
    ip_adjacency_t *adj;

    adj = adj_get(index);

    return (&adj->ia_node);
}

#define ADJ_FROM_NODE(_node)						\
    ((ip_adjacency_t*)((char*)_node - STRUCT_OFFSET_OF(ip_adjacency_t, ia_node)))

static void
adj_node_last_lock_gone (fib_node_t *node)
{
    adj_last_lock_gone(ADJ_FROM_NODE(node));
}

static fib_node_back_walk_rc_t
adj_back_walk_notify (fib_node_t *node,
		      fib_node_back_walk_ctx_t *ctx)
{
    /*
     * Que pasa. yo soj en el final!
     */
    ASSERT(0);

    return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * Adjacency's graph node virtual function table
 */
static const fib_node_vft_t adj_vft = {
    .fnv_get = adj_get_node,
    .fnv_last_lock = adj_node_last_lock_gone,
    .fnv_back_walk = adj_back_walk_notify,
};

static clib_error_t *
adj_module_init (vlib_main_t * vm)
{
    fib_node_register_type(FIB_NODE_TYPE_ADJ, &adj_vft);

    adj_nbr_module_init();
    adj_glean_module_init();
    adj_midchain_module_init();

    /*
     * 4 special adjs for v4 and v6 resp.
     */
    aa_bootstrap(8);
    special_v4_miss_adj_with_index_zero = adj_alloc(FIB_PROTOCOL_IP4);

    return (NULL);
}

VLIB_INIT_FUNCTION (adj_module_init);

/* 
 * DEPRECATED: DO NOT USE
 *
 * Create new block of given number of contiguous adjacencies.
 */
ip_adjacency_t *
ip_add_adjacency (ip_lookup_main_t * lm,
		  ip_adjacency_t * copy_adj,
		  u32 n_adj,
		  u32 * adj_index_return)
{
  ip_adjacency_t * adj;
  u32 ai, i, handle;

  ASSERT(1==n_adj);

  adj = aa_alloc ();
  handle = ai = adj->heap_handle;

  /* Validate adjacency counters. */
  vlib_validate_combined_counter (&adjacency_counters, ai + n_adj - 1);

  for (i = 0; i < n_adj; i++)
    {
      /* Make sure certain fields are always initialized. */
      adj[i].rewrite_header.sw_if_index = ~0;
      adj[i].mcast_group_index = ~0;
      adj[i].saved_lookup_next_index = 0;

      if (copy_adj)
	adj[i] = copy_adj[i];

      adj[i].heap_handle = handle;
      adj[i].n_adj = n_adj;

      /* Zero possibly stale counters for re-used adjacencies. */
      vlib_zero_combined_counter (&adjacency_counters, ai + i);
    }

  *adj_index_return = ai;
  return adj;
}
