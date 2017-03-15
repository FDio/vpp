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
#include <vnet/adj/adj_internal.h>
#include <vnet/adj/adj_glean.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/fib/fib_node_list.h>

/*
 * Special Adj with index zero. we need to define this since the v4 mtrie
 * assumes an index of 0 implies the ply is empty. therefore all 'real'
 * adjs need a non-zero index.
 */
static ip_adjacency_t *special_v4_miss_adj_with_index_zero;

/* Adjacency packet/byte counters indexed by adjacency index. */
vlib_combined_counter_main_t adjacency_counters;

/*
 * the single adj pool
 */
ip_adjacency_t *adj_pool;

/**
 * @brief Global Config for enabling per-adjacency counters.
 * By default these are disabled.
 */
int adj_per_adj_counters;

always_inline void
adj_poison (ip_adjacency_t * adj)
{
    if (CLIB_DEBUG > 0)
    {
	memset (adj, 0xfe, sizeof (adj[0]));
    }
}

ip_adjacency_t *
adj_alloc (fib_protocol_t proto)
{
    ip_adjacency_t *adj;

    pool_get(adj_pool, adj);

    adj_poison(adj);

    /* Make sure certain fields are always initialized. */
    /* Validate adjacency counters. */
    vlib_validate_combined_counter(&adjacency_counters,
                                   adj_get_index(adj));

    adj->rewrite_header.sw_if_index = ~0;
    adj->n_adj = 1;
    adj->lookup_next_index = 0;

    fib_node_init(&adj->ia_node,
                  FIB_NODE_TYPE_ADJ);
    adj->ia_nh_proto = proto;
    adj->ia_flags = 0;

    ip4_main.lookup_main.adjacency_heap = adj_pool;
    ip6_main.lookup_main.adjacency_heap = adj_pool;

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
    format_ip_adjacency_flags_t fiaf;
    ip_adjacency_t * adj;
    u32 adj_index;

    adj_index = va_arg (*args, u32);
    fiaf = va_arg (*args, format_ip_adjacency_flags_t);
    adj = adj_get(adj_index);
  
    switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_REWRITE:
	s = format (s, "%U", format_adj_nbr, adj_index, 0);
	break;
    case IP_LOOKUP_NEXT_ARP:
	s = format (s, "%U", format_adj_nbr_incomplete, adj_index, 0);
	break;
    case IP_LOOKUP_NEXT_GLEAN:
	s = format (s, "%U", format_adj_glean, adj_index, 0);
	break;
    case IP_LOOKUP_NEXT_MIDCHAIN:
	s = format (s, "%U", format_adj_midchain, adj_index, 2);
	break;
    case IP_LOOKUP_NEXT_MCAST:
	s = format (s, "%U", format_adj_mcast, adj_index, 0);
	break;
    default:
	break;
    }

    if (fiaf & FORMAT_IP_ADJACENCY_DETAIL)
    {
        vlib_counter_t counts;

        vlib_get_combined_counter(&adjacency_counters, adj_index, &counts);
        s = format (s, "\n counts:[%Ld:%Ld]", counts.packets, counts.bytes);
	s = format (s, "\n locks:%d", adj->ia_node.fn_locks);
	s = format(s, "\n children:\n  ");
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
    vlib_main_t * vm = vlib_get_main();

    ASSERT(0 == fib_node_list_get_size(adj->ia_node.fn_children));
    ADJ_DBG(adj, "last-lock-gone");

    vlib_worker_thread_barrier_sync (vm);

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
	adj_nbr_remove(adj_get_index(adj),
                       adj->ia_nh_proto,
		       adj->ia_link,
		       &adj->sub_type.nbr.next_hop,
		       adj->rewrite_header.sw_if_index);
	break;
    case IP_LOOKUP_NEXT_GLEAN:
	adj_glean_remove(adj->ia_nh_proto,
			 adj->rewrite_header.sw_if_index);
	break;
    case IP_LOOKUP_NEXT_MCAST:
	adj_mcast_remove(adj->ia_nh_proto,
			 adj->rewrite_header.sw_if_index);
	break;
    default:
	/*
	 * type not stored in any DB from which we need to remove it
	 */
	break;
    }

    vlib_worker_thread_barrier_release(vm);

    fib_node_deinit(&adj->ia_node);
    pool_put(adj_pool, adj);
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

    ADJ_DBG(adj, "unlock");
    ASSERT(adj);

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

/*
 * Context for the walk to update the cached feture flags.
 */
typedef struct adj_feature_update_t_
{
    u8 arc;
    u8 enable;
} adj_feature_update_ctx_t;

static adj_walk_rc_t
adj_feature_update_walk_cb (adj_index_t ai,
                            void *arg)
{
    adj_feature_update_ctx_t *ctx = arg;
    ip_adjacency_t *adj;

    adj = adj_get(ai);

    /*
     * this ugly mess matches the feature arc that is changing with affected
     * adjacencies
     */
    if (((ctx->arc == ip6_main.lookup_main.output_feature_arc_index) &&
         (VNET_LINK_IP6 == adj->ia_link)) ||
        ((ctx->arc == ip4_main.lookup_main.output_feature_arc_index) &&
         (VNET_LINK_IP4 == adj->ia_link)) ||
        ((ctx->arc == mpls_main.output_feature_arc_index) &&
         (VNET_LINK_MPLS == adj->ia_link)))
    {
        if (ctx->enable)
            adj->rewrite_header.flags |= VNET_REWRITE_HAS_FEATURES;
        else
            adj->rewrite_header.flags &= ~VNET_REWRITE_HAS_FEATURES;
    }
    return (ADJ_WALK_RC_CONTINUE);
}

void
adj_feature_update (u32 sw_if_index,
                    u8 arc_index,
                    u8 is_enable)
{
    /*
     * Walk all the adjacencies on the interface to update the cached
     * 'has-features' flag
     */
    adj_feature_update_ctx_t ctx = {
        .arc = arc_index,
        .enable = is_enable,
    };
    adj_walk (sw_if_index, adj_feature_update_walk_cb, &ctx);
}

/**
 * @brief Walk the Adjacencies on a given interface
 */
void
adj_walk (u32 sw_if_index,
          adj_walk_cb_t cb,
          void *ctx)
{
    /*
     * walk all the neighbor adjacencies
     */
    fib_protocol_t proto;

    FOR_EACH_FIB_IP_PROTOCOL(proto)
    {
        adj_nbr_walk(sw_if_index, proto, cb, ctx);
    }
}

/**
 * @brief Return the link type of the adjacency
 */
vnet_link_t
adj_get_link_type (adj_index_t ai)
{
    const ip_adjacency_t *adj;

    adj = adj_get(ai);

    return (adj->ia_link); 
}

/**
 * @brief Return the sw interface index of the adjacency.
 */
u32
adj_get_sw_if_index (adj_index_t ai)
{
    const ip_adjacency_t *adj;

    adj = adj_get(ai);

    return (adj->rewrite_header.sw_if_index);
}

/**
 * @brief Return the link type of the adjacency
 */
const u8*
adj_get_rewrite (adj_index_t ai)
{
    vnet_rewrite_header_t *rw;
    ip_adjacency_t *adj;

    adj = adj_get(ai);
    rw = &adj->rewrite_header;

    ASSERT (rw->data_bytes != 0xfefe);

    return (rw->data - rw->data_bytes);
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
    adj_mcast_module_init();

    /*
     * one special adj to reserve index 0
     */
    special_v4_miss_adj_with_index_zero = adj_alloc(FIB_PROTOCOL_IP4);

    return (NULL);
}

VLIB_INIT_FUNCTION (adj_module_init);

static clib_error_t *
adj_show (vlib_main_t * vm,
	  unformat_input_t * input,
	  vlib_cli_command_t * cmd)
{
    adj_index_t ai = ADJ_INDEX_INVALID;
    u32 sw_if_index = ~0;
    int summary = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
	if (unformat (input, "%d", &ai))
	    ;
	else if (unformat (input, "sum"))
	    summary = 1;
	else if (unformat (input, "summary"))
	    summary = 1;
	else if (unformat (input, "%U",
			   unformat_vnet_sw_interface, vnet_get_main(),
			   &sw_if_index))
	    ;
	else
	    break;
    }

    if (summary)
    {
        vlib_cli_output (vm, "Number of adjacenies: %d", pool_elts(adj_pool));
        vlib_cli_output (vm, "Per-adjacency counters: %s",
                         (adj_are_counters_enabled() ?
                          "enabled":
                          "disabled"));
    }
    else
    {
        if (ADJ_INDEX_INVALID != ai)
        {
            if (pool_is_free_index(adj_pool, ai))
            {
                vlib_cli_output (vm, "adjacency %d invalid", ai);
                return 0;
            }

            vlib_cli_output (vm, "[@%d] %U",
                             ai,
                             format_ip_adjacency,  ai,
                             FORMAT_IP_ADJACENCY_DETAIL);
        }
        else
        {
            /* *INDENT-OFF* */
            pool_foreach_index(ai, adj_pool,
            ({
                if (~0 != sw_if_index &&
                    sw_if_index != adj_get_sw_if_index(ai))
                {
                }
                else
                {
                    vlib_cli_output (vm, "[@%d] %U",
                                     ai,
                                     format_ip_adjacency, ai,
                                     FORMAT_IP_ADJACENCY_NONE);
                }
            }));
            /* *INDENT-ON* */
        }
    }
    return 0;
}

/*?
 * Show all adjacencies.
 * @cliexpar
 * @cliexstart{sh adj}
 * [@0]
 * [@1]  glean: loop0
 * [@2] ipv4 via 1.0.0.2 loop0: IP4: 00:00:22:aa:bb:cc -> 00:00:11:aa:bb:cc
 * [@3] mpls via 1.0.0.2 loop0: MPLS_UNICAST: 00:00:22:aa:bb:cc -> 00:00:11:aa:bb:cc
 * [@4] ipv4 via 1.0.0.3 loop0: IP4: 00:00:22:aa:bb:cc -> 00:00:11:aa:bb:cc
 * [@5] mpls via 1.0.0.3 loop0: MPLS_UNICAST: 00:00:22:aa:bb:cc -> 00:00:11:aa:bb:cc
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (adj_show_command, static) = {
    .path = "show adj",
    .short_help = "show adj [<adj_index>] [interface] [summary]",
    .function = adj_show,
};

/**
 * @brief CLI invoked function to enable/disable per-adj counters
 */
static clib_error_t *
adj_cli_counters_set (vlib_main_t * vm,
                      unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
    clib_error_t *error = NULL;
    int enable = ~0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
	if (unformat (input, "enable"))
	    enable = 1;
	else if (unformat (input, "disable"))
	    enable = 0;
	else
	    break;
    }

    if (enable != ~0)
    {
        /* user requested something sensible */
        adj_per_adj_counters = enable;
    }
    else
    {
        error = clib_error_return (0, "specify 'enable' or 'disable'");
    }

    return (error);
}

/*?
 * Enabe/disble per-adjacency counters. This is optional because it comes with
 * a non-negligible performance cost.
 ?*/
VLIB_CLI_COMMAND (adj_cli_counters_set_command, static) = {
    .path = "adjacency counters",
    .short_help = "adjacency counters [enable|disable]",
    .function = adj_cli_counters_set,
};
