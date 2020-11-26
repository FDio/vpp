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
#include <vnet/adj/adj_delegate.h>
#include <vnet/fib/fib_node_list.h>

/* Adjacency packet/byte counters indexed by adjacency index. */
vlib_combined_counter_main_t adjacency_counters = {
    .name = "adjacency",
    .stat_segment_name = "/net/adjacency",
};

/*
 * the single adj pool
 */
ip_adjacency_t *adj_pool;

/**
 * @brief Global Config for enabling per-adjacency counters.
 * By default these are disabled.
 */
int adj_per_adj_counters;

const ip46_address_t ADJ_BCAST_ADDR = {
    .ip6 = {
        .as_u64[0] = 0xffffffffffffffff,
        .as_u64[1] = 0xffffffffffffffff,
    },
};

/**
 * Adj flag names
 */
static const char *adj_attr_names[] = ADJ_ATTR_NAMES;

always_inline void
adj_poison (ip_adjacency_t * adj)
{
    if (CLIB_DEBUG > 0)
    {
	clib_memset (adj, 0xfe, sizeof (adj[0]));
    }
}

ip_adjacency_t *
adj_alloc (fib_protocol_t proto)
{
    ip_adjacency_t *adj;
    u8 need_barrier_sync = 0;
    vlib_main_t *vm;
    vm = vlib_get_main();

    ASSERT (vm->thread_index == 0);

    pool_get_aligned_will_expand (adj_pool, need_barrier_sync,
                                  CLIB_CACHE_LINE_BYTES);
    /* If the adj_pool will expand, stop the parade. */
    if (need_barrier_sync)
        vlib_worker_thread_barrier_sync (vm);

    pool_get_aligned(adj_pool, adj, CLIB_CACHE_LINE_BYTES);

    adj_poison(adj);

    /* Validate adjacency counters. */
    if (need_barrier_sync == 0)
    {
        /* If the adj counter pool will expand, stop the parade */
        need_barrier_sync = vlib_validate_combined_counter_will_expand
            (&adjacency_counters, adj_get_index (adj));
        if (need_barrier_sync)
            vlib_worker_thread_barrier_sync (vm);
    }
    vlib_validate_combined_counter(&adjacency_counters,
                                   adj_get_index(adj));

    /* Make sure certain fields are always initialized. */
    vlib_zero_combined_counter(&adjacency_counters,
                               adj_get_index(adj));
    fib_node_init(&adj->ia_node,
                  FIB_NODE_TYPE_ADJ);

    adj->ia_nh_proto = proto;
    adj->ia_flags = 0;
    adj->ia_cfg_index = 0;
    adj->rewrite_header.sw_if_index = ~0;
    adj->rewrite_header.flags = 0;
    adj->lookup_next_index = 0;
    adj->ia_delegates = NULL;

    /* lest it become a midchain in the future */
    clib_memset(&adj->sub_type.midchain.next_dpo, 0,
           sizeof(adj->sub_type.midchain.next_dpo));

    if (need_barrier_sync)
        vlib_worker_thread_barrier_release (vm);

    return (adj);
}

static int
adj_index_is_special (adj_index_t adj_index)
{
    if (ADJ_INDEX_INVALID == adj_index)
	return (!0);

    return (0);
}

u8*
format_adj_flags (u8 * s, va_list * args)
{
    adj_flags_t af;
    adj_attr_t at;

    af = va_arg (*args, int);

    if (ADJ_FLAG_NONE == af)
    {
        return (format(s, "None"));
    }
    FOR_EACH_ADJ_ATTR(at)
    {
        if (af & (1 << at))
        {
            s = format(s, "%s ", adj_attr_names[at]);
        }
    }
    return (s);
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

    if (!adj_is_valid(adj_index))
      return format(s, "<invalid adjacency>");

    adj = adj_get(adj_index);

    switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_REWRITE:
    case IP_LOOKUP_NEXT_BCAST:
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
    case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
	s = format (s, "%U", format_adj_mcast_midchain, adj_index, 0);
	break;
    case IP_LOOKUP_NEXT_DROP:
    case IP_LOOKUP_NEXT_PUNT:
    case IP_LOOKUP_NEXT_LOCAL:
    case IP_LOOKUP_NEXT_ICMP_ERROR:
    case IP_LOOKUP_N_NEXT:
        break;
    }

    if (fiaf & FORMAT_IP_ADJACENCY_DETAIL)
    {
        vlib_counter_t counts;

        vlib_get_combined_counter(&adjacency_counters, adj_index, &counts);
        s = format (s, "\n   flags:%U", format_adj_flags, adj->ia_flags);
        s = format (s, "\n   counts:[%Ld:%Ld]", counts.packets, counts.bytes);
	s = format (s, "\n   locks:%d", adj->ia_node.fn_locks);
	s = format(s, "\n delegates:");
        s = adj_delegate_format(s, adj);

	s = format(s, "\n children:");
        if (fib_node_list_get_size(adj->ia_node.fn_children))
        {
            s = format(s, "\n  ");
            s = fib_node_children_format(adj->ia_node.fn_children, s);
        }
    }

    return s;
}

int
adj_recursive_loop_detect (adj_index_t ai,
                           fib_node_index_t **entry_indicies)
{
    ip_adjacency_t * adj;

    adj = adj_get(ai);

    switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_REWRITE:
    case IP_LOOKUP_NEXT_ARP:
    case IP_LOOKUP_NEXT_GLEAN:
    case IP_LOOKUP_NEXT_MCAST:
    case IP_LOOKUP_NEXT_BCAST:
    case IP_LOOKUP_NEXT_DROP:
    case IP_LOOKUP_NEXT_PUNT:
    case IP_LOOKUP_NEXT_LOCAL:
    case IP_LOOKUP_NEXT_ICMP_ERROR:
    case IP_LOOKUP_N_NEXT:
        /*
         * these adjacency types are terminal graph nodes, so there's no
         * possibility of a loop down here.
         */
	break;
    case IP_LOOKUP_NEXT_MIDCHAIN:
    case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
        return (adj_ndr_midchain_recursive_loop_detect(ai, entry_indicies));
    }

    return (0);
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

    adj_delegate_adj_deleted(adj);

    vlib_worker_thread_barrier_sync (vm);

    switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_MIDCHAIN:
        adj_midchain_teardown(adj);
        /* FALL THROUGH */
    case IP_LOOKUP_NEXT_ARP:
    case IP_LOOKUP_NEXT_REWRITE:
    case IP_LOOKUP_NEXT_BCAST:
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
	adj_glean_remove(adj);
	break;
    case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
        adj_midchain_teardown(adj);
        /* FALL THROUGH */
    case IP_LOOKUP_NEXT_MCAST:
	adj_mcast_remove(adj->ia_nh_proto,
			 adj->rewrite_header.sw_if_index);
	break;
    case IP_LOOKUP_NEXT_DROP:
    case IP_LOOKUP_NEXT_PUNT:
    case IP_LOOKUP_NEXT_LOCAL:
    case IP_LOOKUP_NEXT_ICMP_ERROR:
    case IP_LOOKUP_N_NEXT:
	/*
	 * type not stored in any DB from which we need to remove it
	 */
	break;
    }

    vlib_worker_thread_barrier_release(vm);

    fib_node_deinit(&adj->ia_node);
    ASSERT(0 == vec_len(adj->ia_delegates));
    vec_free(adj->ia_delegates);
    pool_put(adj_pool, adj);
}

u32
adj_dpo_get_urpf (const dpo_id_t *dpo)
{
    ip_adjacency_t *adj;

    adj = adj_get(dpo->dpoi_index);

    return (adj->rewrite_header.sw_if_index);
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
 * Context for the walk to update the cached feature flags.
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
        vnet_feature_main_t *fm = &feature_main;
        vnet_feature_config_main_t *cm;

        cm = &fm->feature_config_mains[ctx->arc];

        if (ctx->enable)
            adj->rewrite_header.flags |= VNET_REWRITE_HAS_FEATURES;
        else
            adj->rewrite_header.flags &= ~VNET_REWRITE_HAS_FEATURES;

        adj->ia_cfg_index = vec_elt (cm->config_index_by_sw_if_index,
                                     adj->rewrite_header.sw_if_index);
    }
    return (ADJ_WALK_RC_CONTINUE);
}

static void
adj_feature_update (u32 sw_if_index,
                    u8 arc_index,
                    u8 is_enable,
                    void *data)
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

static adj_walk_rc_t
adj_mtu_update_walk_cb (adj_index_t ai,
                        void *arg)
{
    ip_adjacency_t *adj;

    adj = adj_get(ai);

    vnet_rewrite_update_mtu (vnet_get_main(), adj->ia_link,
                             &adj->rewrite_header);

    return (ADJ_WALK_RC_CONTINUE);
}

static clib_error_t *
adj_mtu_update (vnet_main_t * vnm, u32 sw_if_index, u32 flags)
{
  adj_walk (sw_if_index, adj_mtu_update_walk_cb, NULL);

  return (NULL);
}

VNET_SW_INTERFACE_MTU_CHANGE_FUNCTION(adj_mtu_update);

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
        adj_mcast_walk(sw_if_index, proto, cb, ctx);
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
 * @brief Return true if the adjacency is 'UP', i.e. can be used for forwarding
 * 0 is down, !0 is up.
 */
int
adj_is_up (adj_index_t ai)
{
    return (adj_bfd_is_up(ai));
}

/**
 * @brief Return the rewrite string of the adjacency
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
    ip_adjacency_t *adj;

    adj = ADJ_FROM_NODE(node);

    switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_MIDCHAIN:
        adj_midchain_delegate_restack(adj_get_index(adj));
        break;
    case IP_LOOKUP_NEXT_ARP:
    case IP_LOOKUP_NEXT_REWRITE:
    case IP_LOOKUP_NEXT_BCAST:
    case IP_LOOKUP_NEXT_GLEAN:
    case IP_LOOKUP_NEXT_MCAST:
    case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
    case IP_LOOKUP_NEXT_DROP:
    case IP_LOOKUP_NEXT_PUNT:
    case IP_LOOKUP_NEXT_LOCAL:
    case IP_LOOKUP_NEXT_ICMP_ERROR:
    case IP_LOOKUP_N_NEXT:
        /*
         * Que pasa. yo soj en el final!
         */
        ASSERT(0);
        break;
    }

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

    vnet_feature_register(adj_feature_update, NULL);

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
	else if (unformat (input, "summary") || unformat (input, "sum"))
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
        vlib_cli_output (vm, "Number of adjacencies: %d", pool_elts(adj_pool));
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
 * [@3] mpls via 1.0.0.2 loop0: MPLS: 00:00:22:aa:bb:cc -> 00:00:11:aa:bb:cc
 * [@4] ipv4 via 1.0.0.3 loop0: IP4: 00:00:22:aa:bb:cc -> 00:00:11:aa:bb:cc
 * [@5] mpls via 1.0.0.3 loop0: MPLS: 00:00:22:aa:bb:cc -> 00:00:11:aa:bb:cc
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
 * Enable/disable per-adjacency counters. This is optional because it comes
 * with a non-negligible performance cost.
 ?*/
VLIB_CLI_COMMAND (adj_cli_counters_set_command, static) = {
    .path = "adjacency counters",
    .short_help = "adjacency counters [enable|disable]",
    .function = adj_cli_counters_set,
};
