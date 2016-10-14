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

#include <vnet/ip/ip.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/mpls/mpls.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/mpls_fib.h>

static const char *const lookup_input_names[] = LOOKUP_INPUTS;

/**
 * @brief Enumeration of the lookup subtypes
 */
typedef enum lookup_sub_type_t_
{
    LOOKUP_SUB_TYPE_SRC,
    LOOKUP_SUB_TYPE_DST,
    LOOKUP_SUB_TYPE_DST_TABLE_FROM_INTERFACE,
} lookup_sub_type_t;
#define LOOKUP_SUB_TYPE_NUM (LOOKUP_SUB_TYPE_DST_TABLE_FROM_INTERFACE+1)

#define FOR_EACH_LOOKUP_SUB_TYPE(_st)                                   \
    for (_st = LOOKUP_SUB_TYPE_IP4_SRC; _st < LOOKUP_SUB_TYPE_NUM; _st++)

/**
 * @brief pool of all MPLS Label DPOs
 */
lookup_dpo_t *lookup_dpo_pool;

/**
 * @brief An array of registered DPO type values for the sub-types
 */
static dpo_type_t lookup_dpo_sub_types[LOOKUP_SUB_TYPE_NUM];

static lookup_dpo_t *
lookup_dpo_alloc (void)
{
    lookup_dpo_t *lkd;

    pool_get_aligned(lookup_dpo_pool, lkd, CLIB_CACHE_LINE_BYTES);

    return (lkd);
}

static index_t
lookup_dpo_get_index (lookup_dpo_t *lkd)
{
    return (lkd - lookup_dpo_pool);
}

static void
lookup_dpo_add_or_lock_i (fib_node_index_t fib_index,
                          dpo_proto_t proto,
                          lookup_input_t input,
                          lookup_table_t table_config,
                          dpo_id_t *dpo)
{
    lookup_dpo_t *lkd;
    dpo_type_t type;

    lkd = lookup_dpo_alloc();
    lkd->lkd_fib_index = fib_index;
    lkd->lkd_proto = proto;
    lkd->lkd_input = input;
    lkd->lkd_table = table_config;

    /*
     * use the input type to select the lookup sub-type
     */
    type = 0;

    switch (input)
    {
    case LOOKUP_INPUT_SRC_ADDR:
        type = lookup_dpo_sub_types[LOOKUP_SUB_TYPE_SRC];
        break;
    case LOOKUP_INPUT_DST_ADDR:
        switch (table_config)
        {
        case LOOKUP_TABLE_FROM_INPUT_INTERFACE:
            type = lookup_dpo_sub_types[LOOKUP_SUB_TYPE_DST_TABLE_FROM_INTERFACE];
            break;
        case LOOKUP_TABLE_FROM_CONFIG:
            type = lookup_dpo_sub_types[LOOKUP_SUB_TYPE_DST];
            break;
        }
    }

    if (0 == type)
    {
        dpo_reset(dpo);
    }
    else
    {
        dpo_set(dpo, type, proto, lookup_dpo_get_index(lkd));
    }
}

void
lookup_dpo_add_or_lock_w_fib_index (fib_node_index_t fib_index,
                                    dpo_proto_t proto,
                                    lookup_input_t input,
                                    lookup_table_t table_config,
                                    dpo_id_t *dpo)
{
    if (LOOKUP_TABLE_FROM_CONFIG == table_config)
    {
	fib_table_lock(fib_index, dpo_proto_to_fib(proto));
    }
    lookup_dpo_add_or_lock_i(fib_index, proto, input, table_config, dpo);
}

void
lookup_dpo_add_or_lock_w_table_id (u32 table_id,
                                   dpo_proto_t proto,
                                   lookup_input_t input,
                                   lookup_table_t table_config,
                                   dpo_id_t *dpo)
{
    fib_node_index_t fib_index = FIB_NODE_INDEX_INVALID;

    if (LOOKUP_TABLE_FROM_CONFIG == table_config)
    {
	fib_index =
	    fib_table_find_or_create_and_lock(dpo_proto_to_fib(proto),
					      table_id);
    }

    ASSERT(FIB_NODE_INDEX_INVALID != fib_index);
    lookup_dpo_add_or_lock_i(fib_index, proto, input, table_config, dpo);    
}

u8*
format_lookup_dpo (u8 *s, va_list *args)
{
    index_t index = va_arg (*args, index_t);
    lookup_dpo_t *lkd;

    lkd = lookup_dpo_get(index);

    if (LOOKUP_TABLE_FROM_INPUT_INTERFACE == lkd->lkd_table)
    {
        s = format(s, "%s lookup in interface's %U table",
                   lookup_input_names[lkd->lkd_input],
                   format_dpo_proto, lkd->lkd_proto);
    }
    else
    {
	s = format(s, "%s lookup in %U",
		   lookup_input_names[lkd->lkd_input],
		   format_fib_table_name, lkd->lkd_fib_index,
		   dpo_proto_to_fib(lkd->lkd_proto));
    }
    return (s);
}

static void
lookup_dpo_lock (dpo_id_t *dpo)
{
    lookup_dpo_t *lkd;

    lkd = lookup_dpo_get(dpo->dpoi_index);

    lkd->lkd_locks++;
}

static void
lookup_dpo_unlock (dpo_id_t *dpo)
{
    lookup_dpo_t *lkd;

    lkd = lookup_dpo_get(dpo->dpoi_index);

    lkd->lkd_locks--;

    if (0 == lkd->lkd_locks)
    {
        if (LOOKUP_TABLE_FROM_CONFIG == lkd->lkd_table)
        {
	    fib_table_unlock(lkd->lkd_fib_index,
			     dpo_proto_to_fib(lkd->lkd_proto));
        }
        pool_put(lookup_dpo_pool, lkd);
    }
}

always_inline void
ip4_src_fib_lookup_one (u32 src_fib_index0,
                        const ip4_address_t * addr0,
                        u32 * src_adj_index0)
{
    ip4_fib_mtrie_leaf_t leaf0, leaf1;
    ip4_fib_mtrie_t * mtrie0;

    mtrie0 = &ip4_fib_get (src_fib_index0)->mtrie;

    leaf0 = leaf1 = IP4_FIB_MTRIE_LEAF_ROOT;
    leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 0);
    leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 1);
    leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 2);
    leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 3);

    /* Handle default route. */
    leaf0 = (leaf0 == IP4_FIB_MTRIE_LEAF_EMPTY ? mtrie0->default_leaf : leaf0);
    src_adj_index0[0] = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
}

always_inline void
ip4_src_fib_lookup_two (u32 src_fib_index0,
                        u32 src_fib_index1,
                        const ip4_address_t * addr0,
                        const ip4_address_t * addr1,
                        u32 * src_adj_index0,
                        u32 * src_adj_index1)
{
    ip4_fib_mtrie_leaf_t leaf0, leaf1;
    ip4_fib_mtrie_t * mtrie0, * mtrie1;

    mtrie0 = &ip4_fib_get (src_fib_index0)->mtrie;
    mtrie1 = &ip4_fib_get (src_fib_index1)->mtrie;

    leaf0 = leaf1 = IP4_FIB_MTRIE_LEAF_ROOT;

    leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 0);
    leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, addr1, 0);

    leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 1);
    leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, addr1, 1);

    leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 2);
    leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, addr1, 2);

    leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 3);
    leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, addr1, 3);

    /* Handle default route. */
    leaf0 = (leaf0 == IP4_FIB_MTRIE_LEAF_EMPTY ? mtrie0->default_leaf : leaf0);
    leaf1 = (leaf1 == IP4_FIB_MTRIE_LEAF_EMPTY ? mtrie1->default_leaf : leaf1);
    src_adj_index0[0] = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
    src_adj_index1[0] = ip4_fib_mtrie_leaf_get_adj_index (leaf1);
}

/**
 * @brief Lookup trace  data
 */
typedef struct lookup_trace_t_
{
    union {
	ip46_address_t addr;
	mpls_unicast_header_t hdr;
    };
    fib_node_index_t fib_index;
    index_t lbi;
} lookup_trace_t;


always_inline uword
lookup_dpo_ip4_inline (vlib_main_t * vm,
                       vlib_node_runtime_t * node,
                       vlib_frame_t * from_frame,
                       int input_src_addr,
                       int table_from_interface)
{
    u32 n_left_from, next_index, * from, * to_next;
    u32 cpu_index = os_get_cpu_number();
    vlib_combined_counter_main_t * cm = &load_balance_main.lbm_to_counters;

    from = vlib_frame_vector_args (from_frame);
    n_left_from = from_frame->n_vectors;

    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
	    u32 bi0, lkdi0, lbi0, fib_index0, next0, hash_c0;
	    flow_hash_config_t flow_hash_config0;
            const ip4_address_t *input_addr;
            const load_balance_t *lb0;
            const lookup_dpo_t * lkd0;
            const ip4_header_t * ip0;
            const dpo_id_t *dpo0;
            vlib_buffer_t * b0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            ip0 = vlib_buffer_get_current (b0);

            /* dst lookup was done by ip4 lookup */
            lkdi0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
            lkd0 = lookup_dpo_get(lkdi0);

            /*
             * choose between a lookup using the fib index in the DPO
             * or getting the FIB index from the interface.
             */
            if (table_from_interface)
            {
                fib_index0 = 
                    ip4_fib_table_get_index_for_sw_if_index(
                        vnet_buffer(b0)->sw_if_index[VLIB_RX]);
            }
            else
            {
                fib_index0 = lkd0->lkd_fib_index;
            }

            /*
             * choose between a source or destination address lookup in the table
             */
            if (input_src_addr)
            {
                input_addr = &ip0->src_address;
            }
            else
            {
                input_addr = &ip0->dst_address;
            }

            /* do lookup */
            ip4_src_fib_lookup_one (fib_index0, input_addr, &lbi0);
            lb0 = load_balance_get(lbi0);

	    /* Use flow hash to compute multipath adjacency. */
	    hash_c0 = vnet_buffer (b0)->ip.flow_hash = 0;

	    if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
            {
		flow_hash_config0 = lb0->lb_hash_config;
		hash_c0 = vnet_buffer (b0)->ip.flow_hash =
		    ip4_compute_flow_hash (ip0, flow_hash_config0);
            }

	    dpo0 = load_balance_get_bucket_i(lb0,
					     (hash_c0 &
					      (lb0->lb_n_buckets_minus_1)));

            next0 = dpo0->dpoi_next_node;
            vnet_buffer(b0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

            vlib_increment_combined_counter
                (cm, cpu_index, lbi0, 1,
                 vlib_buffer_length_in_chain (vm, b0));

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
                lookup_trace_t *tr = vlib_add_trace (vm, node, 
                                                     b0, sizeof (*tr));
                tr->fib_index = fib_index0;
                tr->lbi = lbi0;
                tr->addr.ip4 = *input_addr;
            }

            vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                            n_left_to_next, bi0, next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return from_frame->n_vectors;
}

static u8 *
format_lookup_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    lookup_trace_t * t = va_arg (*args, lookup_trace_t *);
    uword indent = format_get_indent (s);
    s = format (s, "%U fib-index:%d addr:%U load-balance:%d",
                format_white_space, indent,
                t->fib_index,
                format_ip46_address, &t->addr, IP46_TYPE_ANY,
                t->lbi);
    return s;
}

always_inline uword
lookup_ip4_dst (vlib_main_t * vm,
                vlib_node_runtime_t * node,
                vlib_frame_t * from_frame)
{
    return (lookup_dpo_ip4_inline(vm, node, from_frame, 0, 0));
}

VLIB_REGISTER_NODE (lookup_ip4_dst_node) = {
    .function = lookup_ip4_dst,
    .name = "lookup-ip4-dst",
    .vector_size = sizeof (u32),
    .sibling_of = "ip4-lookup",
    .format_trace = format_lookup_trace,
};
VLIB_NODE_FUNCTION_MULTIARCH (lookup_ip4_dst_node, lookup_ip4_dst)

always_inline uword
lookup_ip4_dst_itf (vlib_main_t * vm,
                    vlib_node_runtime_t * node,
                    vlib_frame_t * from_frame)
{
    return (lookup_dpo_ip4_inline(vm, node, from_frame, 0, 1));
}

VLIB_REGISTER_NODE (lookup_ip4_dst_itf_node) = {
    .function = lookup_ip4_dst_itf,
    .name = "lookup-ip4-dst-itf",
    .vector_size = sizeof (u32),
    .sibling_of = "ip4-lookup",
    .format_trace = format_lookup_trace,
};
VLIB_NODE_FUNCTION_MULTIARCH (lookup_ip4_dst_itf_node, lookup_ip4_dst_itf)

always_inline uword
lookup_ip4_src (vlib_main_t * vm,
                vlib_node_runtime_t * node,
                vlib_frame_t * from_frame)
{
    return (lookup_dpo_ip4_inline(vm, node, from_frame, 1, 0));
}

VLIB_REGISTER_NODE (lookup_ip4_src_node) = {
    .function = lookup_ip4_src,
    .name = "lookup-ip4-src",
    .vector_size = sizeof (u32),
    .format_trace = format_lookup_trace,
    .sibling_of = "ip4-lookup",
};
VLIB_NODE_FUNCTION_MULTIARCH (lookup_ip4_src_node, lookup_ip4_src)

always_inline uword
lookup_dpo_ip6_inline (vlib_main_t * vm,
                       vlib_node_runtime_t * node,
                       vlib_frame_t * from_frame,
                       int input_src_addr,
                       int table_from_interface)
{
    vlib_combined_counter_main_t * cm = &load_balance_main.lbm_to_counters;
    u32 n_left_from, next_index, * from, * to_next;
    u32 cpu_index = os_get_cpu_number();

    from = vlib_frame_vector_args (from_frame);
    n_left_from = from_frame->n_vectors;

    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 bi0, lkdi0, lbi0, fib_index0, next0, hash_c0;
	    flow_hash_config_t flow_hash_config0;
            const ip6_address_t *input_addr0;
            const load_balance_t *lb0;
            const lookup_dpo_t * lkd0;
            const ip6_header_t * ip0;
            const dpo_id_t *dpo0;
            vlib_buffer_t * b0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            ip0 = vlib_buffer_get_current (b0);

            /* dst lookup was done by ip6 lookup */
            lkdi0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
            lkd0 = lookup_dpo_get(lkdi0);

            /*
             * choose between a lookup using the fib index in the DPO
             * or getting the FIB index from the interface.
             */
            if (table_from_interface)
            {
                fib_index0 =
                    ip4_fib_table_get_index_for_sw_if_index(
                        vnet_buffer(b0)->sw_if_index[VLIB_RX]);
            }
            else
            {
                fib_index0 = lkd0->lkd_fib_index;
            }

            /*
             * choose between a source or destination address lookup in the table
             */
            if (input_src_addr)
            {
                input_addr0 = &ip0->src_address;
            }
            else
            {
                input_addr0 = &ip0->dst_address;
            }

            /* do src lookup */
            lbi0 = ip6_fib_table_fwding_lookup(&ip6_main,
                                               fib_index0,
                                               input_addr0);
            lb0 = load_balance_get(lbi0);

	    /* Use flow hash to compute multipath adjacency. */
	    hash_c0 = vnet_buffer (b0)->ip.flow_hash = 0;

	    if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
            {
		flow_hash_config0 = lb0->lb_hash_config;
		hash_c0 = vnet_buffer (b0)->ip.flow_hash =
		    ip6_compute_flow_hash (ip0, flow_hash_config0);
            }

	    dpo0 = load_balance_get_bucket_i(lb0,
					     (hash_c0 &
					      (lb0->lb_n_buckets_minus_1)));

            next0 = dpo0->dpoi_next_node;
            vnet_buffer(b0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

            vlib_increment_combined_counter
                (cm, cpu_index, lbi0, 1,
                 vlib_buffer_length_in_chain (vm, b0));

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
                lookup_trace_t *tr = vlib_add_trace (vm, node, 
                                                     b0, sizeof (*tr));
                tr->fib_index = fib_index0;
                tr->lbi = lbi0;
                tr->addr.ip6 = *input_addr0;
            }
            vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                            n_left_to_next, bi0, next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return from_frame->n_vectors;
}

always_inline uword
lookup_ip6_dst (vlib_main_t * vm,
                vlib_node_runtime_t * node,
                vlib_frame_t * from_frame)
{
    return (lookup_dpo_ip6_inline(vm, node, from_frame, 0 /*use src*/, 0));
}

VLIB_REGISTER_NODE (lookup_ip6_dst_node) = {
    .function = lookup_ip6_dst,
    .name = "lookup-ip6-dst",
    .vector_size = sizeof (u32),
    .format_trace = format_lookup_trace,
    .sibling_of = "ip6-lookup",
};
VLIB_NODE_FUNCTION_MULTIARCH (lookup_ip6_dst_node, lookup_ip6_dst)

always_inline uword
lookup_ip6_dst_itf (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame)
{
    return (lookup_dpo_ip6_inline(vm, node, from_frame, 0 /*use src*/, 1));
}

VLIB_REGISTER_NODE (lookup_ip6_dst_itf_node) = {
    .function = lookup_ip6_dst_itf,
    .name = "lookup-ip6-dst-itf",
    .vector_size = sizeof (u32),
    .format_trace = format_lookup_trace,
    .sibling_of = "ip6-lookup",
};
VLIB_NODE_FUNCTION_MULTIARCH (lookup_ip6_dst_itf_node, lookup_ip6_dst_itf)

always_inline uword
lookup_ip6_src (vlib_main_t * vm,
                vlib_node_runtime_t * node,
                vlib_frame_t * from_frame)
{
    return (lookup_dpo_ip6_inline(vm, node, from_frame, 1, 0));
}

VLIB_REGISTER_NODE (lookup_ip6_src_node) = {
    .function = lookup_ip6_src,
    .name = "lookup-ip6-src",
    .vector_size = sizeof (u32),
    .format_trace = format_lookup_trace,
    .sibling_of = "ip6-lookup",
};
VLIB_NODE_FUNCTION_MULTIARCH (lookup_ip6_src_node, lookup_ip6_src)

always_inline uword
lookup_dpo_mpls_inline (vlib_main_t * vm,
                       vlib_node_runtime_t * node,
                       vlib_frame_t * from_frame,
                       int table_from_interface)
{
    u32 n_left_from, next_index, * from, * to_next;
    u32 cpu_index = os_get_cpu_number();
    vlib_combined_counter_main_t * cm = &load_balance_main.lbm_to_counters;

    from = vlib_frame_vector_args (from_frame);
    n_left_from = from_frame->n_vectors;

    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        /* while (n_left_from >= 4 && n_left_to_next >= 2) */
        /*   } */

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 bi0, lkdi0, lbi0, fib_index0,  next0;
            const mpls_unicast_header_t * hdr0;
            const load_balance_t *lb0;
            const lookup_dpo_t * lkd0;
            const dpo_id_t *dpo0;
            vlib_buffer_t * b0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            hdr0 = vlib_buffer_get_current (b0);

            /* dst lookup was done by mpls lookup */
            lkdi0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
            lkd0 = lookup_dpo_get(lkdi0);

            /*
             * choose between a lookup using the fib index in the DPO
             * or getting the FIB index from the interface.
             */
            if (table_from_interface)
            {
                fib_index0 = 
                    mpls_fib_table_get_index_for_sw_if_index(
                        vnet_buffer(b0)->sw_if_index[VLIB_RX]);
            }
            else
            {
                fib_index0 = lkd0->lkd_fib_index;
            }

            /* do lookup */
            lbi0 = mpls_fib_table_forwarding_lookup (fib_index0, hdr0);
            lb0  = load_balance_get(lbi0);
            dpo0 = load_balance_get_bucket_i(lb0, 0);

            next0 = dpo0->dpoi_next_node;
            vnet_buffer(b0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

            vlib_increment_combined_counter
                (cm, cpu_index, lbi0, 1,
                 vlib_buffer_length_in_chain (vm, b0));

	    if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
                lookup_trace_t *tr = vlib_add_trace (vm, node, 
                                                     b0, sizeof (*tr));
                tr->fib_index = fib_index0;
                tr->lbi = lbi0;
                tr->hdr = *hdr0;
            }

           vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                            n_left_to_next, bi0, next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return from_frame->n_vectors;
}

static u8 *
format_lookup_mpls_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    lookup_trace_t * t = va_arg (*args, lookup_trace_t *);
    uword indent = format_get_indent (s);
    mpls_unicast_header_t hdr;

    hdr.label_exp_s_ttl = clib_net_to_host_u32(t->hdr.label_exp_s_ttl);

    s = format (s, "%U fib-index:%d hdr:%U load-balance:%d",
                format_white_space, indent,
                t->fib_index,
                format_mpls_header, hdr,
                t->lbi);
    return s;
}

always_inline uword
lookup_mpls_dst (vlib_main_t * vm,
                vlib_node_runtime_t * node,
                vlib_frame_t * from_frame)
{
    return (lookup_dpo_mpls_inline(vm, node, from_frame, 0));
}

VLIB_REGISTER_NODE (lookup_mpls_dst_node) = {
    .function = lookup_mpls_dst,
    .name = "lookup-mpls-dst",
    .vector_size = sizeof (u32),
    .sibling_of = "mpls-lookup",
    .format_trace = format_lookup_mpls_trace,
    .n_next_nodes = 0,
};
VLIB_NODE_FUNCTION_MULTIARCH (lookup_mpls_dst_node, lookup_mpls_dst)

always_inline uword
lookup_mpls_dst_itf (vlib_main_t * vm,
                    vlib_node_runtime_t * node,
                    vlib_frame_t * from_frame)
{
    return (lookup_dpo_mpls_inline(vm, node, from_frame, 1));
}

VLIB_REGISTER_NODE (lookup_mpls_dst_itf_node) = {
    .function = lookup_mpls_dst_itf,
    .name = "lookup-mpls-dst-itf",
    .vector_size = sizeof (u32),
    .sibling_of = "mpls-lookup",
    .format_trace = format_lookup_mpls_trace,
    .n_next_nodes = 0,
};
VLIB_NODE_FUNCTION_MULTIARCH (lookup_mpls_dst_itf_node, lookup_mpls_dst_itf)

static void
lookup_dpo_mem_show (void)
{
    fib_show_memory_usage("Lookup",
			  pool_elts(lookup_dpo_pool),
			  pool_len(lookup_dpo_pool),
			  sizeof(lookup_dpo_t));
}

const static dpo_vft_t lkd_vft = {
    .dv_lock = lookup_dpo_lock,
    .dv_unlock = lookup_dpo_unlock,
    .dv_format = format_lookup_dpo,
};
const static dpo_vft_t lkd_vft_w_mem_show = {
    .dv_lock = lookup_dpo_lock,
    .dv_unlock = lookup_dpo_unlock,
    .dv_format = format_lookup_dpo,
    .dv_mem_show = lookup_dpo_mem_show,
};

const static char* const lookup_src_ip4_nodes[] =
{
    "lookup-ip4-src",
    NULL,
};
const static char* const lookup_src_ip6_nodes[] =
{
    "lookup-ip6-src",
    NULL,
};
const static char* const * const lookup_src_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = lookup_src_ip4_nodes,
    [DPO_PROTO_IP6]  = lookup_src_ip6_nodes,
    [DPO_PROTO_MPLS] = NULL,
};

const static char* const lookup_dst_ip4_nodes[] =
{
    "lookup-ip4-dst",
    NULL,
};
const static char* const lookup_dst_ip6_nodes[] =
{
    "lookup-ip6-dst",
    NULL,
};
const static char* const lookup_dst_mpls_nodes[] =
{
    "lookup-mpls-dst",
    NULL,
};
const static char* const * const lookup_dst_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = lookup_dst_ip4_nodes,
    [DPO_PROTO_IP6]  = lookup_dst_ip6_nodes,
    [DPO_PROTO_MPLS] = lookup_dst_mpls_nodes,
};

const static char* const lookup_dst_from_interface_ip4_nodes[] =
{
    "lookup-ip4-dst-itf",
    NULL,
};
const static char* const lookup_dst_from_interface_ip6_nodes[] =
{
    "lookup-ip6-dst-itf",
    NULL,
};
const static char* const lookup_dst_from_interface_mpls_nodes[] =
{
    "lookup-mpls-dst-itf",
    NULL,
};
const static char* const * const lookup_dst_from_interface_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = lookup_dst_from_interface_ip4_nodes,
    [DPO_PROTO_IP6]  = lookup_dst_from_interface_ip6_nodes,
    [DPO_PROTO_MPLS] = lookup_dst_from_interface_mpls_nodes,
};


void
lookup_dpo_module_init (void)
{
    dpo_register(DPO_LOOKUP, &lkd_vft_w_mem_show, NULL);

    /*
     * There are various sorts of lookup; src or dst addr v4 /v6 etc.
     * there isn't an object type for each (there is only the lookup_dpo_t),
     * but, for performance reasons, there is a data plane function, and hence
     * VLIB node for each. VLIB graph node construction is based on DPO types
     * so we create sub-types.
     */
    lookup_dpo_sub_types[LOOKUP_SUB_TYPE_SRC] =
        dpo_register_new_type(&lkd_vft, lookup_src_nodes);
    lookup_dpo_sub_types[LOOKUP_SUB_TYPE_DST] =
        dpo_register_new_type(&lkd_vft, lookup_dst_nodes);
    lookup_dpo_sub_types[LOOKUP_SUB_TYPE_DST_TABLE_FROM_INTERFACE] =
        dpo_register_new_type(&lkd_vft, lookup_dst_from_interface_nodes);
}
