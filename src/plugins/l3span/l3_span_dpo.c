/*
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

#include <plugins/l3span/l3_span_dpo.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/dpo/replicate_dpo.h>
#include <vnet/dpo/load_balance.h>

/**
 * ID registered for L3 span DPOs
 */
dpo_type_t l3_span_dpo_type;

/**
 * pool of all L3 Span DPOs
 */
l3_span_dpo_t *l3_span_dpo_pool;

static l3_span_dpo_t *
l3_span_dpo_alloc (void)
{
    l3_span_dpo_t *l3sd;

    pool_get_aligned(l3_span_dpo_pool, l3sd, CLIB_CACHE_LINE_BYTES);
    memset(l3sd, 0, sizeof(*l3sd));

    return (l3sd);
}

static index_t
l3_span_dpo_get_index (l3_span_dpo_t *l3s)
{
    return (l3s - l3_span_dpo_pool);
}

static fib_forward_chain_type_t
l3_span_dpo_proto_to_chain_type (dpo_proto_t dproto)
{
    switch (dproto)
    {
    case DPO_PROTO_IP4:
        return (FIB_FORW_CHAIN_TYPE_UNICAST_IP4);
    case DPO_PROTO_IP6:
        return (FIB_FORW_CHAIN_TYPE_UNICAST_IP6);
    default:
        ASSERT(0);
    }

    return (FIB_FORW_CHAIN_TYPE_UNICAST_IP4);
}

void
l3_span_dpo_create_and_lock (dpo_proto_t dproto,
                             fib_node_index_t pl,
                             index_t counter,
                             dpo_id_t *dpo)
{
    l3_span_dpo_t *l3sd;

    /*
     * alloc an L3 span DPO and a replicate DPO
     */
    l3sd = l3_span_dpo_alloc();

    /*
     * have the path-list contribute a load-balance DPO we can clone
     */
    fib_path_list_contribute_forwarding
        (pl,
         l3_span_dpo_proto_to_chain_type(dproto),
         FIB_PATH_LIST_FWD_FLAG_NONE,
         &l3sd->l3sd_dpo);

    ASSERT(DPO_LOAD_BALANCE == l3sd->l3sd_dpo.dpoi_type);

    dpo_set(dpo, l3_span_dpo_type, dproto, l3_span_dpo_get_index(l3sd));
}

void
l3_span_dpo_update (index_t l3sdi,
                    fib_node_index_t pl)
{
    l3_span_dpo_t *l3sd;

    l3sd = l3_span_dpo_get(l3sdi);

    fib_path_list_contribute_forwarding
        (pl,
         l3_span_dpo_proto_to_chain_type(l3sd->l3sd_dpo.dpoi_proto),
         FIB_PATH_LIST_FWD_FLAG_NONE,
         &l3sd->l3sd_dpo);
}

u8*
format_l3_span_dpo (u8 *s, va_list *args)
{
    index_t index = va_arg (*args, index_t);
    u32 indent = va_arg (*args, u32);
    l3_span_dpo_t *l3sd;

    s = format(s, "l3-span:[%d]:", index);

    if (pool_is_free_index(l3_span_dpo_pool, index))
    {
        /*
         * the packet trace can be printed after the DPO has been deleted
         */
        return (s);
    }

    l3sd = l3_span_dpo_get(index);

    if (l3sd->l3sd_flags & L3_SPAN_DPO_FLAG_CLONE)
        s = format(s, " orig:%d", l3sd->l3sd_orig);
    s = format(s, "\n%U", format_white_space, indent);
    s = format(s, "%U", format_dpo_id, &l3sd->l3sd_dpo, indent+2);

    return (s);
}

static void
l3_span_dpo_lock (dpo_id_t *dpo)
{
    l3_span_dpo_t *l3sd;

    l3sd = l3_span_dpo_get(dpo->dpoi_index);

    l3sd->l3sd_locks++;
}

static void
l3_span_dpo_unlock_dpo (dpo_id_t *dpo)
{
    l3_span_dpo_unlock(dpo->dpoi_index);
}

void
l3_span_dpo_unlock (index_t l3sdi)
{
    l3_span_dpo_t *l3sd;

    l3sd = l3_span_dpo_get(l3sdi);

    l3sd->l3sd_locks--;

    if (0 == l3sd->l3sd_locks)
    {
        dpo_reset(&l3sd->l3sd_dpo);
        pool_put(l3_span_dpo_pool, l3sd);
    }
}

/**
 * @brief A struct to hold tracing information for the span
 * node.
 */
typedef struct l3_span_trace_t_
{
    /**
     * The index of the original L3-span
     */
    index_t orig;
} l3_span_trace_t;

always_inline uword
l3_span_dpo_inline (vlib_main_t * vm,
                    vlib_node_runtime_t * node,
                    vlib_frame_t * from_frame)
{
    u32 n_left_from, next_index, * from, * to_next;

    from = vlib_frame_vector_args (from_frame);
    n_left_from = from_frame->n_vectors;

    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            l3_span_dpo_t *l3sd0;
            vlib_buffer_t * b0;
            u32 bi0, l3sdi0;
            u32 next0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);

            /* dst lookup was done by ip4 lookup */
            l3sdi0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
            l3sd0 = l3_span_dpo_get(l3sdi0);

            next0 = l3sd0->l3sd_dpo.dpoi_next_node;
            vnet_buffer(b0)->ip.adj_index[VLIB_TX] = l3sd0->l3sd_dpo.dpoi_index;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                l3_span_trace_t *tr =
                    vlib_add_trace (vm, node, b0, sizeof (*tr));
                tr->orig = l3sd0->l3sd_orig;
            }

            vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                            n_left_to_next, bi0, next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return from_frame->n_vectors;
}

static u8 *
format_l3_span_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    l3_span_trace_t * t;

    t = va_arg (*args, l3_span_trace_t *);

    s = format (s, "original:%d", t->orig);

    return (s);
}

static uword
ip4_l3_span (vlib_main_t * vm,
                           vlib_node_runtime_t * node,
                           vlib_frame_t * frame)
{
    return (l3_span_dpo_inline(vm, node, frame));
}

VLIB_REGISTER_NODE (ip4_l3_span_node) = {
    .function = ip4_l3_span,
    .name = "ip4-l3-span",
    .vector_size = sizeof (u32),

    .format_trace = format_l3_span_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "ip4-drop",
    }
};
VLIB_NODE_FUNCTION_MULTIARCH (ip4_l3_span_node,
                              ip4_l3_span)

static uword
ip6_l3_span (vlib_main_t * vm,
                           vlib_node_runtime_t * node,
                           vlib_frame_t * frame)
{
    return (l3_span_dpo_inline(vm, node, frame));
}

VLIB_REGISTER_NODE (ip6_l3_span_node) = {
    .function = ip6_l3_span,
    .name = "ip6-l3-span",
    .vector_size = sizeof (u32),

    .format_trace = format_l3_span_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "ip6-drop",
    }
};
VLIB_NODE_FUNCTION_MULTIARCH (ip6_l3_span_node,
                              ip6_l3_span)

static void
l3_span_dpo_mk_interpose (const dpo_id_t *original,
                          const dpo_id_t *parent,
                          dpo_id_t *clone)
{
    l3_span_dpo_t *l3sd_orig, *l3sd_clone;
    u16 n_buckets;
    index_t repi;
    u16 ii;

    l3sd_orig = l3_span_dpo_get(original->dpoi_index);

    ASSERT(!(l3sd_orig->l3sd_flags & L3_SPAN_DPO_FLAG_CLONE));

    l3sd_clone = l3_span_dpo_alloc();

    l3sd_clone->l3sd_flags |= L3_SPAN_DPO_FLAG_CLONE;
    l3sd_clone->l3sd_orig = original->dpoi_index;

    n_buckets = load_balance_n_buckets(l3sd_orig->l3sd_dpo.dpoi_index);

    /*
     * create a new replicate with one extra bucket. We'll
     * use that extra bucket to stack the parent FIB gives us
     * during the clone.
     */
    repi = replicate_create(n_buckets + 1,
                            l3sd_orig->l3sd_dpo.dpoi_proto);

    /*
     * set the first buckets in the replicte to match the original's.
     * these are the paths to the collectors
     */
    for (ii = 0; ii <n_buckets; ii++)
    {
        replicate_set_bucket
            (repi, ii,
             load_balance_get_bucket(l3sd_orig->l3sd_dpo.dpoi_index, ii));
    }

    /*
     * in the last bucket stack the DPO given by FIB - this is how
     * the FIB entry will forward.
     */
    replicate_set_bucket(repi, n_buckets, parent);

    /*
     * save the replicate we just created on the cloned span
     */
    dpo_set(&l3sd_clone->l3sd_dpo,
            DPO_REPLICATE,
            l3sd_orig->l3sd_dpo.dpoi_proto,
            repi);

    /*
     * construct the Span clone for return to the caller
     */
    dpo_set(clone,
            l3_span_dpo_type,
            l3sd_orig->l3sd_dpo.dpoi_proto,
            l3_span_dpo_get_index(l3sd_clone));
}


static void
l3_span_dpo_mem_show (void)
{
    fib_show_memory_usage("L3 Span",
                          pool_elts(l3_span_dpo_pool),
                          pool_len(l3_span_dpo_pool),
                          sizeof(l3_span_dpo_t));
}

const static dpo_vft_t l3sd_vft = {
    .dv_lock = l3_span_dpo_lock,
    .dv_unlock = l3_span_dpo_unlock_dpo,
    .dv_format = format_l3_span_dpo,
    .dv_mem_show = l3_span_dpo_mem_show,
    .dv_mk_interpose = l3_span_dpo_mk_interpose,
};

const static char* const l3_span_ip4_nodes[] =
{
    "ip4-l3-span",
    NULL,
};
const static char* const l3_span_ip6_nodes[] =
{
    "ip6-l3-span",
    NULL,
};

const static char* const * const l3_span_dpo_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = l3_span_ip4_nodes,
    [DPO_PROTO_IP6]  = l3_span_ip6_nodes,
};

void
l3_span_dpo_module_init (void)
{
    l3_span_dpo_type =
        dpo_register_new_type(&l3sd_vft, l3_span_dpo_nodes);
}
