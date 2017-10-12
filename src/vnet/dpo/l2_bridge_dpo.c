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

#include <vnet/dpo/l2_bridge_dpo.h>
#include <vnet/fib/fib_node.h>
#include <vnet/ethernet/ethernet.h>

/*
 * The 'DB' of L2 bridge DPOs.
 * There is only one per-interface, so this is a per-interface vector
 */
static index_t *l2_bridge_dpo_db;

static l2_bridge_dpo_t *
l2_bridge_dpo_alloc (void)
{
    l2_bridge_dpo_t *l2b;

    pool_get(l2_bridge_dpo_pool, l2b);

    return (l2b);
}

static inline l2_bridge_dpo_t *
l2_bridge_dpo_get_from_dpo (const dpo_id_t *dpo)
{
    ASSERT(DPO_L2_BRIDGE == dpo->dpoi_type);

    return (l2_bridge_dpo_get(dpo->dpoi_index));
}

static inline index_t
l2_bridge_dpo_get_index (l2_bridge_dpo_t *l2b)
{
    return (l2b - l2_bridge_dpo_pool);
}

static void
l2_bridge_dpo_lock (dpo_id_t *dpo)
{
    l2_bridge_dpo_t *l2b;

    l2b = l2_bridge_dpo_get_from_dpo(dpo);
    l2b->l2b_locks++;
}

static void
l2_bridge_dpo_unlock (dpo_id_t *dpo)
{
    l2_bridge_dpo_t *l2b;

    l2b = l2_bridge_dpo_get_from_dpo(dpo);
    l2b->l2b_locks--;

    if (0 == l2b->l2b_locks)
    {
        l2_bridge_dpo_db[l2b->l2b_sw_if_index] = INDEX_INVALID;
        pool_put(l2_bridge_dpo_pool, l2b);
    }
}

/*
 * l2_bridge_dpo_add_or_lock
 *
 * Add/create and lock a new or lock an existing for the L2 Bridge
 * on the interface given
 */
void
l2_bridge_dpo_add_or_lock (u32 sw_if_index,
                           dpo_id_t *dpo)
{
    l2_bridge_dpo_t *l2b;

    vec_validate_init_empty(l2_bridge_dpo_db,
                            sw_if_index,
                            INDEX_INVALID);

    if (INDEX_INVALID == l2_bridge_dpo_db[sw_if_index])
    {
        l2b = l2_bridge_dpo_alloc();

        l2b->l2b_sw_if_index = sw_if_index;

        l2_bridge_dpo_db[sw_if_index] =
            l2_bridge_dpo_get_index(l2b);
    }
    else
    {
        l2b = l2_bridge_dpo_get(l2_bridge_dpo_db[sw_if_index]);
    }

    dpo_set(dpo, DPO_L2_BRIDGE, DPO_PROTO_ETHERNET, l2_bridge_dpo_get_index(l2b));
}


static clib_error_t *
l2_bridge_dpo_interface_state_change (vnet_main_t * vnm,
                                      u32 sw_if_index,
                                      u32 flags)
{
    /*
     */
    return (NULL);
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION(
    l2_bridge_dpo_interface_state_change);

/**
 * @brief Registered callback for HW interface state changes
 */
static clib_error_t *
l2_bridge_dpo_hw_interface_state_change (vnet_main_t * vnm,
                                         u32 hw_if_index,
                                         u32 flags)
{
    return (NULL);
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION(
    l2_bridge_dpo_hw_interface_state_change);

static clib_error_t *
l2_bridge_dpo_interface_delete (vnet_main_t * vnm,
                                u32 sw_if_index,
                                u32 is_add)
{
    return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION(
    l2_bridge_dpo_interface_delete);

u8*
format_l2_bridge_dpo (u8* s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);
    vnet_main_t * vnm = vnet_get_main();
    l2_bridge_dpo_t *l2b = l2_bridge_dpo_get(index);

    return (format(s, "l2-bridge-%U-dpo",
                   format_vnet_sw_interface_name,
                   vnm,
                   vnet_get_sw_interface(vnm, l2b->l2b_sw_if_index)));
}

static void
l2_bridge_dpo_mem_show (void)
{
    fib_show_memory_usage("L2-bridge",
                          pool_elts(l2_bridge_dpo_pool),
                          pool_len(l2_bridge_dpo_pool),
                          sizeof(l2_bridge_dpo_t));
}


const static dpo_vft_t l2_bridge_dpo_vft = {
    .dv_lock = l2_bridge_dpo_lock,
    .dv_unlock = l2_bridge_dpo_unlock,
    .dv_format = format_l2_bridge_dpo,
    .dv_mem_show = l2_bridge_dpo_mem_show,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a glean
 *        object.
 *
 * this means that these graph nodes are ones from which a glean is the
 * parent object in the DPO-graph.
 */
const static char* const l2_bridge_dpo_l2_nodes[] =
{
    "l2-bridge-dpo",
    NULL,
};

const static char* const * const l2_bridge_dpo_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_ETHERNET]  = l2_bridge_dpo_l2_nodes,
};

void
l2_bridge_dpo_module_init (void)
{
    dpo_register(DPO_L2_BRIDGE,
                 &l2_bridge_dpo_vft,
                 l2_bridge_dpo_nodes);
}

/**
 * @brief Interface DPO trace data
 */
typedef struct l2_bridge_dpo_trace_t_
{
    u32 sw_if_index;
} l2_bridge_dpo_trace_t;

typedef enum l2_bridge_dpo_next_t_
{
    L2_BRIDGE_DPO_DROP = 0,
    L2_BRIDGE_DPO_OUTPUT = 1,
} l2_bridge_dpo_next_t;

always_inline uword
l2_bridge_dpo_inline (vlib_main_t * vm,
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

        while (n_left_from >= 4 && n_left_to_next > 2)
        {
            const l2_bridge_dpo_t *l2b0, *l2b1;
            u32 bi0, l2bi0, bi1, l2bi1;
            vlib_buffer_t *b0, *b1;
            u8 len0, len1;

            bi0 = from[0];
            to_next[0] = bi0;
            bi1 = from[1];
            to_next[1] = bi1;
            from += 2;
            to_next += 2;
            n_left_from -= 2;
            n_left_to_next -= 2;

            b0 = vlib_get_buffer (vm, bi0);
            b1 = vlib_get_buffer (vm, bi1);

            l2bi0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
            l2bi1 = vnet_buffer(b1)->ip.adj_index[VLIB_TX];
            l2b0 = l2_bridge_dpo_get(l2bi0);
            l2b1 = l2_bridge_dpo_get(l2bi1);

            vnet_buffer(b0)->sw_if_index[VLIB_TX] = l2b0->l2b_sw_if_index;
            vnet_buffer(b1)->sw_if_index[VLIB_TX] = l2b1->l2b_sw_if_index;

            len0 = ((u8*)vlib_buffer_get_current(b0) -
                    (u8*)ethernet_buffer_get_header(b0));
            len1 = ((u8*)vlib_buffer_get_current(b1) -
                    (u8*)ethernet_buffer_get_header(b1));
            vnet_buffer(b0)->l2.l2_len = len0;
            vnet_buffer(b1)->l2.l2_len = len1;

            vlib_buffer_advance(b0, -len0);
            vlib_buffer_advance(b1, -len1);

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                l2_bridge_dpo_trace_t *tr0;

                tr0 = vlib_add_trace (vm, node, b0, sizeof (*tr0));
                tr0->sw_if_index = l2b0->l2b_sw_if_index;
            }
            if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
                l2_bridge_dpo_trace_t *tr1;

                tr1 = vlib_add_trace (vm, node, b1, sizeof (*tr1));
                tr1->sw_if_index = l2b1->l2b_sw_if_index;
            }

            vlib_validate_buffer_enqueue_x2(vm, node, next_index, to_next,
                                            n_left_to_next, bi0, bi1,
                                            L2_BRIDGE_DPO_OUTPUT,
                                            L2_BRIDGE_DPO_OUTPUT);
        }

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            const l2_bridge_dpo_t * l2b0;
            vlib_buffer_t * b0;
            u32 bi0, l2bi0;
            u8 len0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);

            l2bi0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
            l2b0 = l2_bridge_dpo_get(l2bi0);

            vnet_buffer(b0)->sw_if_index[VLIB_TX] = l2b0->l2b_sw_if_index;

            /*
             * take that, and rewind it back...
             */
            len0 = ((u8*)vlib_buffer_get_current(b0) -
                    (u8*)ethernet_buffer_get_header(b0));
            vnet_buffer(b0)->l2.l2_len = len0;
            vlib_buffer_advance(b0, -len0);

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                l2_bridge_dpo_trace_t *tr;

                tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
                tr->sw_if_index = l2b0->l2b_sw_if_index;
            }

            vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                            n_left_to_next, bi0,
                                            L2_BRIDGE_DPO_OUTPUT);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return from_frame->n_vectors;
}

static u8 *
format_l2_bridge_dpo_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    l2_bridge_dpo_trace_t * t = va_arg (*args, l2_bridge_dpo_trace_t *);
    u32 indent = format_get_indent (s);
    s = format (s, "%U sw_if_index:%d",
                format_white_space, indent,
                t->sw_if_index);
    return s;
}

static uword
l2_bridge_dpo_l2 (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
    return (l2_bridge_dpo_inline(vm, node, from_frame));
}


VLIB_REGISTER_NODE (l2_bridge_dpo_l2_node) = {
    .function = l2_bridge_dpo_l2,
    .name = "l2-bridge-dpo",
    .vector_size = sizeof (u32),
    .format_trace = format_l2_bridge_dpo_trace,

    .n_next_nodes = 2,
    .next_nodes = {
        [L2_BRIDGE_DPO_DROP] = "error-drop",
        [L2_BRIDGE_DPO_OUTPUT] = "l2-output",
    },
};

VLIB_NODE_FUNCTION_MULTIARCH (l2_bridge_dpo_l2_node,
                              l2_bridge_dpo_l2)
