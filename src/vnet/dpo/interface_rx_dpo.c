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

#include <vnet/dpo/interface_rx_dpo.h>
#include <vnet/fib/fib_node.h>
#include <vnet/l2/l2_input.h>

#ifndef CLIB_MARCH_VARIANT
interface_rx_dpo_t *interface_rx_dpo_pool;

/*
 * The 'DB' of interface DPOs.
 * There is only one  per-interface per-protocol, so this is a per-interface
 * vector
 */
static index_t *interface_rx_dpo_db[DPO_PROTO_NUM];

static interface_rx_dpo_t *
interface_rx_dpo_alloc (void)
{
    interface_rx_dpo_t *ido;

    pool_get(interface_rx_dpo_pool, ido);

    return (ido);
}

static inline interface_rx_dpo_t *
interface_rx_dpo_get_from_dpo (const dpo_id_t *dpo)
{
    ASSERT(DPO_INTERFACE_RX == dpo->dpoi_type);

    return (interface_rx_dpo_get(dpo->dpoi_index));
}

static inline index_t
interface_rx_dpo_get_index (interface_rx_dpo_t *ido)
{
    return (ido - interface_rx_dpo_pool);
}

static void
interface_rx_dpo_lock (dpo_id_t *dpo)
{
    interface_rx_dpo_t *ido;

    ido = interface_rx_dpo_get_from_dpo(dpo);
    ido->ido_locks++;
}

static void
interface_rx_dpo_unlock (dpo_id_t *dpo)
{
    interface_rx_dpo_t *ido;

    ido = interface_rx_dpo_get_from_dpo(dpo);
    ido->ido_locks--;

    if (0 == ido->ido_locks)
    {
        interface_rx_dpo_db[ido->ido_proto][ido->ido_sw_if_index] =
            INDEX_INVALID;
        pool_put(interface_rx_dpo_pool, ido);
    }
}

/*
 * interface_rx_dpo_add_or_lock
 *
 * Add/create and lock a new or lock an existing for the interface DPO
 * on the interface and protocol given
 */
void
interface_rx_dpo_add_or_lock (dpo_proto_t proto,
                              u32 sw_if_index,
                              dpo_id_t *dpo)
{
    interface_rx_dpo_t *ido;

    vec_validate_init_empty(interface_rx_dpo_db[proto],
                            sw_if_index,
                            INDEX_INVALID);

    if (INDEX_INVALID == interface_rx_dpo_db[proto][sw_if_index])
    {
        ido = interface_rx_dpo_alloc();

        ido->ido_sw_if_index = sw_if_index;
        ido->ido_proto = proto;

        interface_rx_dpo_db[proto][sw_if_index] =
            interface_rx_dpo_get_index(ido);
    }
    else
    {
        ido = interface_rx_dpo_get(interface_rx_dpo_db[proto][sw_if_index]);
    }

    dpo_set(dpo, DPO_INTERFACE_RX, proto, interface_rx_dpo_get_index(ido));
}
#endif /* CLIB_MARCH_VARIANT */


static clib_error_t *
interface_rx_dpo_interface_state_change (vnet_main_t * vnm,
                                         u32 sw_if_index,
                                         u32 flags)
{
    /*
     */
    return (NULL);
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION(
    interface_rx_dpo_interface_state_change);

/**
 * @brief Registered callback for HW interface state changes
 */
static clib_error_t *
interface_rx_dpo_hw_interface_state_change (vnet_main_t * vnm,
                                            u32 hw_if_index,
                                            u32 flags)
{
    return (NULL);
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION(
    interface_rx_dpo_hw_interface_state_change);

static clib_error_t *
interface_rx_dpo_interface_delete (vnet_main_t * vnm,
                                   u32 sw_if_index,
                                   u32 is_add)
{
    return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION(
    interface_rx_dpo_interface_delete);

#ifndef CLIB_MARCH_VARIANT
static u8*
format_interface_rx_dpo (u8* s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);
    vnet_main_t * vnm = vnet_get_main();
    interface_rx_dpo_t *ido = interface_rx_dpo_get(index);

    return (format(s, "%U-rx-dpo: %U",
                   format_vnet_sw_interface_name,
                   vnm,
                   vnet_get_sw_interface(vnm, ido->ido_sw_if_index),
                   format_dpo_proto, ido->ido_proto));
}

static void
interface_rx_dpo_mem_show (void)
{
    fib_show_memory_usage("Interface",
                          pool_elts(interface_rx_dpo_pool),
                          pool_len(interface_rx_dpo_pool),
                          sizeof(interface_rx_dpo_t));
}


const static dpo_vft_t interface_rx_dpo_vft = {
    .dv_lock = interface_rx_dpo_lock,
    .dv_unlock = interface_rx_dpo_unlock,
    .dv_format = format_interface_rx_dpo,
    .dv_mem_show = interface_rx_dpo_mem_show,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a glean
 *        object.
 *
 * this means that these graph nodes are ones from which a glean is the
 * parent object in the DPO-graph.
 */
const static char* const interface_rx_dpo_ip4_nodes[] =
{
    "interface-rx-dpo-ip4",
    NULL,
};
const static char* const interface_rx_dpo_ip6_nodes[] =
{
    "interface-rx-dpo-ip6",
    NULL,
};
const static char* const interface_rx_dpo_l2_nodes[] =
{
    "interface-rx-dpo-l2",
    NULL,
};

const static char* const * const interface_rx_dpo_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = interface_rx_dpo_ip4_nodes,
    [DPO_PROTO_IP6]  = interface_rx_dpo_ip6_nodes,
    [DPO_PROTO_ETHERNET]  = interface_rx_dpo_l2_nodes,
    [DPO_PROTO_MPLS] = NULL,
};

void
interface_rx_dpo_module_init (void)
{
    dpo_register(DPO_INTERFACE_RX,
                 &interface_rx_dpo_vft,
                 interface_rx_dpo_nodes);
}
#endif /* CLIB_MARCH_VARIANT */

/**
 * @brief Interface DPO trace data
 */
typedef struct interface_rx_dpo_trace_t_
{
    u32 sw_if_index;
} interface_rx_dpo_trace_t;

typedef enum interface_rx_dpo_next_t_
{
    INTERFACE_RX_DPO_DROP = 0,
    INTERFACE_RX_DPO_INPUT = 1,
} interface_rx_dpo_next_t;

always_inline uword
interface_rx_dpo_inline (vlib_main_t * vm,
                         vlib_node_runtime_t * node,
                         vlib_frame_t * from_frame,
			 u8 is_l2)
{
    u32 n_left_from, next_index, * from, * to_next;
    u32 thread_index = vm->thread_index;
    vnet_interface_main_t *im;

    im = &vnet_get_main ()->interface_main;
    from = vlib_frame_vector_args (from_frame);
    n_left_from = from_frame->n_vectors;

    next_index = INTERFACE_RX_DPO_INPUT;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from >= 4 && n_left_to_next > 2)
        {
            const interface_rx_dpo_t *ido0, *ido1;
            u32 bi0, idoi0, bi1, idoi1;
            vlib_buffer_t *b0, *b1;

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

            idoi0 = vnet_buffer(b0)->ip.adj_index;
            idoi1 = vnet_buffer(b1)->ip.adj_index;
            ido0 = interface_rx_dpo_get(idoi0);
            ido1 = interface_rx_dpo_get(idoi1);

            vnet_buffer(b0)->sw_if_index[VLIB_RX] = ido0->ido_sw_if_index;
            vnet_buffer(b1)->sw_if_index[VLIB_RX] = ido1->ido_sw_if_index;

	    if (is_l2)
	    {
		vnet_update_l2_len (b0);
		vnet_update_l2_len (b1);
	    }

            vlib_increment_combined_counter (im->combined_sw_if_counters
                                             + VNET_INTERFACE_COUNTER_RX,
                                             thread_index,
                                             ido0->ido_sw_if_index,
                                             1,
                                             vlib_buffer_length_in_chain (vm, b0));
            vlib_increment_combined_counter (im->combined_sw_if_counters
                                             + VNET_INTERFACE_COUNTER_RX,
                                             thread_index,
                                             ido1->ido_sw_if_index,
                                             1,
                                             vlib_buffer_length_in_chain (vm, b1));

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                interface_rx_dpo_trace_t *tr0;

                tr0 = vlib_add_trace (vm, node, b0, sizeof (*tr0));
                tr0->sw_if_index = ido0->ido_sw_if_index;
            }
            if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
                interface_rx_dpo_trace_t *tr1;

                tr1 = vlib_add_trace (vm, node, b1, sizeof (*tr1));
                tr1->sw_if_index = ido1->ido_sw_if_index;
            }
        }

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            const interface_rx_dpo_t * ido0;
            vlib_buffer_t * b0;
            u32 bi0, idoi0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);

            idoi0 = vnet_buffer(b0)->ip.adj_index;
            ido0 = interface_rx_dpo_get(idoi0);

            /* Swap the RX interface of the packet to the one the
             * interface DPR represents */
            vnet_buffer(b0)->sw_if_index[VLIB_RX] = ido0->ido_sw_if_index;

	    /* Update l2_len to make l2 tag rewrite work */
	    if (is_l2)
		vnet_update_l2_len (b0);

            /* Bump the interface's RX coutners */
            vlib_increment_combined_counter (im->combined_sw_if_counters
                                             + VNET_INTERFACE_COUNTER_RX,
                                             thread_index,
                                             ido0->ido_sw_if_index,
                                             1,
                                             vlib_buffer_length_in_chain (vm, b0));

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                interface_rx_dpo_trace_t *tr;

                tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
                tr->sw_if_index = ido0->ido_sw_if_index;
            }
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return from_frame->n_vectors;
}

static u8 *
format_interface_rx_dpo_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    interface_rx_dpo_trace_t * t = va_arg (*args, interface_rx_dpo_trace_t *);
    u32 indent = format_get_indent (s);
    s = format (s, "%U sw_if_index:%d",
                format_white_space, indent,
                t->sw_if_index);
    return s;
}

VLIB_NODE_FN (interface_rx_dpo_ip4_node) (vlib_main_t * vm,
                      vlib_node_runtime_t * node,
                      vlib_frame_t * from_frame)
{
    return (interface_rx_dpo_inline(vm, node, from_frame, 0));
}

VLIB_NODE_FN (interface_rx_dpo_ip6_node) (vlib_main_t * vm,
                      vlib_node_runtime_t * node,
                      vlib_frame_t * from_frame)
{
    return (interface_rx_dpo_inline(vm, node, from_frame, 0));
}

VLIB_NODE_FN (interface_rx_dpo_l2_node) (vlib_main_t * vm,
                     vlib_node_runtime_t * node,
                     vlib_frame_t * from_frame)
{
    return (interface_rx_dpo_inline(vm, node, from_frame, 1));
}

VLIB_REGISTER_NODE (interface_rx_dpo_ip4_node) = {
    .name = "interface-rx-dpo-ip4",
    .vector_size = sizeof (u32),
    .format_trace = format_interface_rx_dpo_trace,

    .n_next_nodes = 2,
    .next_nodes = {
        [INTERFACE_RX_DPO_DROP] = "ip4-drop",
        [INTERFACE_RX_DPO_INPUT] = "ip4-input",
    },
};


VLIB_REGISTER_NODE (interface_rx_dpo_ip6_node) = {
    .name = "interface-rx-dpo-ip6",
    .vector_size = sizeof (u32),
    .format_trace = format_interface_rx_dpo_trace,

    .n_next_nodes = 2,
    .next_nodes = {
        [INTERFACE_RX_DPO_DROP] = "ip6-drop",
        [INTERFACE_RX_DPO_INPUT] = "ip6-input",
    },
};


VLIB_REGISTER_NODE (interface_rx_dpo_l2_node) = {
    .name = "interface-rx-dpo-l2",
    .vector_size = sizeof (u32),
    .format_trace = format_interface_rx_dpo_trace,

    .n_next_nodes = 2,
    .next_nodes = {
        [INTERFACE_RX_DPO_DROP] = "error-drop",
        [INTERFACE_RX_DPO_INPUT] = "l2-input",
    },
};

