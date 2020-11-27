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

#include <vnet/dpo/dvr_dpo.h>
#include <vnet/fib/fib_node.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/l2/l2_input.h>

#ifndef CLIB_MARCH_VARIANT
dvr_dpo_t *dvr_dpo_pool;

/**
 * The 'DB' of DVR DPOs.
 * There is one per-interface per-L3 proto, so this is a per-interface vector
 */
static index_t *dvr_dpo_db[DPO_PROTO_NUM];

static dvr_dpo_t *
dvr_dpo_alloc (void)
{
    dvr_dpo_t *dd;

    pool_get(dvr_dpo_pool, dd);

    return (dd);
}

static inline dvr_dpo_t *
dvr_dpo_get_from_dpo (const dpo_id_t *dpo)
{
    ASSERT(DPO_DVR == dpo->dpoi_type);

    return (dvr_dpo_get(dpo->dpoi_index));
}

static inline index_t
dvr_dpo_get_index (dvr_dpo_t *dd)
{
    return (dd - dvr_dpo_pool);
}

static void
dvr_dpo_lock (dpo_id_t *dpo)
{
    dvr_dpo_t *dd;

    dd = dvr_dpo_get_from_dpo(dpo);
    dd->dd_locks++;
}

static void
dvr_dpo_unlock (dpo_id_t *dpo)
{
    dvr_dpo_t *dd;

    dd = dvr_dpo_get_from_dpo(dpo);
    dd->dd_locks--;

    if (0 == dd->dd_locks)
    {
        if (DPO_PROTO_IP4 == dd->dd_proto)
        {
            vnet_feature_enable_disable ("ip4-output", "ip4-dvr-reinject",
                                         dd->dd_sw_if_index, 0, 0, 0);
        }
        else
        {
            vnet_feature_enable_disable ("ip6-output", "ip6-dvr-reinject",
                                         dd->dd_sw_if_index, 0, 0, 0);
        }

        dvr_dpo_db[dd->dd_proto][dd->dd_sw_if_index] = INDEX_INVALID;
        pool_put(dvr_dpo_pool, dd);
    }
}

void
dvr_dpo_add_or_lock (u32 sw_if_index,
                     dpo_proto_t dproto,
                     dpo_id_t *dpo)
{
    l2_input_config_t *config;
    dvr_dpo_t *dd;

    vec_validate_init_empty(dvr_dpo_db[dproto],
                            sw_if_index,
                            INDEX_INVALID);

    if (INDEX_INVALID == dvr_dpo_db[dproto][sw_if_index])
    {
        dd = dvr_dpo_alloc();

        dd->dd_sw_if_index = sw_if_index;
        dd->dd_proto = dproto;

        dvr_dpo_db[dproto][sw_if_index] = dvr_dpo_get_index(dd);

        config = l2input_intf_config (sw_if_index);

        if (l2_input_is_bridge(config) ||
            l2_input_is_xconnect(config))
        {
            dd->dd_reinject = DVR_REINJECT_L2;
        }
        else
        {
            dd->dd_reinject = DVR_REINJECT_L3;
        }

        /*
         * enable the reinject into L2 path feature on the interface
         */
        if (DPO_PROTO_IP4 == dproto)
            vnet_feature_enable_disable ("ip4-output", "ip4-dvr-reinject",
                                         dd->dd_sw_if_index, 1, 0, 0);
        else if (DPO_PROTO_IP6 == dproto)
            vnet_feature_enable_disable ("ip6-output", "ip6-dvr-reinject",
                                         dd->dd_sw_if_index, 1, 0, 0);
        else
            ASSERT(0);
    }
    else
    {
        dd = dvr_dpo_get(dvr_dpo_db[dproto][sw_if_index]);
    }

    dpo_set(dpo, DPO_DVR, dproto, dvr_dpo_get_index(dd));
}
#endif /* CLIB_MARCH_VARIANT */


static clib_error_t *
dvr_dpo_interface_state_change (vnet_main_t * vnm,
                                      u32 sw_if_index,
                                      u32 flags)
{
    /*
     */
    return (NULL);
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION(
    dvr_dpo_interface_state_change);

/**
 * @brief Registered callback for HW interface state changes
 */
static clib_error_t *
dvr_dpo_hw_interface_state_change (vnet_main_t * vnm,
                                         u32 hw_if_index,
                                         u32 flags)
{
    return (NULL);
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION(
    dvr_dpo_hw_interface_state_change);

static clib_error_t *
dvr_dpo_interface_delete (vnet_main_t * vnm,
                                u32 sw_if_index,
                                u32 is_add)
{
    return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION(
    dvr_dpo_interface_delete);

#ifndef CLIB_MARCH_VARIANT
static u8*
format_dvr_reinject (u8* s, va_list *ap)
{
    dvr_dpo_reinject_t ddr = va_arg(*ap, int);

    switch (ddr)
    {
    case DVR_REINJECT_L2:
        s = format (s, "l2");
        break;
    case DVR_REINJECT_L3:
        s = format (s, "l3");
        break;
    }
    return (s);
}

static u8*
format_dvr_dpo (u8* s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);
    vnet_main_t * vnm = vnet_get_main();
    dvr_dpo_t *dd = dvr_dpo_get(index);

    return (format(s, "%U-dvr-%U-dpo %U",
                   format_dpo_proto, dd->dd_proto,
                   format_vnet_sw_interface_name,
                   vnm,
                   vnet_get_sw_interface(vnm, dd->dd_sw_if_index),
                   format_dvr_reinject, dd->dd_reinject));
}

static void
dvr_dpo_mem_show (void)
{
    fib_show_memory_usage("DVR",
                          pool_elts(dvr_dpo_pool),
                          pool_len(dvr_dpo_pool),
                          sizeof(dvr_dpo_t));
}


const static dpo_vft_t dvr_dpo_vft = {
    .dv_lock = dvr_dpo_lock,
    .dv_unlock = dvr_dpo_unlock,
    .dv_format = format_dvr_dpo,
    .dv_mem_show = dvr_dpo_mem_show,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a glean
 *        object.
 *
 * this means that these graph nodes are ones from which a glean is the
 * parent object in the DPO-graph.
 */
const static char* const dvr_dpo_ip4_nodes[] =
{
    "ip4-dvr-dpo",
    NULL,
};
const static char* const dvr_dpo_ip6_nodes[] =
{
    "ip6-dvr-dpo",
    NULL,
};

const static char* const * const dvr_dpo_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = dvr_dpo_ip4_nodes,
    [DPO_PROTO_IP6]  = dvr_dpo_ip6_nodes,
};

void
dvr_dpo_module_init (void)
{
    dpo_register(DPO_DVR,
                 &dvr_dpo_vft,
                 dvr_dpo_nodes);
}
#endif /* CLIB_MARCH_VARIANT */

/**
 * @brief Interface DPO trace data
 */
typedef struct dvr_dpo_trace_t_
{
    u32 sw_if_index;
} dvr_dpo_trace_t;

always_inline uword
dvr_dpo_inline (vlib_main_t * vm,
                vlib_node_runtime_t * node,
                vlib_frame_t * from_frame,
                u8 is_ip6)
{
    u32 n_left_from, next_index, * from, * to_next;
    ip_lookup_main_t *lm = (is_ip6?
                            &ip6_main.lookup_main:
                            &ip4_main.lookup_main);

    from = vlib_frame_vector_args (from_frame);
    n_left_from = from_frame->n_vectors;

    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from >= 4 && n_left_to_next > 2)
        {
            const dvr_dpo_t *dd0, *dd1;
            u32 bi0, ddi0, bi1, ddi1;
            vlib_buffer_t *b0, *b1;
            u32 next0, next1;
            u8 len0, len1;

            bi0 = from[0];
            to_next[0] = bi0;
            bi1 = from[1];
            to_next[1] = bi1;
            from += 2;
            to_next += 2;
            n_left_from -= 2;
            n_left_to_next -= 2;
            next0 = next1 = 0;

            b0 = vlib_get_buffer (vm, bi0);
            b1 = vlib_get_buffer (vm, bi1);

            ddi0 = vnet_buffer(b0)->ip.adj_index;
            ddi1 = vnet_buffer(b1)->ip.adj_index;
            dd0 = dvr_dpo_get(ddi0);
            dd1 = dvr_dpo_get(ddi1);

            vnet_buffer(b0)->sw_if_index[VLIB_TX] = dd0->dd_sw_if_index;
            vnet_buffer(b1)->sw_if_index[VLIB_TX] = dd1->dd_sw_if_index;

            len0 = ((u8*)vlib_buffer_get_current(b0) -
                    (u8*)ethernet_buffer_get_header(b0));
            len1 = ((u8*)vlib_buffer_get_current(b1) -
                    (u8*)ethernet_buffer_get_header(b1));
            vnet_buffer(b0)->l2.l2_len =
                vnet_buffer(b0)->ip.save_rewrite_length =
                   len0;
            vnet_buffer(b1)->l2.l2_len =
                vnet_buffer(b1)->ip.save_rewrite_length =
                    len1;

            b0->flags |= VNET_BUFFER_F_IS_DVR;
            b1->flags |= VNET_BUFFER_F_IS_DVR;

            vlib_buffer_advance(b0, -len0);
            vlib_buffer_advance(b1, -len1);

            vnet_feature_arc_start (lm->output_feature_arc_index,
                                    dd0->dd_sw_if_index, &next0, b0);
            vnet_feature_arc_start (lm->output_feature_arc_index,
                                    dd1->dd_sw_if_index, &next1, b1);

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                dvr_dpo_trace_t *tr0;

                tr0 = vlib_add_trace (vm, node, b0, sizeof (*tr0));
                tr0->sw_if_index = dd0->dd_sw_if_index;
            }
            if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
                dvr_dpo_trace_t *tr1;

                tr1 = vlib_add_trace (vm, node, b1, sizeof (*tr1));
                tr1->sw_if_index = dd1->dd_sw_if_index;
            }

            vlib_validate_buffer_enqueue_x2(vm, node, next_index, to_next,
                                            n_left_to_next, bi0, bi1,
                                            next0, next1);
        }

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            const dvr_dpo_t * dd0;
            vlib_buffer_t * b0;
            u32 bi0, ddi0;
            u32 next0;
            u8 len0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;
            next0 = 0;

            b0 = vlib_get_buffer (vm, bi0);

            ddi0 = vnet_buffer(b0)->ip.adj_index;
            dd0 = dvr_dpo_get(ddi0);

            vnet_buffer(b0)->sw_if_index[VLIB_TX] = dd0->dd_sw_if_index;

            /*
             * take that, rewind it back...
             */
            len0 = ((u8*)vlib_buffer_get_current(b0) -
                    (u8*)ethernet_buffer_get_header(b0));
            vnet_buffer(b0)->l2.l2_len =
                vnet_buffer(b0)->ip.save_rewrite_length =
                    len0;
            b0->flags |= VNET_BUFFER_F_IS_DVR;
            vlib_buffer_advance(b0, -len0);

            /*
             * start processing the ipX output features
             */
            vnet_feature_arc_start(lm->output_feature_arc_index,
                                   dd0->dd_sw_if_index, &next0, b0);

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                dvr_dpo_trace_t *tr;

                tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
                tr->sw_if_index = dd0->dd_sw_if_index;
            }

            vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                            n_left_to_next, bi0,
                                            next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return from_frame->n_vectors;
}

static u8 *
format_dvr_dpo_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    dvr_dpo_trace_t * t = va_arg (*args, dvr_dpo_trace_t *);
    u32 indent = format_get_indent (s);
    s = format (s, "%U sw_if_index:%d",
                format_white_space, indent,
                t->sw_if_index);
    return s;
}

VLIB_NODE_FN (ip4_dvr_dpo_node) (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
    return (dvr_dpo_inline(vm, node, from_frame, 0));
}

VLIB_NODE_FN (ip6_dvr_dpo_node) (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
    return (dvr_dpo_inline(vm, node, from_frame, 1));
}

VLIB_REGISTER_NODE (ip4_dvr_dpo_node) = {
    .name = "ip4-dvr-dpo",
    .vector_size = sizeof (u32),
    .format_trace = format_dvr_dpo_trace,
    .sibling_of = "ip4-rewrite",
};
VLIB_REGISTER_NODE (ip6_dvr_dpo_node) = {
    .name = "ip6-dvr-dpo",
    .vector_size = sizeof (u32),
    .format_trace = format_dvr_dpo_trace,
    .sibling_of = "ip6-rewrite",
};

typedef enum dvr_reinject_next_t_
{
    DVR_REINJECT_NEXT_L2,
    DVR_REINJECT_NEXT_L3,
} dvr_reinject_next_t;

always_inline uword
dvr_reinject_inline (vlib_main_t * vm,
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
            dvr_reinject_next_t next0, next1;
            const dvr_dpo_t *dd0, *dd1;
            u32 bi0, bi1, ddi0, ddi1;
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

            if (b0->flags & VNET_BUFFER_F_IS_DVR)
            {
                ddi0 = vnet_buffer(b0)->ip.adj_index;
                dd0 = dvr_dpo_get(ddi0);
                next0 = (dd0->dd_reinject == DVR_REINJECT_L2 ?
                         DVR_REINJECT_NEXT_L2 :
                         DVR_REINJECT_NEXT_L3);
            }
            else
                vnet_feature_next( &next0, b0);

            if (b1->flags & VNET_BUFFER_F_IS_DVR)
            {
                ddi1 = vnet_buffer(b1)->ip.adj_index;
                dd1 = dvr_dpo_get(ddi1);
                next1 = (dd1->dd_reinject == DVR_REINJECT_L2 ?
                         DVR_REINJECT_NEXT_L2 :
                         DVR_REINJECT_NEXT_L3);
            }
            else
                vnet_feature_next( &next1, b1);

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                dvr_dpo_trace_t *tr0;

                tr0 = vlib_add_trace (vm, node, b0, sizeof (*tr0));
                tr0->sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_TX];
            }
            if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
                dvr_dpo_trace_t *tr1;

                tr1 = vlib_add_trace (vm, node, b1, sizeof (*tr1));
                tr1->sw_if_index = vnet_buffer(b1)->sw_if_index[VLIB_TX];
            }

            vlib_validate_buffer_enqueue_x2(vm, node, next_index, to_next,
                                            n_left_to_next, bi0, bi1,
                                            next0, next1);
        }

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            dvr_reinject_next_t next0;
            const dvr_dpo_t *dd0;
            vlib_buffer_t * b0;
            u32 bi0, ddi0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);

            if (b0->flags & VNET_BUFFER_F_IS_DVR)
            {
                ddi0 = vnet_buffer(b0)->ip.adj_index;
                dd0 = dvr_dpo_get(ddi0);
                next0 = (dd0->dd_reinject == DVR_REINJECT_L2 ?
                         DVR_REINJECT_NEXT_L2 :
                         DVR_REINJECT_NEXT_L3);
            }
            else
                vnet_feature_next( &next0, b0);

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                dvr_dpo_trace_t *tr;

                tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
                tr->sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_TX];
            }

            vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                            n_left_to_next, bi0, next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return from_frame->n_vectors;
}

VLIB_NODE_FN (ip4_dvr_reinject_node) (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
    return (dvr_reinject_inline(vm, node, from_frame));
}

VLIB_NODE_FN (ip6_dvr_reinject_node) (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
    return (dvr_reinject_inline(vm, node, from_frame));
}

VLIB_REGISTER_NODE (ip4_dvr_reinject_node) = {
    .name = "ip4-dvr-reinject",
    .vector_size = sizeof (u32),
    .format_trace = format_dvr_dpo_trace,

    .n_next_nodes = 1,
    .next_nodes = {
        [DVR_REINJECT_NEXT_L2] = "l2-output",
        [DVR_REINJECT_NEXT_L3] = "interface-output",
    },
};

VLIB_REGISTER_NODE (ip6_dvr_reinject_node) = {
    .name = "ip6-dvr-reinject",
    .vector_size = sizeof (u32),
    .format_trace = format_dvr_dpo_trace,

    .n_next_nodes = 1,
    .next_nodes = {
        [DVR_REINJECT_NEXT_L2] = "l2-output",
        [DVR_REINJECT_NEXT_L3] = "interface-output",
    },
};

VNET_FEATURE_INIT (ip4_dvr_reinject_feat_node, static) =
{
  .arc_name = "ip4-output",
  .node_name = "ip4-dvr-reinject",
  .runs_after = VNET_FEATURES ("nat44-in2out-output",
                               "acl-plugin-out-ip4-fa"),
};
VNET_FEATURE_INIT (ip6_dvr_reinject_feat_node, static) =
{
  .arc_name = "ip6-output",
  .node_name = "ip6-dvr-reinject",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip6-fa"),
};

