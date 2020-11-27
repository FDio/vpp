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

#include <vnet/dpo/pw_cw.h>
#include <vnet/fib/fib_node.h>

#ifndef CLIB_MARCH_VARIANT

/*
 * pool of all MPLS Label DPOs
 */
pw_cw_dpo_t *pw_cw_dpo_pool;

static pw_cw_dpo_t *
pw_cw_dpo_alloc (void)
{
    pw_cw_dpo_t *pwcw;

    pool_get_aligned_zero(pw_cw_dpo_pool, pwcw, 8);

    return (pwcw);
}

static index_t
pw_cw_dpo_get_index (pw_cw_dpo_t *pwcw)
{
    return (pwcw - pw_cw_dpo_pool);
}

void
pw_cw_dpo_create (const dpo_id_t *parent,
                  dpo_id_t *dpo)
{
    pw_cw_dpo_t *pwcw;

    pwcw = pw_cw_dpo_alloc();

    /*
     * stack this disposition object on the parent given
     */
    dpo_stack(DPO_PW_CW,
              parent->dpoi_proto,
              &pwcw->pwcw_parent,
              parent);

    /*
     * set up the return DPO to refer to this object
     */
    dpo_set(dpo,
            DPO_PW_CW,
            parent->dpoi_proto,
            pw_cw_dpo_get_index(pwcw));
}

u8*
format_pw_cw_dpo (u8 *s, va_list *args)
{
    index_t pwcwi = va_arg (*args, index_t);
    u32 indent = va_arg (*args, u32);
    pw_cw_dpo_t *pwcw;

    if (pool_is_free_index(pw_cw_dpo_pool, pwcwi))
    {
        /*
         * the packet trace can be printed after the DPO has been deleted
         */
        return (format(s, "pw-cw[???,%d]:", pwcwi));
    }

    pwcw = pw_cw_dpo_get(pwcwi);
    s = format(s, "pw-cw[%d]:", pwcwi);

    s = format(s, "\n%U", format_white_space, indent);
    s = format(s, "%U", format_dpo_id, &pwcw->pwcw_parent, indent+2);

    return (s);
}

static void
pw_cw_dpo_lock (dpo_id_t *dpo)
{
    pw_cw_dpo_t *pwcw;

    pwcw = pw_cw_dpo_get(dpo->dpoi_index);

    pwcw->pwcw_locks++;
}

static void
pw_cw_dpo_unlock (dpo_id_t *dpo)
{
    pw_cw_dpo_t *pwcw;

    pwcw = pw_cw_dpo_get(dpo->dpoi_index);

    pwcw->pwcw_locks--;

    if (0 == pwcw->pwcw_locks)
    {
	dpo_reset(&pwcw->pwcw_parent);
	pool_put(pw_cw_dpo_pool, pwcw);
    }
}
#endif /* CLIB_MARCH_VARIANT */

/**
 * @brief A struct to hold tracing information for the MPLS label imposition
 * node.
 */
typedef struct pw_cw_trace_t_
{
    /**
     * The CW popped
     */
    u32 cw;
} pw_cw_trace_t;

always_inline uword
pw_cw_pop_inline (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
    u32 n_left_from, next_index, * from, * to_next;

    from = vlib_frame_vector_args(from_frame);
    n_left_from = from_frame->n_vectors;
    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from >= 4 && n_left_to_next >= 2)
        {
            pw_cw_dpo_t *pwcw0, *pwcw1;
            u32 bi0, pwcwi0, bi1, pwcwi1;
            vlib_buffer_t * b0, *b1;
            u32 next0, next1;

            bi0 = to_next[0] = from[0];
            bi1 = to_next[1] = from[1];

            /* Prefetch next iteration. */
            {
                vlib_buffer_t * p2, * p3;

                p2 = vlib_get_buffer(vm, from[2]);
                p3 = vlib_get_buffer(vm, from[3]);

                vlib_prefetch_buffer_header(p2, STORE);
                vlib_prefetch_buffer_header(p3, STORE);

                CLIB_PREFETCH(p2->data, sizeof(pw_cw_t), STORE);
                CLIB_PREFETCH(p3->data, sizeof(pw_cw_t), STORE);
            }

            from += 2;
            to_next += 2;
            n_left_from -= 2;
            n_left_to_next -= 2;

            b0 = vlib_get_buffer(vm, bi0);
            b1 = vlib_get_buffer(vm, bi1);

            /* get the next parent DPO for the next pop */
            pwcwi0 = vnet_buffer(b0)->ip.adj_index;
            pwcwi1 = vnet_buffer(b1)->ip.adj_index;
            pwcw0 = pw_cw_dpo_get(pwcwi0);
            pwcw1 = pw_cw_dpo_get(pwcwi1);

            next0 = pwcw0->pwcw_parent.dpoi_next_node;
            next1 = pwcw1->pwcw_parent.dpoi_next_node;

            vnet_buffer(b0)->ip.adj_index = pwcw0->pwcw_parent.dpoi_index;
            vnet_buffer(b1)->ip.adj_index = pwcw1->pwcw_parent.dpoi_index;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                pw_cw_trace_t *tr = vlib_add_trace(vm, node, b0, sizeof(*tr));

                tr->cw = *((pw_cw_t*) vlib_buffer_get_current(b0));
            }
            if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
                pw_cw_trace_t *tr = vlib_add_trace(vm, node, b1, sizeof(*tr));

                tr->cw = *((pw_cw_t*) vlib_buffer_get_current(b1));
            }

            /* pop the PW CW */
            vlib_buffer_advance (b0, sizeof(pw_cw_t));
            vlib_buffer_advance (b1, sizeof(pw_cw_t));

            vlib_validate_buffer_enqueue_x2(vm, node, next_index, to_next,
                                            n_left_to_next,
                                            bi0, bi1, next0, next1);
        }

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            pw_cw_dpo_t *pwcw0;
            vlib_buffer_t * b0;
            u32 bi0, pwcwi0;
            u32 next0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer(vm, bi0);

            pwcwi0 = vnet_buffer(b0)->ip.adj_index;
            pwcw0 = pw_cw_dpo_get(pwcwi0);
            next0 = pwcw0->pwcw_parent.dpoi_next_node;
            vnet_buffer(b0)->ip.adj_index = pwcw0->pwcw_parent.dpoi_index;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                pw_cw_trace_t *tr = vlib_add_trace(vm, node, b0, sizeof(*tr));

                tr->cw = *((pw_cw_t*) vlib_buffer_get_current(b0));
            }

            vlib_buffer_advance (b0, sizeof(pw_cw_t));

            vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                            n_left_to_next, bi0, next0);
        }
        vlib_put_next_frame(vm, node, next_index, n_left_to_next);
    }
    return from_frame->n_vectors;
}

static u8 *
format_pw_cw_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
    CLIB_UNUSED(pw_cw_trace_t * t);

    t = va_arg(*args, pw_cw_trace_t *);

    s = format(s, "cw:0x%x", t->cw);

    return (s);
}

VLIB_NODE_FN (pw_cw_node) (vlib_main_t * vm,
                           vlib_node_runtime_t * node,
                           vlib_frame_t * frame)
{
    return (pw_cw_pop_inline(vm, node, frame));
}

VLIB_REGISTER_NODE(pw_cw_node) = {
    .name = "pw-cw-pop",
    .vector_size = sizeof(u32),
    .format_trace = format_pw_cw_trace,
};

#ifndef CLIB_MARCH_VARIANT
static void
pw_cw_dpo_mem_show (void)
{
    fib_show_memory_usage("PW-CW",
			  pool_elts(pw_cw_dpo_pool),
			  pool_len(pw_cw_dpo_pool),
			  sizeof(pw_cw_dpo_t));
}

const static dpo_vft_t pwcw_vft = {
    .dv_lock = pw_cw_dpo_lock,
    .dv_unlock = pw_cw_dpo_unlock,
    .dv_format = format_pw_cw_dpo,
    .dv_mem_show = pw_cw_dpo_mem_show,
};

const static char* const pw_cw_proto_nodes[] =
{
    "pw-cw-pop",
    NULL,
};

const static char* const * const pw_cw_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = pw_cw_proto_nodes,
    [DPO_PROTO_IP6]  = pw_cw_proto_nodes,
    [DPO_PROTO_MPLS] = pw_cw_proto_nodes,
    [DPO_PROTO_ETHERNET] = pw_cw_proto_nodes,
};

void
pw_cw_dpo_module_init (void)
{
    dpo_register(DPO_PW_CW, &pwcw_vft, pw_cw_nodes);
}

#endif /* CLIB_MARCH_VARIANT */
