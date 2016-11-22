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

#include <vnet/mfib/mfib_itf.h>
#include <vnet/mfib/mfib_entry.h>
#include <vnet/dpo/replicate_dpo.h>
#include <vnet/mfib/ip4_mfib.h>
#include <vnet/mfib/ip6_mfib.h>

#include <vnet/ip/ip4.h>
#include <vnet/vnet.h>

typedef struct mfib_forward_lookup_trace_t_ {
    u32 entry_index;
    u32 fib_index;
} mfib_forward_lookup_trace_t;

static u8 *
format_mfib_forward_lookup_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    mfib_forward_lookup_trace_t * t = va_arg (*args, mfib_forward_lookup_trace_t *);

    s = format (s, "fib %d entry %d", t->fib_index, t->entry_index);
    return s;
}

/* Common trace function for all ip4-forward next nodes. */
void
mfib_forward_lookup_trace (vlib_main_t * vm,
                           vlib_node_runtime_t * node,
                           vlib_frame_t * frame)
{
    u32 * from, n_left;
    ip4_main_t * im = &ip4_main;

    n_left = frame->n_vectors;
    from = vlib_frame_vector_args (frame);

    while (n_left >= 4)
    {
        mfib_forward_lookup_trace_t * t0, * t1;
        vlib_buffer_t * b0, * b1;
        u32 bi0, bi1;

        /* Prefetch next iteration. */
        vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
        vlib_prefetch_buffer_with_index (vm, from[3], LOAD);

        bi0 = from[0];
        bi1 = from[1];

        b0 = vlib_get_buffer (vm, bi0);
        b1 = vlib_get_buffer (vm, bi1);

        if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
            t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
            t0->entry_index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
            t0->fib_index = vec_elt (im->mfib_index_by_sw_if_index,
                                     vnet_buffer(b1)->sw_if_index[VLIB_RX]);
	}
        if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
            t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
            t1->entry_index = vnet_buffer (b1)->ip.adj_index[VLIB_TX];
            t1->fib_index = vec_elt (im->mfib_index_by_sw_if_index,
                                     vnet_buffer(b1)->sw_if_index[VLIB_RX]);
	}
        from += 2;
        n_left -= 2;
    }

    while (n_left >= 1)
    {
        mfib_forward_lookup_trace_t * t0;
        vlib_buffer_t * b0;
        u32 bi0;

        bi0 = from[0];

        b0 = vlib_get_buffer (vm, bi0);

        if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
            t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
            t0->entry_index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
            t0->fib_index = vec_elt (im->mfib_index_by_sw_if_index,
                                     vnet_buffer(b0)->sw_if_index[VLIB_RX]);
	}
        from += 1;
        n_left -= 1;
    }
}

typedef enum mfib_forward_lookup_next_t_ {
    MFIB_FORWARD_LOOKUP_NEXT_RPF,
    MFIB_FORWARD_LOOKUP_N_NEXT,
} mfib_forward_lookup_next_t;

static uword
mfib_forward_lookup (vlib_main_t * vm,
                     vlib_node_runtime_t * node,
                     vlib_frame_t * frame,
                     int is_v4)
{
    u32 n_left_from, n_left_to_next, * from, * to_next;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;

    while (n_left_from > 0)
    {
        vlib_get_next_frame (vm, node, MFIB_FORWARD_LOOKUP_NEXT_RPF,
                             to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
	{
            fib_node_index_t mfei0;
            vlib_buffer_t * p0;
            ip4_header_t * ip0;
            u32 fib_index0;
            u32 pi0;

            pi0 = from[0];
            to_next[0] = pi0;
            from += 1;
            to_next += 1;
            n_left_to_next -= 1;
            n_left_from -= 1;

            p0 = vlib_get_buffer (vm, pi0);

            if (is_v4)
            {
                fib_index0 = vec_elt (ip4_main.mfib_index_by_sw_if_index,
                                      vnet_buffer(p0)->sw_if_index[VLIB_RX]);
                ip0 = vlib_buffer_get_current (p0);
                mfei0 = ip4_mfib_table_lookup(ip4_mfib_get(fib_index0),
                                              &ip0->src_address,
                                              &ip0->dst_address,
                                              64);
            }
            else
            {
                ASSERT(0);
            }

            vnet_buffer (p0)->ip.adj_index[VLIB_TX] = mfei0;
	}

        vlib_put_next_frame(vm, node,
                            MFIB_FORWARD_LOOKUP_NEXT_RPF,
                            n_left_to_next);
    }

    if (node->flags & VLIB_NODE_FLAG_TRACE)
        mfib_forward_lookup_trace(vm, node, frame);

    return frame->n_vectors;
}

static uword
ip4_mfib_forward_lookup (vlib_main_t * vm,
                         vlib_node_runtime_t * node,
                         vlib_frame_t * frame)
{
    return (mfib_forward_lookup (vm, node, frame, 1));
}

VLIB_REGISTER_NODE (ip4_mfib_forward_lookup_node, static) = {
    .function = ip4_mfib_forward_lookup,
    .name = "ip4-mfib-forward-lookup",
    .vector_size = sizeof (u32),

    .format_trace = format_mfib_forward_lookup_trace,

    .n_next_nodes = MFIB_FORWARD_LOOKUP_N_NEXT,
    .next_nodes = {
        [MFIB_FORWARD_LOOKUP_NEXT_RPF] = "ip4-mfib-forward-rpf",
    },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_mfib_forward_lookup_node,
                              ip4_mfib_forward_lookup)


typedef struct mfib_forward_rpf_trace_t_ {
    u32 entry_index;
    u32 sw_if_index;
    mfib_itf_flags_t itf_flags;
} mfib_forward_rpf_trace_t;

typedef enum mfib_forward_rpf_next_t_ {
    MFIB_FORWARD_RPF_NEXT_DROP,
    MFIB_FORWARD_RPF_NEXT_INTERNAL_COPY,
    MFIB_FORWARD_RPF_NEXT_RECEIVE,
    MFIB_FORWARD_RPF_N_NEXT,
} mfib_forward_rpf_next_t;

static u8 *
format_mfib_forward_rpf_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    mfib_forward_rpf_trace_t * t = va_arg (*args, mfib_forward_rpf_trace_t *);

    s = format (s, "entry %d", t->entry_index);
    s = format (s, " %d", t->sw_if_index);
    s = format (s, " %U", format_mfib_itf_flags, t->itf_flags);

    return s;
}

static int
mfib_forward_connected_check (vlib_buffer_t * b0,
                              int is_v4)
{
    ASSERT(0);
    return (0);
}

static void
mfib_forward_itf_signal (mfib_itf_t *mfi)
{
    ASSERT(0);
}

always_inline uword
mfib_forward_rpf (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame,
                  int is_v4)
{
    u32 n_left_from, n_left_to_next, * from, * to_next;
    mfib_forward_rpf_next_t next;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next = MFIB_FORWARD_RPF_NEXT_DROP;

    while (n_left_from > 0)
    {
        vlib_get_next_frame (vm, node, next,
                             to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
	{
            fib_node_index_t mfei0;
            const mfib_entry_t *mfe0;
            mfib_itf_t *mfi0;
            vlib_buffer_t * b0;
            u32 pi0, next0;
            mfib_itf_flags_t iflags0;
            mfib_entry_flags_t eflags0;

            pi0 = from[0];
            to_next[0] = pi0;
            from += 1;
            to_next += 1;
            n_left_to_next -= 1;
            n_left_from -= 1;

            b0 = vlib_get_buffer (vm, pi0);
            mfei0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
            mfe0 = mfib_entry_get(mfei0);
            mfi0 = mfib_entry_get_itf(mfe0,
                                      vnet_buffer(b0)->sw_if_index[VLIB_RX]);

            /*
             * throughout this function we are 'PREDICT' optimising
             * for the case of throughput traffic that is not replicated
             * to the host stack nor sets local flags
             */
            if (PREDICT_TRUE(NULL != mfi0))
            {
                iflags0 = mfi0->mfi_flags;
            }
            else
            {
                iflags0 = MFIB_ITF_FLAG_NONE;
            }
            eflags0 = mfe0->mfe_flags;

            if (PREDICT_FALSE(eflags0 != MFIB_ENTRY_FLAG_NONE))
            {
                if (PREDICT_FALSE(eflags0 & MFIB_ENTRY_FLAG_CONNECTED))
                {
                    /*
                     * lookup the source in the unicast FIB - check it
                     * matches a connected.
                     */
                    if (mfib_forward_connected_check(b0, is_v4))
                    {
                        mfib_forward_itf_signal(mfi0);
                    }
                }
                if (PREDICT_FALSE(eflags0 & MFIB_ENTRY_FLAG_SIGNAL))
                {
                    mfib_forward_itf_signal(mfi0);
                }
            }

            if (PREDICT_TRUE((iflags0 & MFIB_ITF_FLAG_ACCEPT)))
            {
                /*
                 * This interface is accepting packets for the matching entry
                 */
                if (PREDICT_FALSE(iflags0 & MFIB_ITF_FLAG_INTERNAL_COPY))
                {
                    /*
                     * A copy is required for the host stack
                     */
                    next0 = MFIB_FORWARD_RPF_NEXT_INTERNAL_COPY;
                }
                else
                {
                    next0 = mfe0->mfe_rep.dpoi_next_node;
                }

                vnet_buffer(b0)->ip.adj_index[VLIB_TX] =
                    mfe0->mfe_rep.dpoi_index;
            }
            else
            {
                if (PREDICT_FALSE(iflags0 & MFIB_ITF_FLAG_INTERNAL_COPY))
                {
                    /*
                     * A copy is required for the host stack
                     */
                    next0 = MFIB_FORWARD_RPF_NEXT_INTERNAL_COPY;
                }
                else
                {
                    next0 = MFIB_FORWARD_RPF_NEXT_DROP;                
                }
            }

            if (b0->flags & VLIB_BUFFER_IS_TRACED)
            {
                mfib_forward_rpf_trace_t *t0;

                t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
                t0->entry_index = mfei0;
                if (NULL == mfi0)
                {
                    t0->sw_if_index = ~0;
                    t0->itf_flags = MFIB_ITF_FLAG_NONE;
                }
                else
                {
                    t0->sw_if_index = mfi0->mfi_sw_if_index;
                    t0->itf_flags = mfi0->mfi_flags;
                }
            }
	    vlib_validate_buffer_enqueue_x1 (vm, node, next,
					     to_next, n_left_to_next,
					     pi0, next0);
	}

        vlib_put_next_frame(vm, node, next, n_left_to_next);
    }

    return frame->n_vectors;
}

static uword
ip4_mfib_forward_rpf (vlib_main_t * vm,
                      vlib_node_runtime_t * node,
                      vlib_frame_t * frame)
{
    return (mfib_forward_rpf(vm, node, frame, 1));
}


VLIB_REGISTER_NODE (ip4_mfib_forward_rpf_node, static) = {
    .function = ip4_mfib_forward_rpf,
    .name = "ip4-mfib-forward-rpf",
    .vector_size = sizeof (u32),

    .format_trace = format_mfib_forward_rpf_trace,

    .n_next_nodes = MFIB_FORWARD_RPF_N_NEXT,
    .next_nodes = {
        [MFIB_FORWARD_RPF_NEXT_DROP] = "error-drop",
        [MFIB_FORWARD_RPF_NEXT_INTERNAL_COPY] =
            "ip4-mfib-forward-internal-copy",
        [MFIB_FORWARD_RPF_NEXT_RECEIVE] = "ip4-local",
    },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_mfib_forward_rpf_node,
                              ip4_mfib_forward_rpf)


typedef struct mfib_forward_internal_copy_trace_t_ {
    int unused;
} mfib_forward_internal_copy_trace_t;

static u8 *
format_mfib_forward_internal_copy_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    CLIB_UNUSED (mfib_forward_internal_copy_trace_t * t) =
        va_arg (*args, mfib_forward_internal_copy_trace_t *);

    return s;
}

static uword
ip4_mfib_forward_internal_copy (vlib_main_t * vm,
                                vlib_node_runtime_t * node,
                                vlib_frame_t * frame)
{
    u32 n_left_from, * from, * to_next, next_index;
    u32 * to_us_next = 0;
    vlib_frame_t * to_us_frame = 0;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;
  
    to_us_frame = vlib_get_frame_to_node (vm, ip4_local_node.index);
    to_us_next = vlib_frame_vector_args (to_us_frame);

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame (vm, node, next_index,
                             to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
	{
            vlib_buffer_t * b0, *c0;
            u32 next0, ci0, bi0;
            fib_node_index_t mfei0;
            const mfib_entry_t *mfe0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);

            mfei0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
            mfe0 = mfib_entry_get(mfei0);

            /* Make a for us copy */
            c0 = vlib_buffer_copy(vm, b0);
            ci0 = vlib_get_buffer_index(vm, c0);

            next0 = mfe0->mfe_rep.dpoi_next_node;

            to_us_next[0] = ci0;
            to_us_next++;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                mfib_forward_internal_copy_trace_t *t =
                    vlib_add_trace (vm, node, b0, sizeof (*t));
                t->unused = 0;
            }
            
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi0, next0);
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    to_us_frame->n_vectors = frame->n_vectors;
    vlib_put_frame_to_node (vm, ip4_lookup_node.index, to_us_frame);

    return frame->n_vectors;
}


VLIB_REGISTER_NODE (ip4_mfib_forward_internal_copy_node, static) = {
    .function = ip4_mfib_forward_internal_copy,
    .name = "ip4-mfib-forward-internal-copy",
    .vector_size = sizeof (u32),

    .format_trace = format_mfib_forward_internal_copy_trace,
    .sibling_of = "ip4-mfib-forward-rpf"
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_mfib_forward_internal_copy_node,
                              ip4_mfib_forward_internal_copy)
