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
#include <vnet/mfib/mfib_signal.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>

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
static void
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
            t0->entry_index = vnet_buffer (b0)->ip.adj_index;
            t0->fib_index = vec_elt (im->mfib_index_by_sw_if_index,
                                     vnet_buffer(b1)->sw_if_index[VLIB_RX]);
        }
        if (b1->flags & VLIB_BUFFER_IS_TRACED)
        {
            t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
            t1->entry_index = vnet_buffer (b1)->ip.adj_index;
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
            t0->entry_index = vnet_buffer (b0)->ip.adj_index;
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
                ip4_header_t * ip0;

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
                ip6_header_t * ip0;

                fib_index0 = vec_elt (ip6_main.mfib_index_by_sw_if_index,
                                      vnet_buffer(p0)->sw_if_index[VLIB_RX]);
                ip0 = vlib_buffer_get_current (p0);
                mfei0 = ip6_mfib_table_fwd_lookup(ip6_mfib_get(fib_index0),
                                                  &ip0->src_address,
                                                  &ip0->dst_address);
            }

            vnet_buffer (p0)->ip.adj_index = mfei0;
        }

        vlib_put_next_frame(vm, node,
                            MFIB_FORWARD_LOOKUP_NEXT_RPF,
                            n_left_to_next);
    }

    if (node->flags & VLIB_NODE_FLAG_TRACE)
        mfib_forward_lookup_trace(vm, node, frame);

    return frame->n_vectors;
}

VLIB_NODE_FN (ip4_mfib_forward_lookup_node) (vlib_main_t * vm,
                         vlib_node_runtime_t * node,
                         vlib_frame_t * frame)
{
    return (mfib_forward_lookup (vm, node, frame, 1));
}

VLIB_REGISTER_NODE (ip4_mfib_forward_lookup_node) = {
    .name = "ip4-mfib-forward-lookup",
    .vector_size = sizeof (u32),

    .format_trace = format_mfib_forward_lookup_trace,

    .n_next_nodes = MFIB_FORWARD_LOOKUP_N_NEXT,
    .next_nodes = {
        [MFIB_FORWARD_LOOKUP_NEXT_RPF] = "ip4-mfib-forward-rpf",
    },
};

VLIB_NODE_FN (ip6_mfib_forward_lookup_node) (vlib_main_t * vm,
                         vlib_node_runtime_t * node,
                         vlib_frame_t * frame)
{
    return (mfib_forward_lookup (vm, node, frame, 0));
}

VLIB_REGISTER_NODE (ip6_mfib_forward_lookup_node) = {
    .name = "ip6-mfib-forward-lookup",
    .vector_size = sizeof (u32),

    .format_trace = format_mfib_forward_lookup_trace,

    .n_next_nodes = MFIB_FORWARD_LOOKUP_N_NEXT,
    .next_nodes = {
        [MFIB_FORWARD_LOOKUP_NEXT_RPF] = "ip6-mfib-forward-rpf",
    },
};


typedef struct mfib_forward_rpf_trace_t_ {
    u32 entry_index;
    u32 sw_if_index;
    mfib_itf_flags_t itf_flags;
} mfib_forward_rpf_trace_t;

typedef enum mfib_forward_rpf_next_t_ {
    MFIB_FORWARD_RPF_NEXT_DROP,
    MFIB_FORWARD_RPF_N_NEXT,
} mfib_forward_rpf_next_t;

static u8 *
format_mfib_forward_rpf_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    mfib_forward_rpf_trace_t * t = va_arg (*args, mfib_forward_rpf_trace_t *);

    s = format (s, "entry %d", t->entry_index);
    s = format (s, " itf %d", t->sw_if_index);
    s = format (s, " flags %U", format_mfib_itf_flags, t->itf_flags);

    return s;
}

static int
mfib_forward_connected_check (vlib_buffer_t * b0,
                              u32 sw_if_index,
                              int is_v4)
{
    /*
     * Lookup the source of the IP packet in the
     * FIB. return true if the entry is attached.
     */
    index_t lbi0;

    if (is_v4)
    {
        load_balance_t *lb0;
        ip4_header_t *ip0;

        ip0 = vlib_buffer_get_current(b0);

        lbi0 = ip4_fib_forwarding_lookup(
                   ip4_fib_table_get_index_for_sw_if_index(
                       sw_if_index),
                   &ip0->src_address);
        lb0 = load_balance_get(lbi0);

        return (FIB_ENTRY_FLAG_ATTACHED &
                lb0->lb_fib_entry_flags);
    }
    else
    {
        ASSERT(0);
    }
    return (0);
}

static void
mfib_forward_itf_signal (vlib_main_t *vm,
                         const mfib_entry_t *mfe,
                         mfib_itf_t *mfi,
                         vlib_buffer_t *b0)
{
    mfib_itf_flags_t old_flags;

    old_flags = clib_atomic_fetch_or(&mfi->mfi_flags,
				     MFIB_ITF_FLAG_SIGNAL_PRESENT);

    if (!(old_flags & MFIB_ITF_FLAG_SIGNAL_PRESENT))
    {
        /*
         * we were the lucky ones to set the signal present flag
         */
        if (!(old_flags & MFIB_ITF_FLAG_DONT_PRESERVE))
        {
            /*
             * preserve a copy of the packet for the control
             * plane to examine.
             * Only allow one preserved packet at at time, since
             * when the signal present flag is cleared so is the
             * preserved packet.
             */
            mfib_signal_push(mfe, mfi, b0);
        }
        else
        {
            /*
             *  The control plane just wants the signal, not the packet as well
             */
            mfib_signal_push(mfe, mfi, NULL);
        }
    }
    /*
     * else
     *   there is already a signal present on this interface that the
     *   control plane has not yet acknowledged
     */
}

always_inline uword
mfib_forward_rpf (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame,
                  int is_v4)
{
    u32 n_left_from, n_left_to_next, * from, * to_next;
    mfib_forward_rpf_next_t next;
    vlib_node_runtime_t *error_node;

    if (is_v4)
        error_node = vlib_node_get_runtime (vm, ip4_input_node.index);
    else
        error_node = vlib_node_get_runtime (vm, ip6_input_node.index);
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
            u8 error0;

            pi0 = from[0];
            to_next[0] = pi0;
            from += 1;
            to_next += 1;
            n_left_to_next -= 1;
            n_left_from -= 1;

            error0 = IP4_ERROR_NONE;
            b0 = vlib_get_buffer (vm, pi0);
            mfei0 = vnet_buffer (b0)->ip.adj_index;
            mfe0 = mfib_entry_get(mfei0);
            mfi0 = mfib_entry_get_itf(mfe0,
                                      vnet_buffer(b0)->sw_if_index[VLIB_RX]);

            /*
             * throughout this function we are 'PREDICT' optimising
             * for the case of throughput traffic that is not replicated
             * to the host stack nor sets local flags
             */

            /*
             * If the mfib entry has a configured RPF-ID check that
             * in preference to an interface based RPF
             */
            if (MFIB_RPF_ID_NONE != mfe0->mfe_rpf_id)
            {
                iflags0 = (mfe0->mfe_rpf_id == vnet_buffer(b0)->ip.rpf_id ?
                           MFIB_ITF_FLAG_ACCEPT :
                           MFIB_ITF_FLAG_NONE);
            }
            else
            {
                if (PREDICT_TRUE(NULL != mfi0))
                {
                    iflags0 = mfi0->mfi_flags;
                }
                else
                {
                    iflags0 = MFIB_ITF_FLAG_NONE;
                }
            }
            eflags0 = mfe0->mfe_flags;

            if (PREDICT_FALSE(eflags0 & MFIB_ENTRY_FLAG_CONNECTED))
            {
                /*
                 * lookup the source in the unicast FIB - check it
                 * matches a connected.
                 */
                if (mfib_forward_connected_check(
                        b0,
                        vnet_buffer(b0)->sw_if_index[VLIB_RX],
                        is_v4))
                {
                    mfib_forward_itf_signal(vm, mfe0, mfi0, b0);
                }
            }
            if (PREDICT_FALSE((eflags0 & MFIB_ENTRY_FLAG_SIGNAL) ^
                              (iflags0 & MFIB_ITF_FLAG_NEGATE_SIGNAL)))
            {
                /*
                 * Entry signal XOR interface negate-signal
                 */
                if (NULL != mfi0)
                {
                    mfib_forward_itf_signal(vm, mfe0, mfi0, b0);
                }
            }

            if (PREDICT_TRUE((iflags0 & MFIB_ITF_FLAG_ACCEPT) ||
                             (eflags0 & MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF)))
            {
                /*
                 * This interface is accepting packets for the matching entry
                 */
                next0 = mfe0->mfe_rep.dpoi_next_node;

                vnet_buffer(b0)->ip.adj_index =
                    mfe0->mfe_rep.dpoi_index;
            }
            else
            {
                next0 = MFIB_FORWARD_RPF_NEXT_DROP;
                error0 = IP4_ERROR_RPF_FAILURE;
            }

            b0->error = error0 ? error_node->errors[error0] : 0;

            if (b0->flags & VLIB_BUFFER_IS_TRACED)
            {
                mfib_forward_rpf_trace_t *t0;

                t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
                t0->entry_index = mfei0;
                t0->itf_flags = iflags0;
                if (NULL == mfi0)
                {
                    t0->sw_if_index = ~0;
                }
                else
                {
                    t0->sw_if_index = mfi0->mfi_sw_if_index;
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

VLIB_NODE_FN (ip4_mfib_forward_rpf_node) (vlib_main_t * vm,
                      vlib_node_runtime_t * node,
                      vlib_frame_t * frame)
{
    return (mfib_forward_rpf(vm, node, frame, 1));
}


VLIB_REGISTER_NODE (ip4_mfib_forward_rpf_node) = {
    .name = "ip4-mfib-forward-rpf",
    .vector_size = sizeof (u32),

    .format_trace = format_mfib_forward_rpf_trace,

    .n_next_nodes = MFIB_FORWARD_RPF_N_NEXT,
    .next_nodes = {
        [MFIB_FORWARD_RPF_NEXT_DROP] = "ip4-drop",
    },
};

VLIB_NODE_FN (ip6_mfib_forward_rpf_node) (vlib_main_t * vm,
                      vlib_node_runtime_t * node,
                      vlib_frame_t * frame)
{
    return (mfib_forward_rpf(vm, node, frame, 0));
}


VLIB_REGISTER_NODE (ip6_mfib_forward_rpf_node) = {
    .name = "ip6-mfib-forward-rpf",
    .vector_size = sizeof (u32),

    .format_trace = format_mfib_forward_rpf_trace,

    .n_next_nodes = MFIB_FORWARD_RPF_N_NEXT,
    .next_nodes = {
        [MFIB_FORWARD_RPF_NEXT_DROP] = "ip6-drop",
    },
};

