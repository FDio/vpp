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
#include <vnet/dpo/mpls_label_dpo.h>
#include <vnet/mpls/mpls.h>

/*
 * pool of all MPLS Label DPOs
 */
mpls_label_dpo_t *mpls_label_dpo_pool;

static mpls_label_dpo_t *
mpls_label_dpo_alloc (void)
{
    mpls_label_dpo_t *mld;

    pool_get_aligned(mpls_label_dpo_pool, mld, CLIB_CACHE_LINE_BYTES);
    memset(mld, 0, sizeof(*mld));

    dpo_reset(&mld->mld_dpo);

    return (mld);
}

static index_t
mpls_label_dpo_get_index (mpls_label_dpo_t *mld)
{
    return (mld - mpls_label_dpo_pool);
}

index_t
mpls_label_dpo_create (mpls_label_t *label_stack,
                       mpls_eos_bit_t eos,
                       u8 ttl,
                       u8 exp,
                       dpo_proto_t payload_proto,
		       const dpo_id_t *dpo)
{
    mpls_label_dpo_t *mld;
    u32 ii;

    mld = mpls_label_dpo_alloc();
    mld->mld_n_labels = vec_len(label_stack);
    mld->mld_n_hdr_bytes = mld->mld_n_labels * sizeof(mld->mld_hdr[0]);
    mld->mld_payload_proto = payload_proto;

    /*
     * construct label rewrite headers for each value value passed.
     * get the header in network byte order since we will paint it
     * on a packet in the data-plane
     */

    for (ii = 0; ii < mld->mld_n_labels-1; ii++)
    {
	vnet_mpls_uc_set_label(&mld->mld_hdr[ii].label_exp_s_ttl, label_stack[ii]);
	vnet_mpls_uc_set_ttl(&mld->mld_hdr[ii].label_exp_s_ttl, 255);
	vnet_mpls_uc_set_exp(&mld->mld_hdr[ii].label_exp_s_ttl, 0);
	vnet_mpls_uc_set_s(&mld->mld_hdr[ii].label_exp_s_ttl, MPLS_NON_EOS);
	mld->mld_hdr[ii].label_exp_s_ttl =
	    clib_host_to_net_u32(mld->mld_hdr[ii].label_exp_s_ttl);
    }

    /*
     * the inner most label
     */
    ii = mld->mld_n_labels-1;

    vnet_mpls_uc_set_label(&mld->mld_hdr[ii].label_exp_s_ttl, label_stack[ii]);
    vnet_mpls_uc_set_ttl(&mld->mld_hdr[ii].label_exp_s_ttl, ttl);
    vnet_mpls_uc_set_exp(&mld->mld_hdr[ii].label_exp_s_ttl, exp);
    vnet_mpls_uc_set_s(&mld->mld_hdr[ii].label_exp_s_ttl, eos);
    mld->mld_hdr[ii].label_exp_s_ttl =
	clib_host_to_net_u32(mld->mld_hdr[ii].label_exp_s_ttl);

    /*
     * stack this label objct on its parent.
     */
    dpo_stack(DPO_MPLS_LABEL,
              mld->mld_payload_proto,
              &mld->mld_dpo,
              dpo);

    return (mpls_label_dpo_get_index(mld));
}

u8*
format_mpls_label_dpo (u8 *s, va_list *args)
{
    index_t index = va_arg (*args, index_t);
    u32 indent = va_arg (*args, u32);
    mpls_unicast_header_t hdr;
    mpls_label_dpo_t *mld;
    u32 ii;

    s = format(s, "mpls-label:[%d]:", index);

    if (pool_is_free_index(mpls_label_dpo_pool, index))
    {
        /*
         * the packet trace can be printed after the DPO has been deleted
         */
        return (s);
    }

    mld = mpls_label_dpo_get(index);

    for (ii = 0; ii < mld->mld_n_labels; ii++)
    {
	hdr.label_exp_s_ttl =
	    clib_net_to_host_u32(mld->mld_hdr[ii].label_exp_s_ttl);
	s = format(s, "%U", format_mpls_header, hdr);
    }

    s = format(s, "\n%U", format_white_space, indent);
    s = format(s, "%U", format_dpo_id, &mld->mld_dpo, indent+2);

    return (s);
}

static void
mpls_label_dpo_lock (dpo_id_t *dpo)
{
    mpls_label_dpo_t *mld;

    mld = mpls_label_dpo_get(dpo->dpoi_index);

    mld->mld_locks++;
}

static void
mpls_label_dpo_unlock (dpo_id_t *dpo)
{
    mpls_label_dpo_t *mld;

    mld = mpls_label_dpo_get(dpo->dpoi_index);

    mld->mld_locks--;

    if (0 == mld->mld_locks)
    {
	dpo_reset(&mld->mld_dpo);
	pool_put(mpls_label_dpo_pool, mld);
    }
}

/**
 * @brief A struct to hold tracing information for the MPLS label imposition
 * node.
 */
typedef struct mpls_label_imposition_trace_t_
{
    /**
     * The MPLS header imposed
     */
    mpls_unicast_header_t hdr;
} mpls_label_imposition_trace_t;

always_inline mpls_unicast_header_t *
mpls_label_paint (vlib_buffer_t * b0,
                  mpls_label_dpo_t *mld0,
                  u8 ttl0)
{
    mpls_unicast_header_t *hdr0;

    vlib_buffer_advance(b0, -(mld0->mld_n_hdr_bytes));

    hdr0 = vlib_buffer_get_current(b0);

    if (1 == mld0->mld_n_labels)
    {
        /* optimise for the common case of one label */
        *hdr0 = mld0->mld_hdr[0];
    }
    else
    {
        clib_memcpy(hdr0, mld0->mld_hdr, mld0->mld_n_hdr_bytes);
        hdr0 = hdr0 + (mld0->mld_n_labels - 1);
    }
    /* fixup the TTL for the inner most label */
    ((char*)hdr0)[3] = ttl0;

    return (hdr0);
}

always_inline uword
mpls_label_imposition_inline (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * from_frame,
                              u8 payload_is_ip4,
                              u8 payload_is_ip6,
                              u8 payload_is_ethernet)
{
    u32 n_left_from, next_index, * from, * to_next;

    from = vlib_frame_vector_args (from_frame);
    n_left_from = from_frame->n_vectors;

    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from >= 8 && n_left_to_next >= 4)
        {
            u32 bi0, mldi0, bi1, mldi1, bi2, mldi2, bi3, mldi3;
            mpls_unicast_header_t *hdr0, *hdr1, *hdr2, *hdr3;
            mpls_label_dpo_t *mld0, *mld1, *mld2, *mld3;
            vlib_buffer_t * b0, *b1, * b2, *b3;
            u32 next0, next1, next2, next3;
            u8 ttl0, ttl1,ttl2, ttl3 ;

            bi0 = to_next[0] = from[0];
            bi1 = to_next[1] = from[1];
            bi2 = to_next[2] = from[2];
            bi3 = to_next[3] = from[3];

            /* Prefetch next iteration. */
            {
                vlib_buffer_t * p2, * p3, *p4, *p5;

                p2 = vlib_get_buffer (vm, from[2]);
                p3 = vlib_get_buffer (vm, from[3]);
                p4 = vlib_get_buffer (vm, from[4]);
                p5 = vlib_get_buffer (vm, from[5]);

                vlib_prefetch_buffer_header (p2, STORE);
                vlib_prefetch_buffer_header (p3, STORE);
                vlib_prefetch_buffer_header (p4, STORE);
                vlib_prefetch_buffer_header (p5, STORE);

                CLIB_PREFETCH (p2->data, sizeof (hdr0[0]), STORE);
                CLIB_PREFETCH (p3->data, sizeof (hdr0[0]), STORE);
                CLIB_PREFETCH (p4->data, sizeof (hdr0[0]), STORE);
                CLIB_PREFETCH (p5->data, sizeof (hdr0[0]), STORE);
            }

            from += 4;
            to_next += 4;
            n_left_from -= 4;
            n_left_to_next -= 4;

            b0 = vlib_get_buffer (vm, bi0);
            b1 = vlib_get_buffer (vm, bi1);
            b2 = vlib_get_buffer (vm, bi2);
            b3 = vlib_get_buffer (vm, bi3);

            /* dst lookup was done by ip4 lookup */
            mldi0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
            mldi1 = vnet_buffer(b1)->ip.adj_index[VLIB_TX];
            mldi2 = vnet_buffer(b2)->ip.adj_index[VLIB_TX];
            mldi3 = vnet_buffer(b3)->ip.adj_index[VLIB_TX];
            mld0 = mpls_label_dpo_get(mldi0);
            mld1 = mpls_label_dpo_get(mldi1);
            mld2 = mpls_label_dpo_get(mldi2);
            mld3 = mpls_label_dpo_get(mldi3);

            if (payload_is_ip4)
            {
                /*
                 * decrement the TTL on ingress to the LSP
                 */
                ip4_header_t * ip0 = vlib_buffer_get_current(b0);
                ip4_header_t * ip1 = vlib_buffer_get_current(b1);
                ip4_header_t * ip2 = vlib_buffer_get_current(b2);
                ip4_header_t * ip3 = vlib_buffer_get_current(b3);
                u32 checksum0;
                u32 checksum1;
                u32 checksum2;
                u32 checksum3;

                checksum0 = ip0->checksum + clib_host_to_net_u16 (0x0100);
                checksum1 = ip1->checksum + clib_host_to_net_u16 (0x0100);
                checksum2 = ip2->checksum + clib_host_to_net_u16 (0x0100);
                checksum3 = ip3->checksum + clib_host_to_net_u16 (0x0100);

                checksum0 += checksum0 >= 0xffff;
                checksum1 += checksum1 >= 0xffff;
                checksum2 += checksum2 >= 0xffff;
                checksum3 += checksum3 >= 0xffff;

                ip0->checksum = checksum0;
                ip1->checksum = checksum1;
                ip2->checksum = checksum2;
                ip3->checksum = checksum3;

                ip0->ttl -= 1;
                ip1->ttl -= 1;
                ip2->ttl -= 1;
                ip3->ttl -= 1;

                ttl1 = ip1->ttl;
                ttl0 = ip0->ttl;
                ttl3 = ip3->ttl;
                ttl2 = ip2->ttl;
            }
            else if (payload_is_ip6)
            {
                /*
                 * decrement the TTL on ingress to the LSP
                 */
                ip6_header_t * ip0 = vlib_buffer_get_current(b0);
                ip6_header_t * ip1 = vlib_buffer_get_current(b1);
                ip6_header_t * ip2 = vlib_buffer_get_current(b2);
                ip6_header_t * ip3 = vlib_buffer_get_current(b3);

                ip0->hop_limit -= 1;
                ip1->hop_limit -= 1;
                ip2->hop_limit -= 1;
                ip3->hop_limit -= 1;

                ttl0 = ip0->hop_limit;
                ttl1 = ip1->hop_limit;
                ttl2 = ip2->hop_limit;
                ttl3 = ip3->hop_limit;
            }
            else if (payload_is_ethernet)
            {
                /*
                 * nothing to chang ein the ethernet header
                 */
                ttl0 = ttl1 = ttl2 = ttl3 = 255;
            }
            else
            {
                /*
                 * else, the packet to be encapped is an MPLS packet
                 */
                if (PREDICT_TRUE(vnet_buffer(b0)->mpls.first))
                {
                    /*
                     * The first label to be imposed on the packet. this is a label swap.
                     * in which case we stashed the TTL and EXP bits in the
                     * packet in the lookup node
                     */
                    ASSERT(0 != vnet_buffer (b0)->mpls.ttl);

                    ttl0 = vnet_buffer(b0)->mpls.ttl - 1;
                }
                else
                {
                    /*
                     * not the first label. implying we are recusring down a chain of
                     * output labels.
                     * Each layer is considered a new LSP - hence the TTL is reset.
                     */
                    ttl0 = 255;
                }
                if (PREDICT_TRUE(vnet_buffer(b1)->mpls.first))
                {
                    ASSERT(1 != vnet_buffer (b1)->mpls.ttl);
                    ttl1 = vnet_buffer(b1)->mpls.ttl - 1;
                }
                else
                {
                    ttl1 = 255;
                }
                if (PREDICT_TRUE(vnet_buffer(b2)->mpls.first))
                {
                    ASSERT(1 != vnet_buffer (b2)->mpls.ttl);

                    ttl2 = vnet_buffer(b2)->mpls.ttl - 1;
                }
                else
                {
                    ttl2 = 255;
                }
                if (PREDICT_TRUE(vnet_buffer(b3)->mpls.first))
                {
                    ASSERT(1 != vnet_buffer (b3)->mpls.ttl);
                    ttl3 = vnet_buffer(b3)->mpls.ttl - 1;
                }
                else
                {
                    ttl3 = 255;
                }
            }
            vnet_buffer(b0)->mpls.first = 0;
            vnet_buffer(b1)->mpls.first = 0;
            vnet_buffer(b2)->mpls.first = 0;
            vnet_buffer(b3)->mpls.first = 0;

            /* Paint the MPLS header */
            hdr0 = mpls_label_paint(b0, mld0, ttl0);
            hdr1 = mpls_label_paint(b1, mld1, ttl1);
            hdr2 = mpls_label_paint(b2, mld2, ttl2);
            hdr3 = mpls_label_paint(b3, mld3, ttl3);

            next0 = mld0->mld_dpo.dpoi_next_node;
            next1 = mld1->mld_dpo.dpoi_next_node;
            next2 = mld2->mld_dpo.dpoi_next_node;
            next3 = mld3->mld_dpo.dpoi_next_node;
            vnet_buffer(b0)->ip.adj_index[VLIB_TX] = mld0->mld_dpo.dpoi_index;
            vnet_buffer(b1)->ip.adj_index[VLIB_TX] = mld1->mld_dpo.dpoi_index;
            vnet_buffer(b2)->ip.adj_index[VLIB_TX] = mld2->mld_dpo.dpoi_index;
            vnet_buffer(b3)->ip.adj_index[VLIB_TX] = mld3->mld_dpo.dpoi_index;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                mpls_label_imposition_trace_t *tr =
                    vlib_add_trace (vm, node, b0, sizeof (*tr));
                tr->hdr = *hdr0;
            }
            if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
                mpls_label_imposition_trace_t *tr =
                    vlib_add_trace (vm, node, b1, sizeof (*tr));
                tr->hdr = *hdr1;
            }
            if (PREDICT_FALSE(b2->flags & VLIB_BUFFER_IS_TRACED))
            {
                mpls_label_imposition_trace_t *tr =
                    vlib_add_trace (vm, node, b2, sizeof (*tr));
                tr->hdr = *hdr2;
            }
            if (PREDICT_FALSE(b3->flags & VLIB_BUFFER_IS_TRACED))
            {
                mpls_label_imposition_trace_t *tr =
                    vlib_add_trace (vm, node, b3, sizeof (*tr));
                tr->hdr = *hdr3;
            }

            vlib_validate_buffer_enqueue_x4(vm, node, next_index, to_next,
                                            n_left_to_next,
                                            bi0, bi1, bi2, bi3,
                                            next0, next1, next2, next3);
        }

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            mpls_unicast_header_t *hdr0;
            mpls_label_dpo_t *mld0;
            vlib_buffer_t * b0;
            u32 bi0, mldi0;
            u32 next0;
            u8 ttl;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);

            /* dst lookup was done by ip4 lookup */
            mldi0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
            mld0 = mpls_label_dpo_get(mldi0);

            if (payload_is_ip4)
            {
                /*
                 * decrement the TTL on ingress to the LSP
                 */
                ip4_header_t * ip0 = vlib_buffer_get_current(b0);
                u32 checksum0;

                checksum0 = ip0->checksum + clib_host_to_net_u16 (0x0100);
                checksum0 += checksum0 >= 0xffff;

                ip0->checksum = checksum0;
                ip0->ttl -= 1;
                ttl = ip0->ttl;
            }
            else if (payload_is_ip6)
            {
                /*
                 * decrement the TTL on ingress to the LSP
                 */
                ip6_header_t * ip0 = vlib_buffer_get_current(b0);

                ip0->hop_limit -= 1;
                ttl = ip0->hop_limit;
            }
            else
            {
                /*
                 * else, the packet to be encapped is an MPLS packet
                 */
                if (vnet_buffer(b0)->mpls.first)
                {
                    /*
                     * The first label to be imposed on the packet. this is a label swap.
                     * in which case we stashed the TTL and EXP bits in the
                     * packet in the lookup node
                     */
                    ASSERT(0 != vnet_buffer (b0)->mpls.ttl);

                    ttl = vnet_buffer(b0)->mpls.ttl - 1;
                }
                else
                {
                    /*
                     * not the first label. implying we are recusring down a chain of
                     * output labels.
                     * Each layer is considered a new LSP - hence the TTL is reset.
                     */
                    ttl = 255;
                }
            }
            vnet_buffer(b0)->mpls.first = 0;

            /* Paint the MPLS header */
            vlib_buffer_advance(b0, -(mld0->mld_n_hdr_bytes));
            hdr0 = vlib_buffer_get_current(b0);
            clib_memcpy(hdr0, mld0->mld_hdr, mld0->mld_n_hdr_bytes);

            /* fixup the TTL for the inner most label */
            hdr0 = hdr0 + (mld0->mld_n_labels - 1);
            ((char*)hdr0)[3] = ttl;

            next0 = mld0->mld_dpo.dpoi_next_node;
            vnet_buffer(b0)->ip.adj_index[VLIB_TX] = mld0->mld_dpo.dpoi_index;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                mpls_label_imposition_trace_t *tr =
                    vlib_add_trace (vm, node, b0, sizeof (*tr));
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
format_mpls_label_imposition_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    mpls_label_imposition_trace_t * t;
    mpls_unicast_header_t hdr;
    u32 indent;

    t = va_arg (*args, mpls_label_imposition_trace_t *);
    indent = format_get_indent (s);
    hdr.label_exp_s_ttl = clib_net_to_host_u32(t->hdr.label_exp_s_ttl);

    s = format (s, "%Umpls-header:%U",
                format_white_space, indent,
                format_mpls_header, hdr);
    return (s);
}

static uword
mpls_label_imposition (vlib_main_t * vm,
                       vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame, 0, 0, 0));
}

VLIB_REGISTER_NODE (mpls_label_imposition_node) = {
    .function = mpls_label_imposition,
    .name = "mpls-label-imposition",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "mpls-drop",
    }
};
VLIB_NODE_FUNCTION_MULTIARCH (mpls_label_imposition_node,
                              mpls_label_imposition)

static uword
ip4_mpls_label_imposition (vlib_main_t * vm,
                           vlib_node_runtime_t * node,
                           vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame, 1, 0, 0));
}

VLIB_REGISTER_NODE (ip4_mpls_label_imposition_node) = {
    .function = ip4_mpls_label_imposition,
    .name = "ip4-mpls-label-imposition",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "ip4-drop",
    }
};
VLIB_NODE_FUNCTION_MULTIARCH (ip4_mpls_label_imposition_node,
                              ip4_mpls_label_imposition)

static uword
ip6_mpls_label_imposition (vlib_main_t * vm,
                           vlib_node_runtime_t * node,
                           vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame, 0, 1, 0));
}

VLIB_REGISTER_NODE (ip6_mpls_label_imposition_node) = {
    .function = ip6_mpls_label_imposition,
    .name = "ip6-mpls-label-imposition",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "ip6-drop",
    }
};
VLIB_NODE_FUNCTION_MULTIARCH (ip6_mpls_label_imposition_node,
                              ip6_mpls_label_imposition)

static uword
ethernet_mpls_label_imposition (vlib_main_t * vm,
                                vlib_node_runtime_t * node,
                                vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame, 0, 0, 1));
}

VLIB_REGISTER_NODE (ethernet_mpls_label_imposition_node) = {
    .function = ethernet_mpls_label_imposition,
    .name = "ethernet-mpls-label-imposition",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "error-drop",
    }
};
VLIB_NODE_FUNCTION_MULTIARCH (ethernet_mpls_label_imposition_node,
                              ethernet_mpls_label_imposition)

static void
mpls_label_dpo_mem_show (void)
{
    fib_show_memory_usage("MPLS label",
			  pool_elts(mpls_label_dpo_pool),
			  pool_len(mpls_label_dpo_pool),
			  sizeof(mpls_label_dpo_t));
}

const static dpo_vft_t mld_vft = {
    .dv_lock = mpls_label_dpo_lock,
    .dv_unlock = mpls_label_dpo_unlock,
    .dv_format = format_mpls_label_dpo,
    .dv_mem_show = mpls_label_dpo_mem_show,
};

const static char* const mpls_label_imp_ip4_nodes[] =
{
    "ip4-mpls-label-imposition",
    NULL,
};
const static char* const mpls_label_imp_ip6_nodes[] =
{
    "ip6-mpls-label-imposition",
    NULL,
};
const static char* const mpls_label_imp_mpls_nodes[] =
{
    "mpls-label-imposition",
    NULL,
};
const static char* const mpls_label_imp_ethernet_nodes[] =
{
    "ethernet-mpls-label-imposition",
    NULL,
};

const static char* const * const mpls_label_imp_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = mpls_label_imp_ip4_nodes,
    [DPO_PROTO_IP6]  = mpls_label_imp_ip6_nodes,
    [DPO_PROTO_MPLS] = mpls_label_imp_mpls_nodes,
    [DPO_PROTO_ETHERNET] = mpls_label_imp_ethernet_nodes,
};


void
mpls_label_dpo_module_init (void)
{
    dpo_register(DPO_MPLS_LABEL, &mld_vft, mpls_label_imp_nodes);
}
