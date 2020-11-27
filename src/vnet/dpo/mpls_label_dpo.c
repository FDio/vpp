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
#include <vnet/dpo/drop_dpo.h>

#ifndef CLIB_MARCH_VARIANT
/*
 * pool of all MPLS Label DPOs
 */
mpls_label_dpo_t *mpls_label_dpo_pool;

/**
 * Strings for the flags
 */
const char* mpls_label_dpo_attr_names[] = MPLS_LABEL_DPO_ATTR_NAMES;

/**
 * registered DPO types for each of the label sub-types. And there's a
 * subtype for each of the flag combinations.
 */
static dpo_type_t mpls_label_dpo_types[1 << MPLS_LABEL_DPO_ATTR_MAX];

static mpls_label_dpo_t *
mpls_label_dpo_alloc (void)
{
    mpls_label_dpo_t *mld;
    vlib_main_t *vm;
    u8 did_barrier_sync;

    dpo_pool_barrier_sync (vm, mpls_label_dpo_pool, did_barrier_sync);
    pool_get_aligned(mpls_label_dpo_pool, mld, CLIB_CACHE_LINE_BYTES);
    dpo_pool_barrier_release (vm, did_barrier_sync);

    clib_memset(mld, 0, sizeof(*mld));

    dpo_reset(&mld->mld_dpo);

    return (mld);
}

static index_t
mpls_label_dpo_get_index (mpls_label_dpo_t *mld)
{
    return (mld - mpls_label_dpo_pool);
}

void
mpls_label_dpo_create (fib_mpls_label_t *label_stack,
                       mpls_eos_bit_t eos,
                       dpo_proto_t payload_proto,
                       mpls_label_dpo_flags_t flags,
		       const dpo_id_t *parent,
                       dpo_id_t *dpo)
{
    mpls_label_dpo_t *mld;
    dpo_type_t dtype;
    u32 ii;

    if ((DPO_PROTO_IP4 != payload_proto) &&
        (DPO_PROTO_IP6 != payload_proto))
    {
        /*
         * remove unsupported configuration
         */
        flags &= ~MPLS_LABEL_DPO_FLAG_NO_IP_TTL_DECR;
    }

    mld = mpls_label_dpo_alloc();
    mld->mld_flags = flags;
    dtype = mpls_label_dpo_types[flags];

    if (MPLS_LABEL_DPO_MAX_N_LABELS < vec_len(label_stack))
    {
        clib_warning("Label stack size exceeded");
        dpo_stack(dtype,
                  mld->mld_payload_proto,
                  &mld->mld_dpo,
                  drop_dpo_get(DPO_PROTO_MPLS));
    }
    else
    {
        mld->mld_n_labels = vec_len(label_stack);
        mld->mld_n_hdr_bytes = mld->mld_n_labels * sizeof(mld->mld_hdr[0]);
        mld->mld_payload_proto = payload_proto;

        /*
         * construct label rewrite headers for each value passed.
         * get the header in network byte order since we will paint it
         * on a packet in the data-plane
         */
        for (ii = 0; ii < mld->mld_n_labels-1; ii++)
        {
            vnet_mpls_uc_set_label(&mld->mld_hdr[ii].label_exp_s_ttl,
                                   label_stack[ii].fml_value);
            vnet_mpls_uc_set_exp(&mld->mld_hdr[ii].label_exp_s_ttl,
                                 label_stack[ii].fml_exp);
            vnet_mpls_uc_set_s(&mld->mld_hdr[ii].label_exp_s_ttl,
                               MPLS_NON_EOS);
            if (0 != label_stack[ii].fml_ttl)
            {
                vnet_mpls_uc_set_ttl(&mld->mld_hdr[ii].label_exp_s_ttl,
                                     label_stack[ii].fml_ttl);
            }
            else
            {
                vnet_mpls_uc_set_ttl(&mld->mld_hdr[ii].label_exp_s_ttl,
                                     MPLS_LABEL_DEFAULT_TTL);
            }
            mld->mld_hdr[ii].label_exp_s_ttl =
                clib_host_to_net_u32(mld->mld_hdr[ii].label_exp_s_ttl);
        }

        /*
         * the inner most label
         */
        ii = mld->mld_n_labels-1;

        vnet_mpls_uc_set_label(&mld->mld_hdr[ii].label_exp_s_ttl,
                               label_stack[ii].fml_value);
        vnet_mpls_uc_set_exp(&mld->mld_hdr[ii].label_exp_s_ttl,
                             label_stack[ii].fml_exp);
        vnet_mpls_uc_set_s(&mld->mld_hdr[ii].label_exp_s_ttl, eos);
        if (0 != label_stack[ii].fml_ttl)
        {
            vnet_mpls_uc_set_ttl(&mld->mld_hdr[ii].label_exp_s_ttl,
                                 label_stack[ii].fml_ttl);
        }
        else
        {
            vnet_mpls_uc_set_ttl(&mld->mld_hdr[ii].label_exp_s_ttl,
                                 MPLS_LABEL_DEFAULT_TTL);
        }
        mld->mld_hdr[ii].label_exp_s_ttl =
            clib_host_to_net_u32(mld->mld_hdr[ii].label_exp_s_ttl);

        /*
         * pipe/uniform mode is only supported for the bottom of stack label
         */
        if (FIB_MPLS_LSP_MODE_UNIFORM == label_stack[ii].fml_mode)
        {
            mld->mld_flags |= MPLS_LABEL_DPO_FLAG_UNIFORM_MODE;
        }
        else
        {
            mld->mld_flags &= ~MPLS_LABEL_DPO_FLAG_UNIFORM_MODE;
        }
        dtype = mpls_label_dpo_types[mld->mld_flags];

        /*
         * stack this label object on its parent.
         */
        dpo_stack(dtype,
                  mld->mld_payload_proto,
                  &mld->mld_dpo,
                  parent);
    }

    dpo_set(dpo,
            dtype,
            mld->mld_payload_proto,
            mpls_label_dpo_get_index(mld));
}

u8*
format_mpls_label_dpo_flags (u8 *s, va_list *args)
{
    mpls_label_dpo_flags_t flags = va_arg (*args, int);
    mpls_label_dpo_attr_t attr;

    FOR_EACH_MPLS_LABEL_DPO_ATTR(attr)
    {
        if ((1 << attr) & flags)
        {
            s = format(s, "%s,", mpls_label_dpo_attr_names[attr]);
        }
    }

    return (s);
}

u8*
format_mpls_label_dpo (u8 *s, va_list *args)
{
    index_t index = va_arg (*args, index_t);
    u32 indent = va_arg (*args, u32);
    mpls_unicast_header_t hdr;
    mpls_label_dpo_t *mld;
    u32 ii;

    if (pool_is_free_index(mpls_label_dpo_pool, index))
    {
        /*
         * the packet trace can be printed after the DPO has been deleted
         */
        return (format(s, "mpls-label[???,%d]:", index));
    }

    mld = mpls_label_dpo_get(index);
    s = format(s, "mpls-label[%U@%d]:",
               format_mpls_label_dpo_flags,
               (int) mld->mld_flags, index);

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
#endif /* CLIB_MARCH_VARIANT */

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

    /**
     * TTL imposed - only valid for uniform LSPs
     */
    u8 ttl;

    /**
     * TTL imposed - only valid for uniform LSPs
     */
    u8 exp;
} mpls_label_imposition_trace_t;

always_inline mpls_unicast_header_t *
mpls_label_paint (vlib_buffer_t * b0,
                  mpls_label_dpo_t *mld0)
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
        clib_memcpy_fast(hdr0, mld0->mld_hdr, mld0->mld_n_hdr_bytes);
        hdr0 = hdr0 + (mld0->mld_n_labels - 1);
    }

    return (hdr0);
}

/**
 * Paint on an MPLS label and fixup the TTL
 */
always_inline mpls_unicast_header_t *
mpls_label_paint_w_ttl (vlib_buffer_t * b0,
                        mpls_label_dpo_t *mld0,
                        u8 ttl0)
{
    mpls_unicast_header_t *hdr0;

    hdr0 = mpls_label_paint(b0, mld0);

    /* fixup the TTL for the inner most label */
    ((char*)hdr0)[3] = ttl0;

    return (hdr0);
}

/**
 * Paint on an MPLS label and fixup the TTL and EXP bits.
 */
always_inline mpls_unicast_header_t *
mpls_label_paint_w_ttl_exp (vlib_buffer_t * b0,
                            mpls_label_dpo_t *mld0,
                            u8 ttl0,
                            u8 exp0)
{
    mpls_unicast_header_t *hdr0;

    hdr0 = mpls_label_paint_w_ttl(b0, mld0, ttl0);

    /* fixup the EXP for the inner most label */
    ((char*)hdr0)[2] |= (exp0 << 1);

    return (hdr0);
}

/**
 * Paint on an MPLS label and fixup the TTL and EXP bits
 * When the EXP bits are *already* bit shift to the correct place in
 * in the 2nd byte (i.e. they were read from another label)
 */
always_inline mpls_unicast_header_t *
mpls_label_paint_w_ttl_mpls_exp (vlib_buffer_t * b0,
                                 mpls_label_dpo_t *mld0,
                                 u8 ttl0,
                                 u8 exp0)
{
    mpls_unicast_header_t *hdr0;

    hdr0 = mpls_label_paint_w_ttl(b0, mld0, ttl0);

    /* fixup the EXP for the inner most label */
    ((char*)hdr0)[2] |= exp0;

    return (hdr0);
}

always_inline uword
mpls_label_imposition_inline (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * from_frame,
                              const dpo_proto_t dproto,
                              const mpls_label_dpo_flags_t flags)
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
            u8 ttl0, ttl1, ttl2, ttl3;
            u8 exp0, exp1, exp2, exp3;

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
            mldi0 = vnet_buffer(b0)->ip.adj_index;
            mldi1 = vnet_buffer(b1)->ip.adj_index;
            mldi2 = vnet_buffer(b2)->ip.adj_index;
            mldi3 = vnet_buffer(b3)->ip.adj_index;
            mld0 = mpls_label_dpo_get(mldi0);
            mld1 = mpls_label_dpo_get(mldi1);
            mld2 = mpls_label_dpo_get(mldi2);
            mld3 = mpls_label_dpo_get(mldi3);

            if (DPO_PROTO_MPLS != dproto)
            {
                /*
                 * These are the non-MPLS payload imposition cases
                 */
                if (DPO_PROTO_IP4 == dproto)
                {
                    ip4_header_t * ip0 = vlib_buffer_get_current(b0);
                    ip4_header_t * ip1 = vlib_buffer_get_current(b1);
                    ip4_header_t * ip2 = vlib_buffer_get_current(b2);
                    ip4_header_t * ip3 = vlib_buffer_get_current(b3);

                    if (!(MPLS_LABEL_DPO_FLAG_NO_IP_TTL_DECR & flags))
                    {
                        /*
                         * decrement the TTL on ingress to the LSP
                         */
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
                    }

                    if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                    {
                        ttl1 = ip1->ttl;
                        ttl0 = ip0->ttl;
                        ttl3 = ip3->ttl;
                        ttl2 = ip2->ttl;
                        /* by default copy the 3 most significant bits */
                        exp0 = ip_dscp_to_mpls_exp(ip0->tos);
                        exp1 = ip_dscp_to_mpls_exp(ip1->tos);
                        exp2 = ip_dscp_to_mpls_exp(ip2->tos);
                        exp3 = ip_dscp_to_mpls_exp(ip3->tos);
                    }

                    /* save the payload proto information in mpls opaque */
                    vnet_buffer(b0)->mpls.pyld_proto = DPO_PROTO_IP4;
                    vnet_buffer(b1)->mpls.pyld_proto = DPO_PROTO_IP4;
                    vnet_buffer(b2)->mpls.pyld_proto = DPO_PROTO_IP4;
                    vnet_buffer(b3)->mpls.pyld_proto = DPO_PROTO_IP4;
                }
                else if (DPO_PROTO_IP6 == dproto)
                {
                    /*
                     * decrement the TTL on ingress to the LSP
                     */
                    ip6_header_t * ip0 = vlib_buffer_get_current(b0);
                    ip6_header_t * ip1 = vlib_buffer_get_current(b1);
                    ip6_header_t * ip2 = vlib_buffer_get_current(b2);
                    ip6_header_t * ip3 = vlib_buffer_get_current(b3);

                    if (!(MPLS_LABEL_DPO_FLAG_NO_IP_TTL_DECR & flags))
                    {
                        ip0->hop_limit -= 1;
                        ip1->hop_limit -= 1;
                        ip2->hop_limit -= 1;
                        ip3->hop_limit -= 1;
                    }
                    if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                    {
                        ttl0 = ip0->hop_limit;
                        ttl1 = ip1->hop_limit;
                        ttl2 = ip2->hop_limit;
                        ttl3 = ip3->hop_limit;
                        /* by default copy the 3 most significant bits */
                        exp0 = ip_dscp_to_mpls_exp(
                            ip6_traffic_class_network_order(ip0));
                        exp1 = ip_dscp_to_mpls_exp(
                            ip6_traffic_class_network_order(ip1));
                        exp2 = ip_dscp_to_mpls_exp(
                            ip6_traffic_class_network_order(ip2));
                        exp3 = ip_dscp_to_mpls_exp(
                            ip6_traffic_class_network_order(ip3));
                    }

                    /* save the payload proto information in mpls opaque */
                    vnet_buffer(b0)->mpls.pyld_proto = DPO_PROTO_IP6;
                    vnet_buffer(b1)->mpls.pyld_proto = DPO_PROTO_IP6;
                    vnet_buffer(b2)->mpls.pyld_proto = DPO_PROTO_IP6;
                    vnet_buffer(b3)->mpls.pyld_proto = DPO_PROTO_IP6;
                }
                else
                {
                    /*
                     * nothing to change in the ethernet header
                     */
                    ttl0 = ttl1 = ttl2 = ttl3 = MPLS_LABEL_DEFAULT_TTL;
                    exp0 = exp1 = exp2 = exp3 = MPLS_LABEL_DEFAULT_EXP;
                }
                /*
                 * These are the non-MPLS payload imposition cases.
                 * Based on the LSP mode either, for uniform, copy down the TTL
                 * and EXP from the payload or, for pipe mode, slap on the value
                 * requested from config
                 */
                if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                {
                    hdr0 = mpls_label_paint_w_ttl_exp(b0, mld0, ttl0, exp0);
                    hdr1 = mpls_label_paint_w_ttl_exp(b1, mld1, ttl1, exp1);
                    hdr2 = mpls_label_paint_w_ttl_exp(b2, mld2, ttl2, exp2);
                    hdr3 = mpls_label_paint_w_ttl_exp(b3, mld3, ttl3, exp3);
                }
                else
                {
                    hdr0 = mpls_label_paint(b0, mld0);
                    hdr1 = mpls_label_paint(b1, mld1);
                    hdr2 = mpls_label_paint(b2, mld2);
                    hdr3 = mpls_label_paint(b3, mld3);
                }
            }
            else
            {
                /*
                 * else, the packet to be encapped is an MPLS packet
                 * there are two cases to consider:
                 *  1 - this is an MPLS label swap at an LSP midpoint.
                 *      recognisable because mpls.first = 1. In this case the
                 *      TTL must be set to the current value -1.
                 *  2 - The MPLS packet is recursing (or being injected into)
                 *      this LSP, in which case the pipe/uniform rules apply
                 *
                 */
                if (PREDICT_TRUE(vnet_buffer(b0)->mpls.first))
                {
                    /*
                     * The first label to be imposed on the packet. this is a
                     * label swap.in which case we stashed the TTL and EXP bits
                     * in the packet in the lookup node
                     */
                    ASSERT(0 != vnet_buffer (b0)->mpls.ttl);

                    ttl0 = vnet_buffer(b0)->mpls.ttl - 1;
                    exp0 = vnet_buffer(b0)->mpls.exp;
                    hdr0 = mpls_label_paint_w_ttl_exp(b0, mld0, ttl0, exp0);
                }
                else
                {
                    /*
                     * not the first label. implying we are recusring down a
                     * chain of output labels. Each layer is considered a new
                     * LSP - hence the TTL/EXP are pipe/uniform handled
                     */
                    if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                    {
                        hdr0 = vlib_buffer_get_current(b0);
                        ttl0 = ((u8*)hdr0)[3];
                        exp0 = ((u8*)hdr0)[2] & 0xe;
                        hdr0 = mpls_label_paint_w_ttl_mpls_exp(b0, mld0, ttl0, exp0);
                    }
                    else
                    {
                        hdr0 = mpls_label_paint(b0, mld0);
                    }
                }
                if (PREDICT_TRUE(vnet_buffer(b1)->mpls.first))
                {
                    ASSERT(0 != vnet_buffer (b1)->mpls.ttl);

                    ttl1 = vnet_buffer(b1)->mpls.ttl - 1;
                    exp1 = vnet_buffer(b1)->mpls.exp;
                    hdr1 = mpls_label_paint_w_ttl_exp(b1, mld1, ttl1, exp1);
                }
                else
                {
                    if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                    {
                        hdr1 = vlib_buffer_get_current(b1);
                        ttl1 = ((u8*)hdr1)[3];
                        exp1 = ((u8*)hdr1)[2] & 0xe;
                        hdr1 = mpls_label_paint_w_ttl_mpls_exp(b1, mld1, ttl1, exp1);
                    }
                    else
                    {
                        hdr1 = mpls_label_paint(b1, mld1);
                    }
                }
                if (PREDICT_TRUE(vnet_buffer(b2)->mpls.first))
                {
                    ASSERT(0 != vnet_buffer (b2)->mpls.ttl);

                    ttl2 = vnet_buffer(b2)->mpls.ttl - 1;
                    exp2 = vnet_buffer(b2)->mpls.exp;
                    hdr2 = mpls_label_paint_w_ttl_exp(b2, mld2, ttl2, exp2);
                }
                else
                {
                    if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                    {
                        hdr2 = vlib_buffer_get_current(b2);
                        ttl2 = ((u8*)hdr2)[3];
                        exp2 = ((u8*)hdr2)[2] & 0xe;
                        hdr2 = mpls_label_paint_w_ttl_mpls_exp(b2, mld2, ttl2, exp2);
                    }
                    else
                    {
                        hdr2 = mpls_label_paint(b2, mld2);
                    }
                }
                if (PREDICT_TRUE(vnet_buffer(b3)->mpls.first))
                {
                    ASSERT(0 != vnet_buffer (b3)->mpls.ttl);

                    ttl3 = vnet_buffer(b3)->mpls.ttl - 1;
                    exp3 = vnet_buffer(b3)->mpls.exp;
                    hdr3 = mpls_label_paint_w_ttl_exp(b3, mld3, ttl3, exp3);
                }
                else
                {
                    if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                    {
                        hdr3 = vlib_buffer_get_current(b3);
                        ttl3 = ((u8*)hdr3)[3];
                        exp3 = ((u8*)hdr3)[2] & 0xe;
                        hdr3 = mpls_label_paint_w_ttl_mpls_exp(b3, mld3, ttl3, exp3);
                    }
                    else
                    {
                        hdr3 = mpls_label_paint(b3, mld3);
                    }
                }

                vnet_buffer(b0)->mpls.first = 0;
                vnet_buffer(b1)->mpls.first = 0;
                vnet_buffer(b2)->mpls.first = 0;
                vnet_buffer(b3)->mpls.first = 0;
            }

            next0 = mld0->mld_dpo.dpoi_next_node;
            next1 = mld1->mld_dpo.dpoi_next_node;
            next2 = mld2->mld_dpo.dpoi_next_node;
            next3 = mld3->mld_dpo.dpoi_next_node;

            vnet_buffer(b0)->ip.adj_index = mld0->mld_dpo.dpoi_index;
            vnet_buffer(b1)->ip.adj_index = mld1->mld_dpo.dpoi_index;
            vnet_buffer(b2)->ip.adj_index = mld2->mld_dpo.dpoi_index;
            vnet_buffer(b3)->ip.adj_index = mld3->mld_dpo.dpoi_index;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                mpls_label_imposition_trace_t *tr =
                    vlib_add_trace (vm, node, b0, sizeof (*tr));
                tr->hdr = *hdr0;
                if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                {
                    tr->ttl = ttl0;
                    tr->exp = exp0;
                }
                else
                {
                    tr->ttl = tr->exp = 0;
                }
            }
            if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
                mpls_label_imposition_trace_t *tr =
                    vlib_add_trace (vm, node, b1, sizeof (*tr));
                tr->hdr = *hdr1;
                if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                {
                    tr->ttl = ttl1;
                    tr->exp = exp1;
                }
                else
                {
                    tr->ttl = tr->exp = 0;
                }
            }
            if (PREDICT_FALSE(b2->flags & VLIB_BUFFER_IS_TRACED))
            {
                mpls_label_imposition_trace_t *tr =
                    vlib_add_trace (vm, node, b2, sizeof (*tr));
                tr->hdr = *hdr2;
                if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                {
                    tr->ttl = ttl2;
                    tr->exp = exp2;
                }
                else
                {
                    tr->ttl = tr->exp = 0;
                }
            }
            if (PREDICT_FALSE(b3->flags & VLIB_BUFFER_IS_TRACED))
            {
                mpls_label_imposition_trace_t *tr =
                    vlib_add_trace (vm, node, b3, sizeof (*tr));
                tr->hdr = *hdr3;
                if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                {
                    tr->ttl = ttl3;
                    tr->exp = exp3;
                }
                else
                {
                    tr->ttl = tr->exp = 0;
                }
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
            u8 ttl0, exp0;
            u32 next0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);

            /* dst lookup was done by ip4 lookup */
            mldi0 = vnet_buffer(b0)->ip.adj_index;
            mld0 = mpls_label_dpo_get(mldi0);

            if (DPO_PROTO_MPLS != dproto)
            {
                if (DPO_PROTO_IP4 == dproto)
                {
                    /*
                     * decrement the TTL on ingress to the LSP
                     */
                    ip4_header_t * ip0 = vlib_buffer_get_current(b0);
                    if (!(MPLS_LABEL_DPO_FLAG_NO_IP_TTL_DECR & flags))
                    {
                        u32 checksum0;

                        checksum0 = ip0->checksum + clib_host_to_net_u16 (0x0100);
                        checksum0 += checksum0 >= 0xffff;

                        ip0->checksum = checksum0;
                        ip0->ttl -= 1;
                    }
                    if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                    {
                        ttl0 = ip0->ttl;
                        exp0 = ip_dscp_to_mpls_exp(ip0->tos);
                    }

                    /* save the payload proto information in mpls opaque */
                    vnet_buffer(b0)->mpls.pyld_proto = DPO_PROTO_IP4;
                }
                else if (DPO_PROTO_IP6 == dproto)
                {
                    /*
                     * decrement the TTL on ingress to the LSP
                     */
                    ip6_header_t * ip0 = vlib_buffer_get_current(b0);

                    if (!(MPLS_LABEL_DPO_FLAG_NO_IP_TTL_DECR & flags))
                    {
                        ip0->hop_limit -= 1;
                    }
                    if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                    {
                        ttl0 = ip0->hop_limit;
                        exp0 = ip_dscp_to_mpls_exp(
                            ip6_traffic_class_network_order(ip0));
                    }

                    /* save the payload proto information in mpls opaque */
                    vnet_buffer(b0)->mpls.pyld_proto = DPO_PROTO_IP6;
                }
                else
                {
                    /*
                     * nothing to change in the ethernet header
                     */
                    ttl0 = MPLS_LABEL_DEFAULT_TTL;
                    exp0 = MPLS_LABEL_DEFAULT_EXP;
                }

                /*
                 * These are the non-MPLS payload imposition cases.
                 * Based on the LSP mode either, for uniform, copy down the TTL
                 * from the payload or, for pipe mode, slap on the value
                 * requested from config
                 */
                if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                {
                    hdr0 = mpls_label_paint_w_ttl_exp(b0, mld0, ttl0, exp0);
                }
                else
                {
                    hdr0 = mpls_label_paint(b0, mld0);
                }
            }
            else
            {
                if (PREDICT_TRUE(vnet_buffer(b0)->mpls.first))
                {
                    ASSERT(0 != vnet_buffer (b0)->mpls.ttl);

                    ttl0 = vnet_buffer(b0)->mpls.ttl - 1;
                    exp0 = vnet_buffer(b0)->mpls.exp;
                    hdr0 = mpls_label_paint_w_ttl_exp(b0, mld0, ttl0, exp0);
                }
                else
                {
                    if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                    {
                        hdr0 = vlib_buffer_get_current(b0);
                        ttl0 = ((u8*)hdr0)[3];
                        exp0 = ((u8*)hdr0)[2] & 0xe;
                        hdr0 = mpls_label_paint_w_ttl_mpls_exp(b0, mld0, ttl0, exp0);
                    }
                    else
                    {
                        hdr0 = mpls_label_paint(b0, mld0);
                    }
                }

                vnet_buffer(b0)->mpls.first = 0;
            }

            next0 = mld0->mld_dpo.dpoi_next_node;
            vnet_buffer(b0)->ip.adj_index = mld0->mld_dpo.dpoi_index;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                mpls_label_imposition_trace_t *tr =
                    vlib_add_trace (vm, node, b0, sizeof (*tr));
                tr->hdr = *hdr0;
                if (flags & MPLS_LABEL_DPO_FLAG_UNIFORM_MODE)
                {
                    tr->ttl = ttl0;
                    tr->exp = exp0;
                }
                else
                {
                    tr->ttl = tr->exp = 0;
                }
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

VLIB_NODE_FN (mpls_mpls_label_imposition_pipe_node) (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame,
                                         DPO_PROTO_MPLS,
                                         MPLS_LABEL_DPO_FLAG_NONE));
}

VLIB_REGISTER_NODE (mpls_mpls_label_imposition_pipe_node) = {
    .name = "mpls-label-imposition-pipe",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "mpls-drop",
    }
};

VLIB_NODE_FN (ip4_mpls_label_imposition_pipe_node) (vlib_main_t * vm,
                                vlib_node_runtime_t * node,
                                vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame,
                                         DPO_PROTO_IP4,
                                         MPLS_LABEL_DPO_FLAG_NONE));
}

VLIB_REGISTER_NODE (ip4_mpls_label_imposition_pipe_node) = {
    .name = "ip4-mpls-label-imposition-pipe",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "ip4-drop",
    }
};

VLIB_NODE_FN (ip6_mpls_label_imposition_pipe_node) (vlib_main_t * vm,
                                vlib_node_runtime_t * node,
                                vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame,
                                         DPO_PROTO_IP6,
                                         MPLS_LABEL_DPO_FLAG_NONE));
}

VLIB_REGISTER_NODE (ip6_mpls_label_imposition_pipe_node) = {
    .name = "ip6-mpls-label-imposition-pipe",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "ip6-drop",
    }
};

VLIB_NODE_FN (ethernet_mpls_label_imposition_pipe_node) (vlib_main_t * vm,
                                     vlib_node_runtime_t * node,
                                     vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame,
                                         DPO_PROTO_ETHERNET,
                                         MPLS_LABEL_DPO_FLAG_NONE));
}

VLIB_REGISTER_NODE (ethernet_mpls_label_imposition_pipe_node) = {
    .name = "ethernet-mpls-label-imposition-pipe",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "error-drop",
    }
};

VLIB_NODE_FN (mpls_mpls_label_imposition_uniform_node) (vlib_main_t * vm,
                                    vlib_node_runtime_t * node,
                                    vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame,
                                         DPO_PROTO_MPLS,
                                         MPLS_LABEL_DPO_FLAG_UNIFORM_MODE));
}

VLIB_REGISTER_NODE (mpls_mpls_label_imposition_uniform_node) = {
    .name = "mpls-label-imposition-uniform",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "mpls-drop",
    }
};

VLIB_NODE_FN (ip4_mpls_label_imposition_uniform_node) (vlib_main_t * vm,
                                   vlib_node_runtime_t * node,
                                   vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame,
                                         DPO_PROTO_IP4,
                                         MPLS_LABEL_DPO_FLAG_UNIFORM_MODE));
}

VLIB_REGISTER_NODE (ip4_mpls_label_imposition_uniform_node) = {
    .name = "ip4-mpls-label-imposition-uniform",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "ip4-drop",
    }
};

VLIB_NODE_FN (ip6_mpls_label_imposition_uniform_node) (vlib_main_t * vm,
                                   vlib_node_runtime_t * node,
                                   vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame,
                                         DPO_PROTO_IP6,
                                         MPLS_LABEL_DPO_FLAG_UNIFORM_MODE));
}

VLIB_REGISTER_NODE (ip6_mpls_label_imposition_uniform_node) = {
    .name = "ip6-mpls-label-imposition-uniform",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "ip6-drop",
    }
};

VLIB_NODE_FN (ethernet_mpls_label_imposition_uniform_node) (vlib_main_t * vm,
                                        vlib_node_runtime_t * node,
                                        vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame,
                                         DPO_PROTO_ETHERNET,
                                         MPLS_LABEL_DPO_FLAG_UNIFORM_MODE));
}

VLIB_REGISTER_NODE (ethernet_mpls_label_imposition_uniform_node) = {
    .name = "ethernet-mpls-label-imposition-uniform",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "error-drop",
    }
};


VLIB_NODE_FN (ip4_mpls_label_imposition_pipe_no_ip_ttl_decr_node) (vlib_main_t * vm,
                                               vlib_node_runtime_t * node,
                                               vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame,
                                         DPO_PROTO_IP4,
                                         MPLS_LABEL_DPO_FLAG_NO_IP_TTL_DECR));
}

VLIB_REGISTER_NODE (ip4_mpls_label_imposition_pipe_no_ip_ttl_decr_node) = {
    .name = "ip4-mpls-label-imposition-pipe-no-ip-ttl-decr",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "ip4-drop",
    }
};

VLIB_NODE_FN (ip6_mpls_label_imposition_pipe_no_ip_ttl_decr_node) (vlib_main_t * vm,
                                               vlib_node_runtime_t * node,
                                               vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame,
                                         DPO_PROTO_IP6,
                                         MPLS_LABEL_DPO_FLAG_NO_IP_TTL_DECR));
}

VLIB_REGISTER_NODE (ip6_mpls_label_imposition_pipe_no_ip_ttl_decr_node) = {
    .name = "ip6-mpls-label-imposition-pipe-no-ip-ttl-decr",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "ip6-drop",
    }
};

VLIB_NODE_FN (ip4_mpls_label_imposition_uniform_no_ip_ttl_decr_node) (vlib_main_t * vm,
                                                  vlib_node_runtime_t * node,
                                                  vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame,
                                         DPO_PROTO_IP4,
                                         (MPLS_LABEL_DPO_FLAG_UNIFORM_MODE |
                                          MPLS_LABEL_DPO_FLAG_NO_IP_TTL_DECR)));
}

VLIB_REGISTER_NODE (ip4_mpls_label_imposition_uniform_no_ip_ttl_decr_node) = {
    .name = "ip4-mpls-label-imposition-uniform-no-ip-ttl-decr",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "ip4-drop",
    }
};

VLIB_NODE_FN (ip6_mpls_label_imposition_uniform_no_ip_ttl_decr_node) (vlib_main_t * vm,
                                                  vlib_node_runtime_t * node,
                                                  vlib_frame_t * frame)
{
    return (mpls_label_imposition_inline(vm, node, frame,
                                         DPO_PROTO_IP6,
                                         (MPLS_LABEL_DPO_FLAG_UNIFORM_MODE |
                                          MPLS_LABEL_DPO_FLAG_NO_IP_TTL_DECR)));
}

VLIB_REGISTER_NODE (ip6_mpls_label_imposition_uniform_no_ip_ttl_decr_node) = {
    .name = "ip6-mpls-label-imposition-uniform-no-ip-ttl-decr",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "ip6-drop",
    }
};


#ifndef CLIB_MARCH_VARIANT
static void
mpls_label_dpo_mem_show (void)
{
    fib_show_memory_usage("MPLS label",
			  pool_elts(mpls_label_dpo_pool),
			  pool_len(mpls_label_dpo_pool),
			  sizeof(mpls_label_dpo_t));
}

/**
 * Interpose a label DPO. used in the FIB unit tests
 */
static void
mpls_label_interpose (const dpo_id_t *original,
                      const dpo_id_t *parent,
                      dpo_id_t *clone)
{
    mpls_label_dpo_t *mld, *mld_clone;

    mld_clone = mpls_label_dpo_alloc();
    mld = mpls_label_dpo_get(original->dpoi_index);

    mld_clone->mld_locks = 0;
    clib_memcpy_fast(&mld_clone->mld_hdr,
                &mld->mld_hdr,
                sizeof(mld_clone->mld_hdr));
    mld_clone->mld_payload_proto = mld->mld_payload_proto;
    mld_clone->mld_n_labels = mld->mld_n_labels;
    mld_clone->mld_n_hdr_bytes = mld->mld_n_hdr_bytes;

    dpo_stack(mpls_label_dpo_types[MPLS_LABEL_DPO_FLAG_NONE],
              mld_clone->mld_payload_proto,
              &mld_clone->mld_dpo,
              parent);

    dpo_set(clone,
            mpls_label_dpo_types[MPLS_LABEL_DPO_FLAG_NONE],
            mld_clone->mld_payload_proto,
            mpls_label_dpo_get_index(mld_clone));
}

const static dpo_vft_t mld_vft = {
    .dv_lock = mpls_label_dpo_lock,
    .dv_unlock = mpls_label_dpo_unlock,
    .dv_format = format_mpls_label_dpo,
    .dv_mem_show = mpls_label_dpo_mem_show,
    .dv_mk_interpose = mpls_label_interpose,
};

const static char* const mpls_label_imp_pipe_ip4_nodes[] =
{
    "ip4-mpls-label-imposition-pipe",
    NULL,
};
const static char* const mpls_label_imp_pipe_ip6_nodes[] =
{
    "ip6-mpls-label-imposition-pipe",
    NULL,
};
const static char* const mpls_label_imp_pipe_mpls_nodes[] =
{
    "mpls-label-imposition-pipe",
    NULL,
};
const static char* const mpls_label_imp_pipe_ethernet_nodes[] =
{
    "ethernet-mpls-label-imposition-pipe",
    NULL,
};

const static char* const * const mpls_label_imp_pipe_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = mpls_label_imp_pipe_ip4_nodes,
    [DPO_PROTO_IP6]  = mpls_label_imp_pipe_ip6_nodes,
    [DPO_PROTO_MPLS] = mpls_label_imp_pipe_mpls_nodes,
    [DPO_PROTO_ETHERNET] = mpls_label_imp_pipe_ethernet_nodes,
};

const static char* const mpls_label_imp_uniform_ip4_nodes[] =
{
    "ip4-mpls-label-imposition-uniform",
    NULL,
};
const static char* const mpls_label_imp_uniform_ip6_nodes[] =
{
    "ip6-mpls-label-imposition-uniform",
    NULL,
};
const static char* const mpls_label_imp_uniform_mpls_nodes[] =
{
    "mpls-label-imposition-uniform",
    NULL,
};
const static char* const mpls_label_imp_uniform_ethernet_nodes[] =
{
    "ethernet-mpls-label-imposition-uniform",
    NULL,
};

const static char* const * const mpls_label_imp_uniform_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = mpls_label_imp_uniform_ip4_nodes,
    [DPO_PROTO_IP6]  = mpls_label_imp_uniform_ip6_nodes,
    [DPO_PROTO_MPLS] = mpls_label_imp_uniform_mpls_nodes,
    [DPO_PROTO_ETHERNET] = mpls_label_imp_uniform_ethernet_nodes,
};

const static char* const mpls_label_imp_pipe_no_ip_tll_decr_ip4_nodes[] =
{
    "ip4-mpls-label-imposition-pipe-no-ip-ttl-decr",
    NULL,
};
const static char* const mpls_label_imp_pipe_no_ip_tll_decr_ip6_nodes[] =
{
    "ip6-mpls-label-imposition-pipe-no-ip-ttl-decr",
    NULL,
};

const static char* const * const mpls_label_imp_pipe_no_ip_tll_decr_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = mpls_label_imp_pipe_no_ip_tll_decr_ip4_nodes,
    [DPO_PROTO_IP6]  = mpls_label_imp_pipe_no_ip_tll_decr_ip6_nodes,
};

const static char* const mpls_label_imp_uniform_no_ip_tll_decr_ip4_nodes[] =
{
    "ip4-mpls-label-imposition-uniform-no-ip-ttl-decr",
    NULL,
};
const static char* const mpls_label_imp_uniform_no_ip_tll_decr_ip6_nodes[] =
{
    "ip6-mpls-label-imposition-uniform-no-ip-ttl-decr",
    NULL,
};

const static char* const * const mpls_label_imp_uniform_no_ip_tll_decr_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = mpls_label_imp_uniform_no_ip_tll_decr_ip4_nodes,
    [DPO_PROTO_IP6]  = mpls_label_imp_uniform_no_ip_tll_decr_ip6_nodes,
};

void
mpls_label_dpo_module_init (void)
{
    mpls_label_dpo_types[MPLS_LABEL_DPO_FLAG_NONE] =
        dpo_register_new_type(&mld_vft,
                              mpls_label_imp_pipe_nodes);
    mpls_label_dpo_types[MPLS_LABEL_DPO_FLAG_NO_IP_TTL_DECR] =
        dpo_register_new_type(&mld_vft,
                              mpls_label_imp_pipe_no_ip_tll_decr_nodes);
    mpls_label_dpo_types[MPLS_LABEL_DPO_FLAG_UNIFORM_MODE] =
        dpo_register_new_type(&mld_vft,
                              mpls_label_imp_uniform_nodes);
    mpls_label_dpo_types[MPLS_LABEL_DPO_FLAG_UNIFORM_MODE |
                         MPLS_LABEL_DPO_FLAG_NO_IP_TTL_DECR] =
        dpo_register_new_type(&mld_vft,
                              mpls_label_imp_uniform_no_ip_tll_decr_nodes);
}

dpo_type_t
mpls_label_dpo_get_type (mpls_label_dpo_flags_t flags)
{
    return (mpls_label_dpo_types[flags]);
}
#endif /* CLIB_MARCH_VARIANT */
