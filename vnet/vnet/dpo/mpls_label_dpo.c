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
mpls_label_dpo_create (mpls_label_t label,
                       mpls_eos_bit_t eos,
                       u8 ttl,
                       u8 exp,
		       const dpo_id_t *dpo)
{
    mpls_label_dpo_t *mld;

    mld = mpls_label_dpo_alloc();

    vnet_mpls_uc_set_label(&mld->mld_hdr.label_exp_s_ttl, label);
    vnet_mpls_uc_set_ttl(&mld->mld_hdr.label_exp_s_ttl, ttl);
    vnet_mpls_uc_set_exp(&mld->mld_hdr.label_exp_s_ttl, exp);
    vnet_mpls_uc_set_s(&mld->mld_hdr.label_exp_s_ttl, eos);

    /*
     * get the header in network byte order since we will paint it
     * on a packet in the data-plane
     */
    mld->mld_hdr.label_exp_s_ttl =
        clib_host_to_net_u32(mld->mld_hdr.label_exp_s_ttl);

    dpo_stack(DPO_MPLS_LABEL, DPO_PROTO_MPLS, &mld->mld_dpo, dpo);

    return (mpls_label_dpo_get_index(mld));
}

u8*
format_mpls_label_dpo (u8 *s, va_list *args)
{
    index_t index = va_arg (*args, index_t);
    u32 indent = va_arg (*args, u32);
    mpls_unicast_header_t hdr;
    mpls_label_dpo_t *mld;

    mld = mpls_label_dpo_get(index);

    hdr.label_exp_s_ttl =
        clib_net_to_host_u32(mld->mld_hdr.label_exp_s_ttl);

    return (format(s, "mpls-label:[%d]:%U\n%U%U",
		   index,
                   format_mpls_header, hdr,
		   format_white_space, indent,
		   format_dpo_id, &mld->mld_dpo, indent+2));
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

always_inline uword
mpls_label_imposition (vlib_main_t * vm,
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
            mpls_unicast_header_t *hdr0;
            mpls_label_dpo_t *mld0;
            vlib_buffer_t * b0;
            u32 bi0, mldi0;
            u32 next0;

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

            /* Paint the MPLS header */
            vlib_buffer_advance(b0, -sizeof(*hdr0));
            hdr0 = vlib_buffer_get_current(b0);

            // FIXME.
            // need to copy the TTL from the correct place.
            // for IPvX imposition from the IP header
            // so we need a deidcated ipx-to-mpls-label-imp-node
            // for mpls switch and stack another solution is required.
            *hdr0 = mld0->mld_hdr;

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
    uword indent;

    t = va_arg (*args, mpls_label_imposition_trace_t *);
    indent = format_get_indent (s);
    hdr.label_exp_s_ttl = clib_net_to_host_u32(t->hdr.label_exp_s_ttl);

    s = format (s, "%Umpls-header:%U",
                format_white_space, indent,
                format_mpls_header, hdr);
    return (s);
}

VLIB_REGISTER_NODE (mpls_label_imposition_node) = {
    .function = mpls_label_imposition,
    .name = "mpls-label-imposition",
    .vector_size = sizeof (u32),

    .format_trace = format_mpls_label_imposition_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "error-drop",
    }
};
VLIB_NODE_FUNCTION_MULTIARCH (mpls_label_imposition_node, mpls_label_imposition)

const static dpo_vft_t mld_vft = {
    .dv_lock = mpls_label_dpo_lock,
    .dv_unlock = mpls_label_dpo_unlock,
    .dv_format = format_mpls_label_dpo,
};

const static char* const mpls_label_imp_ip4_nodes[] =
{
    "mpls-label-imposition",
    NULL,
};
const static char* const mpls_label_imp_ip6_nodes[] =
{
    "mpls-label-imposition",
    NULL,
};
const static char* const mpls_label_imp_mpls_nodes[] =
{
    "mpls-label-imposition",
    NULL,
};
const static char* const * const mpls_label_imp_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = mpls_label_imp_ip4_nodes,
    [DPO_PROTO_IP6]  = mpls_label_imp_ip6_nodes,
    [DPO_PROTO_MPLS] = mpls_label_imp_mpls_nodes,
};


void
mpls_label_dpo_module_init (void)
{
    dpo_register(DPO_MPLS_LABEL, &mld_vft, mpls_label_imp_nodes);
}
