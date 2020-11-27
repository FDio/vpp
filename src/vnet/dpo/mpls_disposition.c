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

#include <vnet/ip/ip4_input.h>
#include <vnet/ip/ip6_input.h>
#include <vnet/dpo/mpls_disposition.h>
#include <vnet/mpls/mpls.h>

#ifndef CLIB_MARCH_VARIANT
/*
 * pool of all MPLS Label DPOs
 */
mpls_disp_dpo_t *mpls_disp_dpo_pool;

static mpls_disp_dpo_t *
mpls_disp_dpo_alloc (void)
{
    mpls_disp_dpo_t *mdd;

    pool_get_aligned(mpls_disp_dpo_pool, mdd, CLIB_CACHE_LINE_BYTES);
    clib_memset(mdd, 0, sizeof(*mdd));

    dpo_reset(&mdd->mdd_dpo);

    return (mdd);
}

static index_t
mpls_disp_dpo_get_index (mpls_disp_dpo_t *mdd)
{
    return (mdd - mpls_disp_dpo_pool);
}

void
mpls_disp_dpo_create (dpo_proto_t payload_proto,
                      fib_rpf_id_t rpf_id,
                      fib_mpls_lsp_mode_t mode,
                      const dpo_id_t *parent,
                      dpo_id_t *dpo)
{
    mpls_disp_dpo_t *mdd;
    dpo_type_t dtype;

    mdd = mpls_disp_dpo_alloc();

    mdd->mdd_payload_proto = payload_proto;
    mdd->mdd_rpf_id = rpf_id;
    mdd->mdd_mode = mode;
    dtype = (FIB_MPLS_LSP_MODE_PIPE == mode ?
             DPO_MPLS_DISPOSITION_PIPE :
             DPO_MPLS_DISPOSITION_UNIFORM);

    /*
     * stack this disposition object on the parent given
     */
    dpo_stack(dtype,
              mdd->mdd_payload_proto,
              &mdd->mdd_dpo,
              parent);

    /*
     * set up the return DPO to refer to this object
     */
    dpo_set(dpo,
            dtype,
            payload_proto,
            mpls_disp_dpo_get_index(mdd));
}

u8*
format_mpls_disp_dpo (u8 *s, va_list *args)
{
    index_t index = va_arg(*args, index_t);
    u32 indent = va_arg(*args, u32);
    mpls_disp_dpo_t *mdd;

    mdd = mpls_disp_dpo_get(index);

    s = format(s, "mpls-disposition:[%d]:[", index);

    if (0 != mdd->mdd_rpf_id)
        s = format(s, "rpf-id:%d ", mdd->mdd_rpf_id);

    s = format(s, "%U, %U]",
               format_dpo_proto, mdd->mdd_payload_proto,
               format_fib_mpls_lsp_mode, mdd->mdd_mode);

    s = format(s, "\n%U", format_white_space, indent);
    s = format(s, "%U", format_dpo_id, &mdd->mdd_dpo, indent+2);

    return (s);
}

static void
mpls_disp_dpo_lock (dpo_id_t *dpo)
{
    mpls_disp_dpo_t *mdd;

    mdd = mpls_disp_dpo_get(dpo->dpoi_index);

    mdd->mdd_locks++;
}

static void
mpls_disp_dpo_unlock (dpo_id_t *dpo)
{
    mpls_disp_dpo_t *mdd;

    mdd = mpls_disp_dpo_get(dpo->dpoi_index);

    mdd->mdd_locks--;

    if (0 == mdd->mdd_locks)
    {
	dpo_reset(&mdd->mdd_dpo);
	pool_put(mpls_disp_dpo_pool, mdd);
    }
}
#endif /* CLIB_MARCH_VARIANT */

/**
 * @brief A struct to hold tracing information for the MPLS label disposition
 * node.
 */
typedef struct mpls_label_disposition_trace_t_
{
    dpo_proto_t mddt_payload_proto;
    fib_rpf_id_t mddt_rpf_id;
    fib_mpls_lsp_mode_t mddt_mode;
} mpls_label_disposition_trace_t;

extern vlib_node_registration_t ip4_mpls_label_disposition_pipe_node;
extern vlib_node_registration_t ip6_mpls_label_disposition_pipe_node;
extern vlib_node_registration_t ip4_mpls_label_disposition_uniform_node;
extern vlib_node_registration_t ip6_mpls_label_disposition_uniform_node;

always_inline uword
mpls_label_disposition_inline (vlib_main_t * vm,
                               vlib_node_runtime_t * node,
                               vlib_frame_t * from_frame,
                               u8 payload_is_ip4,
                               u8 payload_is_ip6,
                               fib_mpls_lsp_mode_t mode)
{
    u32 n_left_from, next_index, * from, * to_next;
    vlib_node_runtime_t *error_node;

    if (payload_is_ip4)
    {
        if (FIB_MPLS_LSP_MODE_PIPE == mode)
            error_node =
                vlib_node_get_runtime(vm, ip4_mpls_label_disposition_pipe_node.index);
        else
            error_node =
                vlib_node_get_runtime(vm, ip4_mpls_label_disposition_uniform_node.index);
    }
    else
    {
        if (FIB_MPLS_LSP_MODE_PIPE == mode)
            error_node =
                vlib_node_get_runtime(vm, ip6_mpls_label_disposition_pipe_node.index);
        else
            error_node =
                vlib_node_get_runtime(vm, ip6_mpls_label_disposition_uniform_node.index);
    }
    from = vlib_frame_vector_args(from_frame);
    n_left_from = from_frame->n_vectors;

    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from >= 4 && n_left_to_next >= 2)
        {
            mpls_disp_dpo_t *mdd0, *mdd1;
            u32 bi0, mddi0, bi1, mddi1;
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

                CLIB_PREFETCH(p2->data, sizeof(ip6_header_t), STORE);
                CLIB_PREFETCH(p3->data, sizeof(ip6_header_t), STORE);
            }

            from += 2;
            to_next += 2;
            n_left_from -= 2;
            n_left_to_next -= 2;

            b0 = vlib_get_buffer(vm, bi0);
            b1 = vlib_get_buffer(vm, bi1);

            /* dst lookup was done by ip4 lookup */
            mddi0 = vnet_buffer(b0)->ip.adj_index;
            mddi1 = vnet_buffer(b1)->ip.adj_index;
            mdd0 = mpls_disp_dpo_get(mddi0);
            mdd1 = mpls_disp_dpo_get(mddi1);

            next0 = mdd0->mdd_dpo.dpoi_next_node;
            next1 = mdd1->mdd_dpo.dpoi_next_node;

            if (payload_is_ip4)
            {
                ip4_header_t *ip0, *ip1;

                ip0 = vlib_buffer_get_current(b0);
                ip1 = vlib_buffer_get_current(b1);

                /*
                 * IPv4 input checks on the exposed IP header
                 * including checksum
                 */
                ip4_input_check_x2(vm, error_node,
                                   b0, b1, ip0, ip1,
                                   &next0, &next1, 1);

                if (FIB_MPLS_LSP_MODE_UNIFORM == mode)
                {
                    /*
                     * Copy the TTL from the MPLS packet into the
                     * exposed IP. recalc the chksum
                     */
                    ip0->ttl = vnet_buffer(b0)->mpls.ttl;
                    ip1->ttl = vnet_buffer(b1)->mpls.ttl;
                    ip0->tos = mpls_exp_to_ip_dscp(vnet_buffer(b0)->mpls.exp);
                    ip1->tos = mpls_exp_to_ip_dscp(vnet_buffer(b1)->mpls.exp);

                    ip0->checksum = ip4_header_checksum(ip0);
                    ip1->checksum = ip4_header_checksum(ip1);
                }
            }
            else if (payload_is_ip6)
            {
                ip6_header_t *ip0, *ip1;

                ip0 = vlib_buffer_get_current(b0);
                ip1 = vlib_buffer_get_current(b1);

                /*
                 * IPv6 input checks on the exposed IP header
                 */
                ip6_input_check_x2(vm, error_node,
                                   b0, b1, ip0, ip1,
                                   &next0, &next1);

                if (FIB_MPLS_LSP_MODE_UNIFORM == mode)
                {
                    /*
                     * Copy the TTL from the MPLS packet into the
                     * exposed IP
                     */
                    ip0->hop_limit = vnet_buffer(b0)->mpls.ttl;
                    ip1->hop_limit = vnet_buffer(b1)->mpls.ttl;

                    ip6_set_traffic_class_network_order(
                        ip0,
                        mpls_exp_to_ip_dscp(vnet_buffer(b0)->mpls.exp));
                    ip6_set_traffic_class_network_order(
                        ip1,
                        mpls_exp_to_ip_dscp(vnet_buffer(b1)->mpls.exp));
                }
            }

            vnet_buffer(b0)->ip.adj_index = mdd0->mdd_dpo.dpoi_index;
            vnet_buffer(b1)->ip.adj_index = mdd1->mdd_dpo.dpoi_index;
            vnet_buffer(b0)->ip.rpf_id = mdd0->mdd_rpf_id;
            vnet_buffer(b1)->ip.rpf_id = mdd1->mdd_rpf_id;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                mpls_label_disposition_trace_t *tr =
                    vlib_add_trace(vm, node, b0, sizeof(*tr));

                tr->mddt_payload_proto = mdd0->mdd_payload_proto;
                tr->mddt_rpf_id = mdd0->mdd_rpf_id;
                tr->mddt_mode = mdd0->mdd_mode;
            }
            if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
                mpls_label_disposition_trace_t *tr =
                    vlib_add_trace(vm, node, b1, sizeof(*tr));
                tr->mddt_payload_proto = mdd1->mdd_payload_proto;
                tr->mddt_rpf_id = mdd1->mdd_rpf_id;
                tr->mddt_mode = mdd1->mdd_mode;
            }

            vlib_validate_buffer_enqueue_x2(vm, node, next_index, to_next,
                                            n_left_to_next,
                                            bi0, bi1, next0, next1);
        }

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            mpls_disp_dpo_t *mdd0;
            vlib_buffer_t * b0;
            u32 bi0, mddi0;
            u32 next0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer(vm, bi0);

            /* dst lookup was done by ip4 lookup */
            mddi0 = vnet_buffer(b0)->ip.adj_index;
            mdd0 = mpls_disp_dpo_get(mddi0);
            next0 = mdd0->mdd_dpo.dpoi_next_node;

            if (payload_is_ip4)
            {
                ip4_header_t *ip0;

                ip0 = vlib_buffer_get_current(b0);

                /*
                 * IPv4 input checks on the exposed IP header
                 * including checksum
                 */
                ip4_input_check_x1(vm, error_node, b0, ip0, &next0, 1);

                if (FIB_MPLS_LSP_MODE_UNIFORM == mode)
                {
                    /*
                     * Copy the TTL from the MPLS packet into the
                     * exposed IP. recalc the chksum
                     */
                    ip0->ttl = vnet_buffer(b0)->mpls.ttl;
                    ip0->tos = mpls_exp_to_ip_dscp(vnet_buffer(b0)->mpls.exp);
                    ip0->checksum = ip4_header_checksum(ip0);
                }
            }
            else if (payload_is_ip6)
            {
                ip6_header_t *ip0;

                ip0 = vlib_buffer_get_current(b0);

                /*
                 * IPv6 input checks on the exposed IP header
                 */
                ip6_input_check_x1(vm, error_node, b0, ip0, &next0);

                if (FIB_MPLS_LSP_MODE_UNIFORM == mode)
                {
                    /*
                     * Copy the TTL from the MPLS packet into the
                     * exposed IP
                     */
                    ip0->hop_limit = vnet_buffer(b0)->mpls.ttl;

                    ip6_set_traffic_class_network_order(
                        ip0,
                        mpls_exp_to_ip_dscp(vnet_buffer(b0)->mpls.exp));
                }
            }

            vnet_buffer(b0)->ip.adj_index = mdd0->mdd_dpo.dpoi_index;
            vnet_buffer(b0)->ip.rpf_id = mdd0->mdd_rpf_id;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                mpls_label_disposition_trace_t *tr =
                    vlib_add_trace(vm, node, b0, sizeof(*tr));
                tr->mddt_payload_proto = mdd0->mdd_payload_proto;
                tr->mddt_rpf_id = mdd0->mdd_rpf_id;
                tr->mddt_mode = mdd0->mdd_mode;
            }

            vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                            n_left_to_next, bi0, next0);
        }
        vlib_put_next_frame(vm, node, next_index, n_left_to_next);
    }
    return from_frame->n_vectors;
}

static u8 *
format_mpls_label_disposition_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
    CLIB_UNUSED(mpls_label_disposition_trace_t * t);

    t = va_arg(*args, mpls_label_disposition_trace_t *);

    s = format(s, "rpf-id:%d %U, %U",
               t->mddt_rpf_id,
               format_dpo_proto, t->mddt_payload_proto,
               format_fib_mpls_lsp_mode, t->mddt_mode);

    return (s);
}

VLIB_NODE_FN (ip4_mpls_label_disposition_pipe_node) (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
    return (mpls_label_disposition_inline(vm, node, frame, 1, 0,
                                          FIB_MPLS_LSP_MODE_PIPE));
}

VLIB_REGISTER_NODE(ip4_mpls_label_disposition_pipe_node) = {
    .name = "ip4-mpls-label-disposition-pipe",
    .vector_size = sizeof(u32),

    .format_trace = format_mpls_label_disposition_trace,
    .sibling_of = "ip4-input",
    .n_errors = IP4_N_ERROR,
    .error_strings = ip4_error_strings,
};

VLIB_NODE_FN (ip6_mpls_label_disposition_pipe_node) (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
    return (mpls_label_disposition_inline(vm, node, frame, 0, 1,
                                          FIB_MPLS_LSP_MODE_PIPE));
}

VLIB_REGISTER_NODE(ip6_mpls_label_disposition_pipe_node) = {
    .name = "ip6-mpls-label-disposition-pipe",
    .vector_size = sizeof(u32),

    .format_trace = format_mpls_label_disposition_trace,
    .sibling_of = "ip6-input",
    .n_errors = IP6_N_ERROR,
    .error_strings = ip6_error_strings,
};

VLIB_NODE_FN (ip4_mpls_label_disposition_uniform_node) (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
    return (mpls_label_disposition_inline(vm, node, frame, 1, 0,
                                          FIB_MPLS_LSP_MODE_UNIFORM));
}

VLIB_REGISTER_NODE(ip4_mpls_label_disposition_uniform_node) = {
    .name = "ip4-mpls-label-disposition-uniform",
    .vector_size = sizeof(u32),

    .format_trace = format_mpls_label_disposition_trace,
    .sibling_of = "ip4-input",
    .n_errors = IP4_N_ERROR,
    .error_strings = ip4_error_strings,
};

VLIB_NODE_FN (ip6_mpls_label_disposition_uniform_node) (vlib_main_t * vm,
                                    vlib_node_runtime_t * node,
                                    vlib_frame_t * frame)
{
    return (mpls_label_disposition_inline(vm, node, frame, 0, 1,
                                          FIB_MPLS_LSP_MODE_UNIFORM));
}

VLIB_REGISTER_NODE(ip6_mpls_label_disposition_uniform_node) = {
    .name = "ip6-mpls-label-disposition-uniform",
    .vector_size = sizeof(u32),

    .format_trace = format_mpls_label_disposition_trace,
    .sibling_of = "ip6-input",
    .n_errors = IP6_N_ERROR,
    .error_strings = ip6_error_strings,
};

#ifndef CLIB_MARCH_VARIANT
static void
mpls_disp_dpo_mem_show (void)
{
    fib_show_memory_usage("MPLS label",
			  pool_elts(mpls_disp_dpo_pool),
			  pool_len(mpls_disp_dpo_pool),
			  sizeof(mpls_disp_dpo_t));
}

const static dpo_vft_t mdd_vft = {
    .dv_lock = mpls_disp_dpo_lock,
    .dv_unlock = mpls_disp_dpo_unlock,
    .dv_format = format_mpls_disp_dpo,
    .dv_mem_show = mpls_disp_dpo_mem_show,
};

const static char* const mpls_label_disp_pipe_ip4_nodes[] =
{
    "ip4-mpls-label-disposition-pipe",
    NULL,
};
const static char* const mpls_label_disp_pipe_ip6_nodes[] =
{
    "ip6-mpls-label-disposition-pipe",
    NULL,
};
const static char* const * const mpls_label_disp_pipe_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = mpls_label_disp_pipe_ip4_nodes,
    [DPO_PROTO_IP6]  = mpls_label_disp_pipe_ip6_nodes,
};

const static char* const mpls_label_disp_uniform_ip4_nodes[] =
{
    "ip4-mpls-label-disposition-uniform",
    NULL,
};
const static char* const mpls_label_disp_uniform_ip6_nodes[] =
{
    "ip6-mpls-label-disposition-uniform",
    NULL,
};
const static char* const * const mpls_label_disp_uniform_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = mpls_label_disp_uniform_ip4_nodes,
    [DPO_PROTO_IP6]  = mpls_label_disp_uniform_ip6_nodes,
};


void
mpls_disp_dpo_module_init(void)
{
    dpo_register(DPO_MPLS_DISPOSITION_PIPE, &mdd_vft,
                 mpls_label_disp_pipe_nodes);
    dpo_register(DPO_MPLS_DISPOSITION_UNIFORM, &mdd_vft,
                 mpls_label_disp_uniform_nodes);
}
#endif /* CLIB_MARCH_VARIANT */
