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

#include <vnet/bier/bier_bift_table.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/udp/udp_local.h>

typedef enum {
#define bier_error(n,s) BIER_INPUT_ERROR_##n,
#include <vnet/bier/bier_input_error.def>
#undef bier_error
    BIER_INPUT_N_ERROR,
} bier_input_error_t;

static char * bier_error_strings[] = {
#define bier_error(n,s) s,
#include <vnet/bier/bier_input_error.def>
#undef bier_error
};

/**
 * Global BIFT table
 */
bier_bfit_table_t *bier_bift_table;

/**
 * Forward declare the node
 */
vlib_node_registration_t bier_bift_input_node;

void
bier_bift_table_entry_add (bier_bift_id_t id,
                           const dpo_id_t *dpo)
{
    if (NULL == bier_bift_table)
    {
        u32 ii;

        /*
         * allocate the table and
         * set each of the entries therein to a BIER drop
         */
        bier_bift_table = clib_mem_alloc_aligned(sizeof(*bier_bift_table),
                                                 CLIB_CACHE_LINE_BYTES);
        clib_memset(bier_bift_table, 0, sizeof(*bier_bift_table));

        for (ii = 0; ii < BIER_BIFT_N_ENTRIES; ii++)
        {
            dpo_stack_from_node(bier_bift_input_node.index,
                                &bier_bift_table->bblt_dpos[ii],
                                drop_dpo_get(DPO_PROTO_BIER));
        }

        /*
         * register to handle packets that arrive on the assigned
         * UDP port
         */
        udp_register_dst_port(vlib_get_main(),
                              UDP_DST_PORT_BIER,
                              bier_bift_input_node.index,
                              0);
        udp_register_dst_port(vlib_get_main(),
                              UDP_DST_PORT_BIER,
                              bier_bift_input_node.index,
                              1);
    }

    dpo_stack_from_node(bier_bift_input_node.index,
                        &bier_bift_table->bblt_dpos[id],
                        dpo);

    bier_bift_table->bblt_n_entries++;
}

void
bier_bift_table_entry_remove (bier_bift_id_t id)
{
    ASSERT(NULL != bier_bift_table);

    dpo_reset(&bier_bift_table->bblt_dpos[id]);

    bier_bift_table->bblt_n_entries--;

    if (0 == bier_bift_table->bblt_n_entries)
    {
        udp_unregister_dst_port(vlib_get_main(),
                                UDP_DST_PORT_BIER,
                                0);
        udp_unregister_dst_port(vlib_get_main(),
                                UDP_DST_PORT_BIER,
                                1);

        clib_mem_free(bier_bift_table);
        bier_bift_table = NULL;
    }
}

/**
 * @brief Packet trace record for BIER input
 */
typedef struct bier_bift_input_trace_t_
{
    u32 bift_id;
} bier_bift_input_trace_t;

static uword
bier_bift_input (vlib_main_t * vm,
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

        vlib_get_next_frame (vm, node, next_index,
                             to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            bier_bift_id_t *biftp0, bift0;
            const dpo_id_t *dpo0;
            vlib_buffer_t * b0;
            u32 bi0, next0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            biftp0 = vlib_buffer_get_current (b0);
            vlib_buffer_advance(b0, sizeof(bift0));
            bift0 = clib_net_to_host_u32(*biftp0);

            /*
             * Do the lookup based on the first 20 bits, i.e. the
             * encoding of the set, sub-domain and BSL
             */
            dpo0 = bier_bift_dp_lookup(bift0);

            /*
             * save the TTL for later during egress
             */
            vnet_buffer(b0)->mpls.ttl = vnet_mpls_uc_get_ttl(bift0);

            next0 = dpo0->dpoi_next_node;
            vnet_buffer(b0)->ip.adj_index = dpo0->dpoi_index;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                bier_bift_input_trace_t *tr;

                tr = vlib_add_trace(vm, node, b0, sizeof (*tr));
                tr->bift_id = bift0;
            }

            vlib_validate_buffer_enqueue_x1(vm, node, next_index,
                                            to_next, n_left_to_next,
                                            bi0, next0);
        }

        vlib_put_next_frame(vm, node, next_index, n_left_to_next);
    }

    vlib_node_increment_counter(vm, bier_bift_input_node.index,
                                BIER_INPUT_ERROR_PKTS_VALID,
                                from_frame->n_vectors);
    return (from_frame->n_vectors);
}

static u8 *
format_bier_bift_input_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    bier_bift_input_trace_t * t = va_arg (*args, bier_bift_input_trace_t *);

    s = format (s, "BIFT-ID:[%U]", format_bier_bift_id,
                vnet_mpls_uc_get_label(t->bift_id));
    return s;
}

VLIB_REGISTER_NODE (bier_bift_input_node) = {
    .function = bier_bift_input,
    .name = "bier-bift-input",
    /* Takes a vector of packets. */
    .vector_size = sizeof (u32),
    .n_errors = BIER_INPUT_N_ERROR,
    .error_strings = bier_error_strings,
    .n_next_nodes = 0,
    .format_trace = format_bier_bift_input_trace,
};

clib_error_t *
show_bier_bift_cmd (vlib_main_t * vm,
                    unformat_input_t * input,
                    vlib_cli_command_t * cmd)
{
    clib_error_t * error = NULL;
    u32 hdr_len, set, sub_domain;

    set = hdr_len = sub_domain = ~0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "sd %d", &sub_domain)) {
            ;
        } else if (unformat (input, "set %d", &set)) {
            ;
        } else if (unformat (input, "bsl %d", &hdr_len)) {
            ;
        }
        else
        {
            error = unformat_parse_error (input);
            goto done;
        }
    }

    if (NULL == bier_bift_table)
    {
        vlib_cli_output(vm, "no BIFT entries");
        goto done;
    }

    if (~0 == set)
    {
        u32 ii;

        for (ii = 0; ii < BIER_BIFT_N_ENTRIES; ii++)
        {
            if (!dpo_is_drop(&bier_bift_table->bblt_dpos[ii]))
            {
                bier_hdr_len_id_t bsl;

                bier_bift_id_decode(ii, &set, &sub_domain, &bsl);

                vlib_cli_output(vm, "set: %d, sub-domain:%d, BSL:%U",
                                set, sub_domain,
                                format_bier_hdr_len_id, bsl);
                vlib_cli_output(vm, "  %U",
                                format_dpo_id,
                                &bier_bift_table->bblt_dpos[ii], 0);
            }
        }
    }
    else
    {
        bier_bift_id_t id;

        id = bier_bift_id_encode(set, sub_domain,
                                 bier_hdr_bit_len_to_id(hdr_len));

        if (!dpo_is_drop(&bier_bift_table->bblt_dpos[id]))
        {
            vlib_cli_output(vm, "set: %d, sub-domain:%d, BSL:%U",
                            set, sub_domain,
                            format_bier_hdr_len_id, hdr_len);
            vlib_cli_output(vm, "  %U",
                            format_dpo_id,
                            &bier_bift_table->bblt_dpos[id], 0);
        }
    }
done:
    return (error);
}

VLIB_CLI_COMMAND (show_bier_bift_command, static) = {
    .path = "show bier bift",
    .short_help = "show bier bift [set <value>] [sd <value>] [bsl <value>]",
    .function = show_bier_bift_cmd,
};
