/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#if DPDK==1
#include <vnet/span/span.h>

vlib_buffer_t *
span_duplicate_buffer (vlib_main_t * vm,
        vlib_buffer_t * b0,
        uword span_if_index,
        u8 copy)
{
    vlib_buffer_t * c0 = 0;
    struct rte_mbuf * clone0 = 0;

    /*
     * Copy buffer for now, clone is not enough because incomming buffer
     * can be changed before it goes out of SPAN interface.
     */
    if (copy) {
        clone0 = dpdk_replicate_packet_mb(b0);
    } else {
        clone0 = dpdk_zerocopy_replicate_packet_mb(b0);
    }

    c0 = vlib_buffer_from_rte_mbuf (clone0);

    c0->current_data   = b0->current_data;
    c0->current_length = b0->current_length;
    c0->flags          = b0->flags | VLIB_NODE_FLAG_IS_SPAN;
    c0->trace_index    = b0->trace_index;

    vnet_buffer(c0)->sw_if_index[VLIB_TX] = span_if_index;
    vnet_buffer(c0)->sw_if_index[VLIB_RX] = vnet_buffer(b0)->sw_if_index[VLIB_RX];
    vnet_buffer(c0)->l2                   = vnet_buffer(b0)->l2;

    return c0;
}

clib_error_t *
set_span_add_delete_entry (vlib_main_t * vm,
        u32 src_sw_if_index,
        u32 dst_sw_if_index,
        u8 disable)
{
    span_main_t * sm = &span_main;

    if (src_sw_if_index == ~0)
        return clib_error_return (0, "Source interface must be set...");
    if (dst_sw_if_index == ~0 && !disable)
        return clib_error_return (0, "Destination interface must be set...");
    if (src_sw_if_index == dst_sw_if_index)
            return clib_error_return (0, "Source interface must be different to Destination interface");

    uword *p = hash_get (sm->dst_sw_if_index_by_src, src_sw_if_index);
    if (p != 0 && !disable)
        return clib_error_return (0, "Source interface is already mirrored to interface index %d", p[0]);
    if (p == 0 && disable)
        return clib_error_return (0, "Source interface is not mirrored");
    if (!disable)
        hash_set(sm->dst_sw_if_index_by_src, src_sw_if_index, dst_sw_if_index);
    else
        hash_unset(sm->dst_sw_if_index_by_src, src_sw_if_index);

    u32 node_index = disable ? ~0 : span_node.index;
    int rv = vnet_hw_interface_rx_redirect_to_node (sm->vnet_main,
            src_sw_if_index, node_index);

    if (rv != 0)
        return clib_error_return (0, "vnet_hw_interface_rx_redirect_to_node"
                " returned %d", rv);

    span_out_register_node (vm,
            src_sw_if_index,
            dst_sw_if_index,
            disable);

    return 0;
}

static clib_error_t *
set_span_command_fn (vlib_main_t * vm,
        unformat_input_t * input,
        vlib_cli_command_t * cmd)
{
    span_main_t * sm = &span_main;
    u32 src_sw_if_index = ~0;
    u32 dst_sw_if_index = ~0;
    u8 disable = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "src %U", unformat_vnet_sw_interface,
                    sm->vnet_main, &src_sw_if_index))
            ;
        else if (unformat (input, "dst %U", unformat_vnet_sw_interface,
                    sm->vnet_main, &dst_sw_if_index))
            ;
        else if (unformat (input, "disable"))
            disable = 1;
        else
            break;
    }

    return set_span_add_delete_entry (vm, src_sw_if_index, dst_sw_if_index, disable);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_span_command, static) = {
    .path = "set span",
    .short_help =
    "set span src <interface-name> dst <interface-name> [disable]",
    .function = set_span_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_span_command_fn (vlib_main_t * vm,
        unformat_input_t * input,
        vlib_cli_command_t * cmd)
{
    span_main_t * sm = &span_main;
    vnet_main_t * vnm = &vnet_main;
    u32 src_sw_if_index = ~0, dst_sw_if_index = ~0;

    /* *INDENT-OFF* */
    vlib_cli_output (vm, "SPAN source interface to destination interface table");
    hash_foreach (src_sw_if_index, dst_sw_if_index, sm->dst_sw_if_index_by_src, ({
        vlib_cli_output (vm, "%32U => %-32U",
                format_vnet_sw_if_index_name, vnm, src_sw_if_index,
                format_vnet_sw_if_index_name, vnm, dst_sw_if_index);
    }));
    /* *INDENT-ON* */
    return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_span_command, static) = {
    .path = "show span",
    .short_help =
    "Shows SPAN mirror table",
    .function = show_span_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
span_init (vlib_main_t * vm)
{
    span_main_t * sm = &span_main;

    sm->dst_sw_if_index_by_src = hash_create(0, sizeof (u32));

    sm->vlib_main = vm;
    sm->vnet_main = vnet_get_main();
    return 0;
}

VLIB_INIT_FUNCTION(span_init);
#else

static clib_error_t *
span_init (vlib_main_t * vm)
{
    return 0;
}

VLIB_INIT_FUNCTION(span_init);

#endif /* DPDK */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
