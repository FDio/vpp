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

    if (src_sw_if_index == ~0)
        return clib_error_return (0, "Source interface must be set...");
    if (dst_sw_if_index == ~0 && !disable)
        return clib_error_return (0, "Destination interface must be set...");

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

    return 0;
}

VLIB_CLI_COMMAND (set_span_command, static) = {
    .path = "set span",
    .short_help = 
    "set span src <interface-name> dst <interface-name> [disable]",
    .function = set_span_command_fn,
};

static clib_error_t *
show_span_command_fn (vlib_main_t * vm,
        unformat_input_t * input,
        vlib_cli_command_t * cmd)
{
    span_main_t * sm = &span_main;
    vnet_main_t * vnm = &vnet_main;
    u32 src_sw_if_index = ~0, dst_sw_if_index = ~0;

    vlib_cli_output (vm, "SPAN source interface to destination interface table");
    hash_foreach (src_sw_if_index, dst_sw_if_index, sm->dst_sw_if_index_by_src, ({
        vlib_cli_output (vm, "%32U => %-32U",
                format_vnet_sw_if_index_name, vnm, src_sw_if_index,
                format_vnet_sw_if_index_name, vnm, dst_sw_if_index);
    }));
    return 0;
}


VLIB_CLI_COMMAND (show_span_command, static) = {
    .path = "show span",
    .short_help =
    "Shows SPAN mirror table",
    .function = show_span_command_fn,
};

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
#endif /* DPDK */

