// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include "ingress.h"
#include <vnet/plugin/plugin.h>
#include <vnet/fib/fib_table.h>
#include <vnet/vnet.h>
#include <sasc/sasc.h>

/*
 *  set sasc ingress interface <interface> tenant <tenant-id>
 */
static clib_error_t *
sasc_interface_input_enable_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    unformat_input_t line_input_, *line_input = &line_input_;
    clib_error_t *err = 0;
    u32 sw_if_index = ~0, tenant_id = ~0;
    bool output_arc = false;

    if (!unformat_user(input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(line_input, "%U", unformat_vnet_sw_interface, vnet_get_main(), &sw_if_index))
            ;
        else if (unformat(line_input, "tenant %d", &tenant_id))
            ;
        else if (unformat(line_input, "output"))
            output_arc = true;
        else {
            err = unformat_parse_error(line_input);
            goto done;
        }
    }
    if (sw_if_index == ~0 || tenant_id == ~0) {
        err = clib_error_return(0, "missing arguments");
        goto done;
    }
    int rv = sasc_interface_input_enable_disable(sw_if_index, tenant_id, output_arc, true);
    if (rv != 0) {
        err = clib_error_return(0, "could not enable interface");
    }

done:
    unformat_free(line_input);
    return err;
}

VLIB_CLI_COMMAND(sasc_interface_input_enable_command, static) = {
    .path = "set sasc ingress interface",
    .short_help = "set sasc ingress interface <interface> tenant <tenant-id> [output]",
    .function = sasc_interface_input_enable_command_fn,
};

/*
 * show sasc ingress interfaces
 */
static clib_error_t *
sasc_show_interfaces_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    sasc_ingress_main_t *sasc_ingress = &sasc_ingress_main;
    vnet_main_t *vnm = vnet_get_main();
    u32 sw_if_index;
    bool found_any = false;

    vlib_cli_output(vm, "SASC Enabled Interfaces:");
    vlib_cli_output(vm, "%-30s %-10s %-10s", "Interface", "Direction", "Tenant ID");
    vlib_cli_output(vm, "%-30s %-10s %-10s", "----------", "---------", "---------");

    // Check ingress (RX) interfaces
    if (sasc_ingress->tenant_idx_by_sw_if_idx[VLIB_RX]) {
        vec_foreach_index (sw_if_index, sasc_ingress->tenant_idx_by_sw_if_idx[VLIB_RX]) {
            u16 tenant_idx = vec_elt(sasc_ingress->tenant_idx_by_sw_if_idx[VLIB_RX], sw_if_index);

            if (tenant_idx == UINT16_MAX)
                continue; // Interface not configured for SASC

            found_any = true;

            u8 *interface_name = format(0, "%U", format_vnet_sw_if_index_name, vnm, sw_if_index);
            vlib_cli_output(vm, "%-30s %-10s %-10u", interface_name, "ingress", tenant_idx);
            vec_free(interface_name);
        }
    }

    // Check egress (TX) interfaces
    if (sasc_ingress->tenant_idx_by_sw_if_idx[VLIB_TX]) {
        vec_foreach_index (sw_if_index, sasc_ingress->tenant_idx_by_sw_if_idx[VLIB_TX]) {
            u16 tenant_idx = vec_elt(sasc_ingress->tenant_idx_by_sw_if_idx[VLIB_TX], sw_if_index);

            if (tenant_idx == UINT16_MAX)
                continue; // Interface not configured for SASC

            found_any = true;

            u8 *interface_name = format(0, "%U", format_vnet_sw_if_index_name, vnm, sw_if_index);
            vlib_cli_output(vm, "%-30s %-10s %-10u", interface_name, "egress", tenant_idx);
            vec_free(interface_name);
        }
    }

    if (!found_any) {
        vlib_cli_output(vm, "No interfaces have SASC enabled.");
    }

    return 0;
}

VLIB_CLI_COMMAND(sasc_show_interfaces_command, static) = {
    .path = "show sasc ingress interfaces",
    .short_help = "show sasc ingress interfaces",
    .function = sasc_show_interfaces_command_fn,
};
