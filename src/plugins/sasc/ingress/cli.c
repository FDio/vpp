// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include "ingress.h"
#include <vnet/plugin/plugin.h>
#include <vnet/fib/fib_table.h>
#include <vnet/vnet.h>

/*
 *  set sasc ingress interface <interface> tenant <tenant-id>
 */
static clib_error_t *
sasc_interface_input_enable_command_fn(vlib_main_t *vm, unformat_input_t *input,
                                       vlib_cli_command_t *cmd) {
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
