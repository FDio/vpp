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

#include <vnet/plugin/plugin.h>
#include <vnet/api_errno.h>
#include <portmirroring/portmirroring.h>
#include <vpp/app/version.h>

int
pm_conf(u8 dst_interface, u8 is_del)
{
    pm_main_t * pm = &pm_main;

    if (is_del == 0)
    {
        if (dst_interface == 0xff)
            pm->sw_if_index = ~0;
        else
            pm->sw_if_index = dst_interface;

        pm->next_node_index = PM_IN_HIT_NEXT_ETHERNET_INPUT;
    } else {
        pm->sw_if_index = ~0;
        pm->next_node_index = ~0;
    }

    return 0;
}

static clib_error_t *
set_pm_command_fn(vlib_main_t * vm,
    unformat_input_t * input, vlib_cli_command_t * cmd)
{
    pm_main_t * pm = &pm_main;
    int enable_disable = 1;
    int sw_if_index = ~0;

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "to %U", unformat_vnet_sw_interface,
            pm->vnet_main, &sw_if_index))
            ;
        else if (unformat(input, "del"))
            enable_disable = 0;
        else if (unformat(input, "disable"))
            enable_disable = 0;
        else
            break;
    }

    if (sw_if_index == ~0)
        return clib_error_return(0, "mirror interface required");


    if (enable_disable)
    {
        if (sw_if_index != ~0)
            pm->sw_if_index = sw_if_index;
        return 0;
    } else   {
        pm->sw_if_index = ~0;
    }


    return 0;
}

VLIB_CLI_COMMAND(set_pm_command, static) = {
    .path = "set pm to",
    .short_help = "set pm to <intfc> [del]",
    .function = set_pm_command_fn,
};


static clib_error_t *
pm_init (vlib_main_t * vm)
{
    pm_main_t * pm = &pm_main;

    pm->sw_if_index = ~0;

    pm->pm_hit_node_index = pm_hit_node.index;

    /* portmirroring next node */
    pm->interface_output_node_index = vlib_get_node_by_name(vm, (u8 *) "interface-output")->index;

    return 0;
}

VLIB_INIT_FUNCTION(pm_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "portmirroring",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
