/*
 * Copyright (c) 2016 Qosmos and/or its affiliates.
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
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/dlist.h>
#include <vppinfra/pool.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vpp/app/version.h>

#include "flowtable.h"
#include <vnet/plugin/plugin.h>

flowtable_main_t flowtable_main;

int
flowtable_enable_disable(flowtable_main_t * fm,
    u32 sw_if_index, int enable_disable)
{
    u32 node_index = enable_disable ? flowtable_node.index : ~0;

    return vnet_hw_interface_rx_redirect_to_node(fm->vnet_main,
            sw_if_index, node_index);
}

static clib_error_t *
flowtable_enable_disable_command_fn(vlib_main_t * vm,
    unformat_input_t * input, vlib_cli_command_t * cmd)
{
    flowtable_main_t * fm = &flowtable_main;
    u32 sw_if_index = ~0;
    int enable_disable = 1;
    u32 next_node_index = ~0;

    int rv;

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "disable"))
            enable_disable = 0;
        else if (unformat(input, "next-node %U", unformat_vlib_node,
                    fm->vnet_main, &next_node_index))
            ;
        else if (unformat(input, "%U", unformat_vnet_sw_interface,
            fm->vnet_main, &sw_if_index))
            ;
        else
            break;
    }

    if (sw_if_index == ~0)
        return clib_error_return(0, "No Interface specified");

    /* by default, leave the packet follow its course */
    if (next_node_index != ~0)
        fm->next_node_index = next_node_index;
    else
        fm->next_node_index = FT_NEXT_ETHERNET_INPUT;

    rv = flowtable_enable_disable(fm, sw_if_index, enable_disable);
    switch (rv) {
      case 0:
          break;
      case VNET_API_ERROR_INVALID_SW_IF_INDEX:
          return clib_error_return(0, "Invalid interface");
      case VNET_API_ERROR_UNIMPLEMENTED:
          return clib_error_return(0,
                "Device driver doesn't support redirection");
      default:
          return clib_error_return(0, "flowtable_enable_disable returned %d",
                rv);
    }

    return 0;
}

VLIB_CLI_COMMAND(flowtable_interface_enable_disable_command) = {
    .path = "flowtable",
    .short_help = "flowtable <interface> [next-node <name>] [disable]",
    .function = flowtable_enable_disable_command_fn,
};

static clib_error_t *
flowtable_init(vlib_main_t * vm)
{
    int i;
    clib_error_t * error = 0;
    flowtable_main_t * fm = &flowtable_main;

    fm->flowtable_index = flowtable_node.index;

    /* ensures flow_info structure fits into vlib_buffer_t's opaque 1 field */
    ASSERT(sizeof(flow_data_t) <= sizeof(u32) * 8);

    /* init flow pool
     * TODO get flow count from configuration */
    pool_alloc_aligned(fm->flows, FM_POOL_COUNT, CLIB_CACHE_LINE_BYTES);

    /* init hashtable */
    fm->flows_cpt = 0;
    pool_alloc(fm->ht_lines, 2 * FM_POOL_COUNT);
    BV(clib_bihash_init) (&fm->flows_ht, "flow hash table",
            FM_NUM_BUCKETS, FM_MEMORY_SIZE);

    /* init timer wheel */
    fm->time_index = ~0;
    for (i = 0; i < TIMER_MAX_LIFETIME ; i++) {
        dlist_elt_t * timer_slot;
        pool_get(fm->timers, timer_slot);

        u32 timer_slot_head_index = timer_slot - fm->timers;
        clib_dlist_init (fm->timers, timer_slot_head_index);
        vec_add1(fm->timer_wheel, timer_slot_head_index);
    }

    return error;
}

VLIB_INIT_FUNCTION(flowtable_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Flowtable",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
