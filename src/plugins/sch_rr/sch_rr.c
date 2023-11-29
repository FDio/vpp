/* Copyright (c) 2023 Cisco and/or its affiliates.
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
 * limitations under the License. */

#include "sch_rr.h"

sch_rr_buffer_t *rr_buffer;

static clib_error_t* sch_rr_enable_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    u32 interface_index = ~0;
    if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (!(unformat(input, "%d", &interface_index)))
            return clib_error_return(0, "unknown input '%U'", format_unformat_error, input);
    }
    if (interface_index == ~0)
        return clib_error_return(0, "need an interface index", format_unformat_error);
    vnet_feature_enable_disable ("interface-output", "sch_rr_enqueue_node", interface_index, 1, 0, 0);
    vnet_feature_enable_disable ("interface-output", "sch_rr_dequeue_node", interface_index, 1, 0, 0);
    return(NULL);
}

VLIB_CLI_COMMAND (sch_rr, static) = {
    .path = "set sch_rr",
    .short_help = "set sch_rr [interface-name]",
    .function = sch_rr_enable_command_fn,
};

VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Round Robin scheduling",
};

static clib_error_t* sch_rr_init (vlib_main_t *vm) {

    sch_rr_buffer_t *rr_b;
    vec_validate_aligned (rr_buffer, clib_max(1, vlib_num_workers()), CLIB_CACHE_LINE_BYTES);
    vec_foreach (rr_b, rr_buffer) {
        clib_bitmap_vec_validate (rr_b->class_bitmap, MAX_CLASS);
        for (int i = 0; i < MAX_CLASS; i++)
            init_ring_buffer(&(rr_b->queue_map[i]));
    }
    return NULL;
}

VLIB_INIT_FUNCTION (sch_rr_init);