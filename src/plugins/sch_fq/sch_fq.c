#include "sch_fq.h"

sch_fq_buffer_t *fq_buffer;

static clib_error_t* sch_fq_enable_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    u32 interface_index = ~0;
    if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (!(unformat(input, "%d", &interface_index)))
            return clib_error_return(0, "unknown input '%U'", format_unformat_error, input);
    }
    if (interface_index == ~0)
        return clib_error_return(0, "need an interface index", format_unformat_error);
    vnet_feature_enable_disable ("interface-output", "sch_fq_enqueue_node", interface_index, 1, 0, 0);
    vnet_feature_enable_disable ("interface-output", "sch_fq_dequeue_node", interface_index, 1, 0, 0);
    return(NULL);
}

VLIB_CLI_COMMAND (sch_fq, static) = {
    .path = "set sch_fq",
    .short_help = "set sch_fq [interface-name] [quantum size]",
    .function = sch_fq_enable_command_fn,
};

VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Fair Queuing scheduling",
};

static clib_error_t* sch_fq_init (vlib_main_t *vm) {

    sch_fq_buffer_t *fq_b;
    vec_validate_aligned (fq_buffer, clib_max(1, vlib_num_workers()), CLIB_CACHE_LINE_BYTES);
    vec_foreach (fq_b, fq_buffer) {
        clib_bitmap_vec_validate (fq_b->class_bitmap, MAX_CLASS);
        for (int i = 0; i < MAX_CLASS; i++) {
            init_ring_buffer(&(fq_b->queue_map[i]));
            fq_b->num_round = 0;
        }
    }
    return NULL;
}

VLIB_INIT_FUNCTION (sch_fq_init);