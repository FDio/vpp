#include "sch_qfq.h"

sch_qfq_buffer_t *qfq_buffer;

static clib_error_t* sch_qfq_enable_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    u32 interface_index = ~0;
    if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (!(unformat(input, "%d", &interface_index)))
            return clib_error_return(0, "unknown input '%U'", format_unformat_error, input);
    }
    if (interface_index == ~0)
        return clib_error_return(0, "need an interface index", format_unformat_error);
    vnet_feature_enable_disable ("interface-output", "sch_qfq_enqueue_node", interface_index, 1, 0, 0);
    vnet_feature_enable_disable ("interface-output", "sch_qfq_dequeue_node", interface_index, 1, 0, 0);
    return(NULL);
}

VLIB_CLI_COMMAND (sch_qfq, static) = {
    .path = "set sch_qfq",
    .short_help = "set sch_qfq [interface-name] [quantum size]",
    .function = sch_qfq_enable_command_fn,
};

VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Quick Fair Queuing scheduling",
};

static clib_error_t* sch_qfq_init (vlib_main_t *vm) {

    sch_qfq_buffer_t *qfq_b;
    vec_validate_aligned (qfq_buffer, clib_max(1, vlib_num_workers()), CLIB_CACHE_LINE_BYTES);
    vec_foreach(qfq_b, qfq_buffer) {
        clib_bitmap_vec_validate(qfq_b->state_bitmaps[ER], MAX_CLASS);
        clib_bitmap_vec_validate(qfq_b->state_bitmaps[EB], MAX_CLASS);
        clib_bitmap_vec_validate(qfq_b->state_bitmaps[IR], MAX_CLASS);
        clib_bitmap_vec_validate(qfq_b->state_bitmaps[IB], MAX_CLASS);
        clib_bitmap_vec_validate(qfq_b->state_bitmaps[IDLE], MAX_CLASS);
        clib_bitmap_vec_validate(qfq_b->tool_bitmap, MAX_CLASS);
        for (int i = 0; i < MAX_CLASS; i++) {
            init_ring_buffer(&(qfq_b->flow_map[i].pkt_queue));
            qfq_b->flow_map[i].prev_flow = NULL;
            qfq_b->flow_map[i].lmax = 0;
            qfq_b->flow_map[i].finish_time = 0;
            qfq_b->flow_map[i].lmax = 0;
        }
        for (int i = 0; i < MAX_GROUP; i++) {
            qfq_b->group_map[i].approx_finish_time = 0;
            qfq_b->group_map[i].slot_size = pow(2,i);
            clib_bitmap_vec_validate(qfq_b->group_map[i].bucket_bitmap, MAX_BUCKET);
        }
        qfq_b->virtual_time = 0;
    }
    return NULL;
}

VLIB_INIT_FUNCTION (sch_qfq_init);