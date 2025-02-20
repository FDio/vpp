
#include <vlib/vlib.h>
#include <click/click.h>
#include <click/vppclick.h>

VLIB_NODE_FN (click_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  click_main_t *cm = &click_main;
  click_instance_t *inst;
  u32 n_rx_packets = 0;
  f64 now = vlib_time_now (vm);

  pool_foreach (inst, cm->instances)
    {
      if (now - inst->last_run < 1e-3)
	continue;

      vppclick_run (inst->ctx);
      inst->last_run = now;
      // fformat (stderr, "x\n");
    }
  return n_rx_packets;
}

VLIB_REGISTER_NODE (click_input_node) = {
  .name = "click-input",
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};
