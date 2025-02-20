
#include <vlib/vlib.h>
#include <click/click.h>

#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

VLIB_NODE_FN (click_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  click_node_runtime_t *rt = click_get_node_rt (node);
  u32 n_rx_packets = 0;
  u16 thread_index = vm->thread_index;
  f64 t;

  click_elog_sched_before (node, thread_index);
  t = vppclick_run (rt->ctx, thread_index);
  click_elog_sched_after (thread_index, t);

  if (t)
    vlib_node_schedule (vm, node->node_index, t);
  return n_rx_packets;
}

VLIB_NODE_FN (click_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx_packets = 0;
  return n_rx_packets;
}
