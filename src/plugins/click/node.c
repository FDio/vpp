
#include <vlib/vlib.h>
#include <click/click.h>
#include <click/vppclick.h>

VLIB_NODE_FN (click_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  click_main_t *cm = &click_main;
  click_node_runtime_t *rt = click_get_node_rt (node);
  click_instance_t *ci = pool_elt_at_index (cm->instances, rt->instance_index);
  u32 n_rx_packets = 0;
  u16 thread_index = vm->thread_index;
  f64 t;

  t = vppclick_run (rt->ctx, thread_index);
  t += vlib_time_now (vm);

  ci->next_run_time[thread_index] = t;
  return n_rx_packets;
}

VLIB_NODE_FN (click_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx_packets = 0;
  return n_rx_packets;
}

