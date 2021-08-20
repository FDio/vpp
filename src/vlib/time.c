/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

/* Virtual time allows to adjust VPP clock by arbitrary amount of time.
 * It is done such that the order of timer expirations is maintained,
 * and if a timer expiration callback reschedule another timer, this
 * timer will also properly expire in the right order. IOW, the order
 * of events is preserved.
 *
 * When moving time forward, each VPP thread (main and workers) runs an
 * instance of the input node 'virtual-time-input' below. This node is
 * responsible of advancing its own VPP thread clock to the next timer
 * expiration.  IOW each thread will move its clock independently one
 * timer at a time. This also means that while moving time forward, each
 * thread might not have the exact same view of what 'now' means. Once
 * the main thread has finished moving its time forward, the worker thread
 * barrier will ensure the timer between main and workers is synchronized.
 *
 * Using an input node in poll-mode has several advantages, including
 * preventing 'unix-epoll-input' to sleep (as it will not sleep if at
 * least one polling node is active). */

#include <vlib/vlib.h>
#include <vlib/time.h>

static f64 vlib_time_virtual_stop;

static uword
vlib_time_virtual_input (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame)
{
  const f64 next = vlib_time_get_next_timer (vm);
  /* each thread will advance its own time. In case a thread is much faster
   * than another, we must make sure it does not run away... */
  if (vlib_time_now (vm) + next > vlib_time_virtual_stop)
    vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_DISABLED);
  else
    vlib_time_adjust (vm, next);
  return 0;
}

VLIB_REGISTER_NODE (vlib_time_virtual_input_node) = {
  .function = vlib_time_virtual_input,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "virtual-time-input",
  .state = VLIB_NODE_STATE_DISABLED,
};

static clib_error_t *
vlib_time_virtual_adjust_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  f64 val;

  if (!unformat (input, "%f", &val))
    return clib_error_create ("unknown input `%U'", format_unformat_error,
			      input);

  vlib_time_virtual_stop = vlib_time_now (vm) + val;

  foreach_vlib_main ()
    vlib_node_set_state (this_vlib_main, vlib_time_virtual_input_node.index,
			 VLIB_NODE_STATE_POLLING);

  vlib_worker_thread_barrier_release (vm);
  while ((val = vlib_process_wait_for_event_or_clock (vm, val)) >= 0.001)
    ;
  /* this barrier sync will resynchronize all the clocks, so even if the main
   * thread was faster than some workers, this will make sure the workers will
   * disable their virtual-time-input node on their next iteration (as stop
   * time is reached). If a worker is too slow, there is a slight chance
   * several of its timers expire at the same time at this point. Time will
   * tell... */
  vlib_worker_thread_barrier_sync (vm);
  return 0;
}

VLIB_CLI_COMMAND (vlib_time_virtual_command) = {
  .path = "set clock adjust",
  .short_help = "set clock adjust <nn>",
  .function = vlib_time_virtual_adjust_command_fn,
};
