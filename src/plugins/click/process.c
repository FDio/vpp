
#include <vlib/vlib.h>
#include <click/click.h>
#include <click/vppclick.h>

static uword
click_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  click_main_t *cm = &click_main;
  click_instance_t *ci;
  uword *event_data = 0, event_type;
  int enabled = 0;
  f64 last_run_duration = 0;
  f64 last_periodic_time = 0;

  while (1)
    {
      if (enabled)
	vlib_process_wait_for_event_or_clock (vm, 1e-3 - last_run_duration);
      else
	vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	case ~0:
	  last_periodic_time = vlib_time_now (vm);
	  break;
	case CLICK_PROCESS_EVENT_START:
	  enabled = 1;
	  break;
	case CLICK_PROCESS_EVENT_STOP:
	  enabled = 0;
	  break;

	default:
	  ASSERT (0);
	}

      vec_reset_length (event_data);

      if (enabled == 0)
	continue;

      pool_foreach (ci, cm->instances)
	foreach_vlib_main ()
	  vlib_node_set_interrupt_pending (this_vlib_main,
					   ci->input_node_index);
      last_run_duration = vlib_time_now (vm) - last_periodic_time;
    }
  return 0;
}

VLIB_REGISTER_NODE (click_process_node) = {
  .function = click_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "click-process",
};
