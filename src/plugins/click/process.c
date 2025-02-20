
#include <vlib/vlib.h>
#include <click/click.h>
#include <click/vppclick.h>

static uword
click_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  click_main_t *cm = &click_main;
  click_instance_t *ci;
  uword *event_data = 0, event_type;
  int i, enabled = 0;
  f64 next_run_time = 0;

  while (1)
    {
      f64 now = vlib_time_now (vm);

      if (enabled)
	{
	  if (next_run_time > now)
	    vlib_process_wait_for_event_or_clock (vm, next_run_time - now);
	}
      else
	vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	case ~0:
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

      next_run_time = now + 1;

      pool_foreach (ci, cm->instances)
	{
	  vec_foreach_index (i, ci->next_run_time)
	    {
	      if (now >= ci->next_run_time[i])
		vlib_node_set_interrupt_pending (vlib_get_main_by_index (i),
						 ci->input_node_index);
	      else if (ci->next_run_time[i] <= next_run_time)
		next_run_time = ci->next_run_time[i];
	    }
	}
    }

  vec_free (event_data);
  return 0;
}

VLIB_REGISTER_NODE (click_process_node) = {
  .function = click_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .state = VLIB_NODE_STATE_DISABLED,
  .name = "click-process",
};
