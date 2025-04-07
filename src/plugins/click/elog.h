
#ifndef __click_elog_h__
#define __click_elog_h__

#include <vlib/vlib.h>

#define CLICK_EVENT_LOGGING 1

static_always_inline void
click_elog_sched_before (vlib_node_runtime_t *node, u32 thread_index)
{
  if (CLICK_EVENT_LOGGING)
    {
      vlib_worker_thread_t *w = vlib_worker_threads + thread_index;
      ELOG_TYPE_DECLARE (e) = {
	.format = "click[%u]: sched-before dispatch-reason %s",
	.format_args = "i2t1",
	.enum_strings = vlib_node_dispatch_reason_enum_strings,
	.n_enum_strings = VLIB_NODE_DISPATCH_N_REASON,
      };

      struct
      {
	u16 thread_index;
	u8 dispatch_reason;
      } __clib_packed *ed = 0;

      ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, w->elog_track);
      ed->thread_index = thread_index;
      ed->dispatch_reason = node->dispatch_reason;
    }
}

static_always_inline void
click_elog_sched_after (u32 thread_index, f64 next_run)
{
  if (CLICK_EVENT_LOGGING)
    {
      vlib_worker_thread_t *w = vlib_worker_threads + thread_index;
      ELOG_TYPE_DECLARE (e) = {
	.format = "click[%u]: sched-after next-run %.06f",
	.format_args = "i2f8",
      };

      struct
      {
	u16 thread_index;
	f64 next_run;
      } __clib_packed *ed = 0;

      ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, w->elog_track);
      ed->thread_index = thread_index;
      ed->next_run = next_run;
    }
}

static_always_inline void
click_elog_pkt_alloc (u16 thread_index, u16 n_pkts)
{
  if (CLICK_EVENT_LOGGING)
    {
      vlib_worker_thread_t *w = vlib_worker_threads + thread_index;
      ELOG_TYPE_DECLARE (e) = {
	.format = "click[%u]: pkt_alloc %u",
	.format_args = "i2i2",
      };

      struct
      {
	u16 thread_index;
	u16 n_pkts;
      } __clib_packed *ed = 0;

      ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, w->elog_track);
      ed->thread_index = thread_index;
      ed->n_pkts = n_pkts;
    }
}

static_always_inline void
click_elog_pkt_free (u16 thread_index, u16 n_pkts)
{
  if (CLICK_EVENT_LOGGING)
    {
      vlib_worker_thread_t *w = vlib_worker_threads + thread_index;
      ELOG_TYPE_DECLARE (e) = {
	.format = "click[%u]: pkt_free %u",
	.format_args = "i2i2",
      };

      struct
      {
	u16 thread_index;
	u16 n_pkts;
      } __clib_packed *ed = 0;

      ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, w->elog_track);
      ed->thread_index = thread_index;
      ed->n_pkts = n_pkts;
    }
}

#endif /* __click_elog_h__ */
