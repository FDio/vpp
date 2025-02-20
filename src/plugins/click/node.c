
#include <vlib/vlib.h>
#include <click/click.h>
#include <vnet/vnet.h>

#define foreach_click_node_counter                                            \
  _ (NO_QUEUE, no_queue, ERROR, "no queue for interface and thread")          \
  _ (QUEUE_FULL, queue_full, ERROR, "queue full")

typedef enum
{
#define _(f, n, s, d) CLICK_NODE_COUNTER_##f,
  foreach_click_node_counter
#undef _
} click_node_counter_t;

static vlib_error_desc_t click_node_counters[] = {
#define _(f, n, s, d)                                                         \
  [CLICK_NODE_COUNTER_##                                                      \
    f] = { .name = #n, .desc = (d), .severity = VL_COUNTER_SEVERITY_##s },
  foreach_click_node_counter
#undef _
};

VLIB_NODE_FN (click_sched_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t __clib_unused *frame)
{
  click_node_runtime_t *rt = click_get_node_rt (node);
  u32 n_rx_packets = 0;
  u16 thread_index = vm->thread_index;
  f64 t;

  click_elog_sched_before (vm, node, thread_index);
  t = vppclick_run (rt->ctx, thread_index);
  click_elog_sched_after (vm, node, thread_index, t);

  if (t == 0)
    vlib_node_set_interrupt_pending (vm, node->node_index);
  else if (t > 0)
    vlib_node_schedule (vm, node->node_index, t != 0 ? t : 1e-3);

  return n_rx_packets;
}

VLIB_NODE_FN (click_node)
(vlib_main_t *vm, vlib_node_runtime_t __clib_unused *node, vlib_frame_t *frame)
{
  click_main_t *cm = &click_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 drop[VLIB_FRAME_SIZE], n_drop = 0, n_no_queue = 0, n_queue_full = 0;
  u32 ti = vm->thread_index;
  u32 buffer_size = vlib_buffer_get_default_data_size (vm);

  while (n_left)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[0]);
      u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      click_interface_t *ci = vec_elt_at_index (cm->interfaces, sw_if_index);
      click_from_vpp_queue_t *cfq;
      vppclick_pkt_queue_t *q;
      vppclick_pkt_t *p;

      if (ci->from_vpp == 0 || ci->from_vpp[ti].queue == 0)
	{
	  drop[n_drop++] = from[0];
	  n_no_queue++;
	  goto next;
	}
      cfq = ci->from_vpp + ti;
      q = cfq->queue;

      if (q->n_packets == q->queue_size)
	{
	  drop[n_drop++] = from[0];
	  n_queue_full++;
	  goto next;
	}

      p = q->packets + q->n_packets++;
      p->buffer_index = from[0];
      p->data = b->data + b->current_data;
      p->size = b->current_length;
      p->headroom = sizeof (b->pre_data) + b->current_data;
      p->tailroom = buffer_size - (b->current_data + b->current_length);

      if (vm->main_loop_count != cfq->last_vm_loop_count)
	{
	  vec_add1 (
	    cm->instances[ci->instance_index].threads[ti].reschedule_elts,
	    cfq->elt);
	  cfq->last_vm_loop_count = vm->main_loop_count;
	}

    next:
      from++;
      n_left--;
    }

  if (n_drop)
    {
      vlib_buffer_free (vm, drop, n_drop);
      if (n_no_queue)
	vlib_node_increment_counter (vm, click_node.index,
				     CLICK_NODE_COUNTER_NO_QUEUE, n_no_queue);
      if (n_queue_full)
	vlib_node_increment_counter (
	  vm, click_node.index, CLICK_NODE_COUNTER_QUEUE_FULL, n_queue_full);
    }

  return frame->n_vectors - n_drop;
}

VLIB_REGISTER_NODE (click_node) = {
  .name = "click",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,

  /* counters */
  .n_errors = ARRAY_LEN(click_node_counters),
  .error_counters = click_node_counters,

  /* next nodes */
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
