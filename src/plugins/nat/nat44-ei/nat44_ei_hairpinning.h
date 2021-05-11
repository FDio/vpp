#ifndef __included_nat44_ei_hairpinning_h__
#define __included_nat44_ei_hairpinning_h__

#include <nat/nat44-ei/nat44_ei.h>

#define foreach_nat44_ei_hairpinning_handoff_error                            \
  _ (CONGESTION_DROP, "congestion drop")

typedef enum
{
#define _(sym, str) NAT44_EI_HAIRPINNING_HANDOFF_ERROR_##sym,
  foreach_nat44_ei_hairpinning_handoff_error
#undef _
    NAT44_EI_HAIRPINNING_HANDOFF_N_ERROR,
} nat44_ei_hairpinning_handoff_error_t;

static char *nat44_ei_hairpinning_handoff_error_strings[] = {
#define _(sym, string) string,
  foreach_nat44_ei_hairpinning_handoff_error
#undef _
};

typedef struct
{
  u32 next_worker_index;
} nat44_ei_hairpinning_handoff_trace_t;

static u8 *
format_nat44_ei_hairpinning_handoff_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat44_ei_hairpinning_handoff_trace_t *t =
    va_arg (*args, nat44_ei_hairpinning_handoff_trace_t *);

  s = format (s, "nat44-ei-hairpinning-handoff: next-worker %d",
	      t->next_worker_index);

  return s;
}

always_inline uword
nat44_ei_hairpinning_handoff_fn_inline (vlib_main_t *vm,
					vlib_node_runtime_t *node,
					vlib_frame_t *frame, u32 fq_index)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 n_enq, n_left_from, *from;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  while (n_left_from > 0)
    {
      ti[0] = vnet_buffer (b[0])->snat.required_thread_index;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nat44_ei_hairpinning_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->next_worker_index = ti[0];
	}

      n_left_from -= 1;
      ti += 1;
      b += 1;
    }
  n_enq = vlib_buffer_enqueue_to_thread (vm, node, fq_index, from,
					 thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (
      vm, node->node_index, NAT44_EI_HAIRPINNING_HANDOFF_ERROR_CONGESTION_DROP,
      frame->n_vectors - n_enq);
  return frame->n_vectors;
}

#endif // __included_nat44_ei_hairpinning_h__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
