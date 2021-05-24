/*
 * Copyright (c) 2021 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <limits.h>
#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/buffer.h>
#include <vnet/scheduler/scheduler.h>

#define foreach_scheduler_errors                                              \
  _ (DISTRIBUTE, "distributed packets received")                              \
  _ (AGGREGATE, "aggregated packets received")

typedef enum
{
#define _(sym, str) VNET_SCHEDULER_ERROR_##sym,
  foreach_scheduler_errors
#undef _
    VNET_SCHEDULER_N_ERROR,
} vnet_scheduler_error_t;

static char *vnet_scheduler_error_strings[] = {
#define _(sym, string) string,
  foreach_scheduler_errors
#undef _
};

typedef struct
{
  vnet_scheduler_event_type_t t;
  u16 next;
} scheduler_dispatch_trace_t;

static u8 *
format_scheduler_dispatch_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  scheduler_dispatch_trace_t *t = va_arg (*args, scheduler_dispatch_trace_t *);

  s = format (s, "Type: %s Next: %u",
	      t->t == VNET_SCHEDULER_EVENT_DISTRIBUTE ? "distributed" :
							"aggregated",
	      t->next);
  return s;
}

static_always_inline void
vnet_scheduler_add_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_buffer_t *buffer, vnet_scheduler_event_type_t t,
			  u16 next_node)
{
  scheduler_dispatch_trace_t *tr =
    vlib_add_trace (vm, node, buffer, sizeof (*tr));
  tr->t = t;
  tr->next = next_node;
}

static_always_inline u32
vnet_scheduler_dequeue_buffers (vlib_main_t *vm, vlib_node_runtime_t *node,
				const u8 is_worker)
{
  vnet_scheduler_main_t *sm = &scheduler_main;
  vlib_buffer_t *b0;
  u32 bis[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  u32 n, n_dispatched = 0;

  while (1)
    {
      if (is_worker)
	n = sm->dequeue_distribute_handler (vm, bis, nexts, VLIB_FRAME_SIZE);
      else
	n = sm->dequeue_aggregate_handler (vm, bis, nexts, VLIB_FRAME_SIZE);
      if (n == 0)
	{
	  if (is_worker)
	    sm->distribute_empty_poll[vm->thread_index]++;
	  else
	    sm->aggregate_empty_poll[vm->thread_index]++;
	  break;
	}

      b0 = vlib_get_buffer (vm, bis[0]);
      /* if first buffer has trace flag set, add trace */
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  vlib_buffer_t *bs[VLIB_FRAME_SIZE], **b = bs;
	  u32 *bi = bis + 1;
	  u16 *next = nexts;
	  u32 nt = n - 1;
	  const vnet_scheduler_event_type_t ev_type =
	    is_worker ? VNET_SCHEDULER_EVENT_DISTRIBUTE :
			VNET_SCHEDULER_EVENT_AGGREGATE;

	  vlib_get_buffers (vm, bi, bs, nt);
	  vnet_scheduler_add_trace (vm, node, b0, ev_type, next[0]);
	  next++;

	  while (nt--)
	    {
	      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
		vnet_scheduler_add_trace (vm, node, b[0], ev_type, next[0]);
	      b++;
	      next++;
	    }
	}

      if (is_worker)
	vlib_node_increment_counter (vm, node->node_index,
				     VNET_SCHEDULER_ERROR_DISTRIBUTE, n);
      else
	vlib_node_increment_counter (vm, node->node_index,
				     VNET_SCHEDULER_ERROR_AGGREGATE, n);
      vlib_buffer_enqueue_to_next (vm, node, bis, nexts, n);

      if (is_worker)
	sm->distribute_dequeued[vm->thread_index] += n;
      else
	sm->aggregate_dequeued[vm->thread_index] += n;

      n_dispatched += n;
    }
  return n_dispatched;
}

VLIB_NODE_FN (scheduler_dispatch_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_scheduler_main_t *sm = &scheduler_main;
  vnet_scheduler_per_thread_data_t *ptd =
    sm->per_thread_data + vm->thread_index;
  u32 n_dispatched = 0;

  if (PREDICT_FALSE (ptd->state_change_hint != 0))
    {
      u8 proposed_hint = ptd->state_change_hint;
      u32 new_hint;

      /* if changing a state is successful, the engine shall clear the
       * bit in return.
       */
      new_hint = sm->set_thread_state_handler (vm, proposed_hint);

      if (proposed_hint & VNET_SCHEDULER_THREAD_STATE_WORKER_ENABLE)
	{
	  if (new_hint & VNET_SCHEDULER_THREAD_STATE_WORKER_ENABLE)
	    ptd->thread_roles &= ~VNET_SCHEDULER_ROLE_MASK_WORKER; /* failed */
	  else
	    ptd->thread_roles |= VNET_SCHEDULER_ROLE_MASK_WORKER;
	}

      if (proposed_hint & VNET_SCHEDULER_THREAD_STATE_WORKER_DISABLE)
	{
	  if (new_hint & VNET_SCHEDULER_THREAD_STATE_WORKER_DISABLE)
	    ptd->thread_roles |= VNET_SCHEDULER_ROLE_MASK_WORKER; /* failed */
	  else
	    ptd->thread_roles &= ~VNET_SCHEDULER_ROLE_MASK_WORKER;
	}

      if (proposed_hint & VNET_SCHEDULER_THREAD_STATE_CONSUMER_ENABLE)
	{
	  if (new_hint & VNET_SCHEDULER_THREAD_STATE_CONSUMER_ENABLE)
	    ptd->thread_roles &=
	      ~VNET_SCHEDULER_ROLE_MASK_CONSUMER; /* failed */
	  else
	    ptd->thread_roles |= VNET_SCHEDULER_ROLE_MASK_CONSUMER;
	}

      if (proposed_hint & VNET_SCHEDULER_THREAD_STATE_CONSUMER_DISABLE)
	{
	  if (new_hint & VNET_SCHEDULER_THREAD_STATE_CONSUMER_DISABLE)
	    ptd->thread_roles |=
	      VNET_SCHEDULER_ROLE_MASK_CONSUMER; /* failed */
	  else
	    ptd->thread_roles &= ~VNET_SCHEDULER_ROLE_MASK_CONSUMER;
	}

      ptd->state_change_hint = new_hint;
    }

  if (ptd->thread_roles & VNET_SCHEDULER_ROLE_MASK_WORKER)
    {
      n_dispatched = vnet_scheduler_dequeue_buffers (vm, node, 1);
    }

  if (ptd->thread_roles & VNET_SCHEDULER_ROLE_MASK_CONSUMER)
    {
      n_dispatched = vnet_scheduler_dequeue_buffers (vm, node, 0);
    }

  if (ptd->thread_roles == 0)
    {
      /* disable the scheduler-dispatch since no role is assigned to it */
      vlib_node_set_state (vm, sm->dispatch_node_index,
			   VLIB_NODE_STATE_DISABLED);
    }

  return n_dispatched;
}

VLIB_REGISTER_NODE (scheduler_dispatch_node) = {
  .name = "scheduler-dispatch",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .format_trace = format_scheduler_dispatch_trace,

  .n_errors = ARRAY_LEN(vnet_scheduler_error_strings),
  .error_strings = vnet_scheduler_error_strings,

  .n_next_nodes = SCHEDULER_DISPATCH_N_NEXT,
  .next_nodes = {
#define _(n, s) [SCHEDULER_DISPATCH_NEXT_##n] = s,
      foreach_scheduler_dispatch_next
#undef _
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
