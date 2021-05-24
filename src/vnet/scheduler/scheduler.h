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

#ifndef included_vnet_scheduler_scheduler_h
#define included_vnet_scheduler_scheduler_h

#include <vlib/vlib.h>

/* SCHEDULER_DISPATCH_NEXT_ERR_DROP next index is publically known to
 * all user components to notify drop next
 */
#define foreach_scheduler_dispatch_next _ (ERR_DROP, "error-drop")

typedef enum
{
#define _(n, s) SCHEDULER_DISPATCH_NEXT_##n,
  foreach_scheduler_dispatch_next
#undef _
    SCHEDULER_DISPATCH_N_NEXT,
} scheduler_dispatch_next_t;

typedef enum
{
  VNET_SCHEDULER_EVENT_DISTRIBUTE = 0,
  /* aggregate event type has multiple producers and 1 consumer */
  VNET_SCHEDULER_EVENT_AGGREGATE,
  VNET_SCHEDULER_MAX_N_EVENT_TYPES
} vnet_scheduler_event_type_t;

#define foreach_scheduler_worker_role                                         \
  _ (WORKER, "worker", 0)                                                     \
  _ (CONSUMER, "consumer", 1)                                                 \
  _ (PRODUCER, "producer", 2)

typedef enum
{
#define _(n, s, b) VNET_SCHEDULER_THREAD_ROLE_##n = b,
  foreach_scheduler_worker_role
#undef _
    VNET_SCHEDULER_THREAD_N_ROLES
} __clib_packed vnet_scheduler_thread_role_t;

typedef enum
{
#define _(n, s, b) VNET_SCHEDULER_ROLE_MASK_##n = (1 << b),
  foreach_scheduler_worker_role
#undef _
} __clib_packed vnet_scheduler_thread_role_mask_t;

#define foreach_vnet_scheduler_thread_state                                   \
  _ (WORKER, ENABLE, 0, 1, "worker enable")                                   \
  _ (WORKER, DISABLE, 1, 0, "worker disable")                                 \
  _ (CONSUMER, ENABLE, 2, 1, "consumer enable")                               \
  _ (CONSUMER, DISABLE, 3, 0, "consumer disable")

typedef enum
{
#define _(a, b, c, d, s) VNET_SCHEDULER_THREAD_STATE_##a##_##b = (1 << c),
  foreach_vnet_scheduler_thread_state
#undef _
} __clib_packed vnet_scheduler_thread_state_hint_t;

/**
 * Enqueue or dequeue a burst of packets to/from the scheduler engine.
 *
 * @param	vm				vlib_main
 * @param	inst				scheduler instance
 * @param	buffers				vlib buffer indices array
 * @param	scheduler_nexts			next node index known to
 *						scheduler infra
 * @param	n_buffers			The number of buffers in the
 *						buffers array
 *						for dequeue: max number of
 *						buffers to write to array.
 * @return
 *	The number of buffers enqueued.
 */
typedef u32 (vnet_scheduler_enqueue_dequeue_handler_t) (vlib_main_t *vm,
							u32 *buffers,
							u16 *scheduler_nexts,
							u32 n_buffers);

/*
 * Change role flag for each threads.
 */
typedef int (vnet_scheduler_thread_role_cfg_t) (
  vlib_main_t *vm, clib_bitmap_t *producer_thread_indices,
  clib_bitmap_t *worker_thread_indices,
  clib_bitmap_t *consumer_thread_indices);

/*
 * Query the engine if to enable or disable the thread's scheduler dispatch.
 */
typedef vnet_scheduler_thread_state_hint_t (
  vnet_scheduler_thread_set_state_t) (
  vlib_main_t *vm, vnet_scheduler_thread_state_hint_t state_hint);

typedef struct
{
  char *name;
  char *desc;
  int priority;
  vnet_scheduler_enqueue_dequeue_handler_t *enqueue_distribute_handler;
  vnet_scheduler_enqueue_dequeue_handler_t *enqueue_aggregate_handler;
  vnet_scheduler_enqueue_dequeue_handler_t *dequeue_distribute_handler;
  vnet_scheduler_enqueue_dequeue_handler_t *dequeue_aggregate_handler;
  vnet_scheduler_thread_role_cfg_t *thread_role_config_handler;
  vnet_scheduler_thread_set_state_t *set_thread_state_handler;
} vnet_scheduler_engine_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_scheduler_thread_role_mask_t thread_roles;
  vnet_scheduler_thread_state_hint_t state_change_hint;
} vnet_scheduler_per_thread_data_t;

typedef struct
{
  vnet_scheduler_enqueue_dequeue_handler_t *enqueue_distribute_handler;
  vnet_scheduler_enqueue_dequeue_handler_t *enqueue_aggregate_handler;
  vnet_scheduler_enqueue_dequeue_handler_t *dequeue_distribute_handler;
  vnet_scheduler_enqueue_dequeue_handler_t *dequeue_aggregate_handler;
  vnet_scheduler_thread_set_state_t *set_thread_state_handler;
  vnet_scheduler_per_thread_data_t *per_thread_data;
  clib_bitmap_t *producer_thread_indices;
  clib_bitmap_t *worker_thread_indices;
  clib_bitmap_t *consumer_thread_indices;
  vnet_scheduler_engine_t *engines;
  uword *engine_index_by_name;
  u16 active_engine_index;
  u16 dispatch_node_index;
  u16 ref_cnt;
#define VNET_SCHEDULER_DISPATCH_MODE_POLLING   0
#define VNET_SCHEDULER_DISPATCH_MODE_INTERRUPT 1
  u16 dispatch_mode;
  uword *next_nodes_index_by_name;
  /* debug data for per-thread enqueue and dequeue stats count */
  u64 *distribute_enqueued;
  u64 *distribute_dequeued;
  u64 *aggregate_enqueued;
  u64 *aggregate_dequeued;
  u64 *distribute_empty_poll;
  u64 *aggregate_empty_poll;
  u64 *last_distribute_enqueued;
  u64 *last_distribute_dequeued;
  u64 *last_aggregate_enqueued;
  u64 *last_aggregate_dequeued;
  u64 freq;
  u64 last_time;
} vnet_scheduler_main_t;

extern vnet_scheduler_main_t scheduler_main;

u32 vnet_scheduler_register_engine (
  vlib_main_t *vm, char *name, char *desc, int prio,
  vnet_scheduler_enqueue_dequeue_handler_t *enqueue_distribute_handler,
  vnet_scheduler_enqueue_dequeue_handler_t *enqueue_aggregate_handler,
  vnet_scheduler_enqueue_dequeue_handler_t *dequeue_distribute_handler,
  vnet_scheduler_enqueue_dequeue_handler_t *dequeue_aggregate_handler,
  vnet_scheduler_thread_set_state_t *set_thread_state_handler,
  vnet_scheduler_thread_role_cfg_t *thread_role_config_handler);

/**
 * Helper function for calling graph node to implement trace function.
 */
static_always_inline vlib_node_runtime_t *
vnet_scheduler_get_node_runtime (vlib_main_t *vm)
{
  vnet_scheduler_main_t *sm = &scheduler_main;
  return vlib_node_get_runtime (vm, sm->dispatch_node_index);
}

always_inline int
vnet_scheduler_is_producer (u32 thread_index)
{
  return clib_bitmap_get_no_check (scheduler_main.producer_thread_indices,
				   thread_index);
}

always_inline int
vnet_scheduler_is_worker (u32 thread_index)
{
  return clib_bitmap_get_no_check (scheduler_main.worker_thread_indices,
				   thread_index);
}

always_inline int
vnet_scheduler_is_consumer (u32 thread_index)
{
  return clib_bitmap_get_no_check (scheduler_main.consumer_thread_indices,
				   thread_index);
}

always_inline void
vnet_scheduler_set_thread_state_hint (u32 thread_index,
				      vnet_scheduler_thread_state_hint_t hint)
{
  vnet_scheduler_main_t *sm = &scheduler_main;
  vnet_scheduler_per_thread_data_t *ptd = sm->per_thread_data + thread_index;

  CLIB_MEMORY_STORE_BARRIER ();
  ptd->state_change_hint = hint;
}

always_inline u32
vnet_scheduler_enqueue_buffers (vlib_main_t *vm,
				vnet_scheduler_event_type_t type, u32 *buffers,
				u16 *scheduler_nexts, u32 n_buffers,
				int drop_on_congestion)
{
  vnet_scheduler_main_t *sm = &scheduler_main;
  u32 enqueued = 0;

  switch (type)
    {
    case VNET_SCHEDULER_EVENT_DISTRIBUTE:
#if CLIB_DEBUG > 0
      if (PREDICT_FALSE (clib_bitmap_get (sm->producer_thread_indices,
					  vm->thread_index) == 0))
	goto drop_not_enqueued;
#endif
      if (PREDICT_FALSE (sm->enqueue_distribute_handler == 0))
	goto drop_not_enqueued;
      enqueued = (sm->enqueue_distribute_handler) (vm, buffers,
						   scheduler_nexts, n_buffers);
      sm->distribute_enqueued[vm->thread_index] += enqueued;
      break;
    case VNET_SCHEDULER_EVENT_AGGREGATE:
#if CLIB_DEBUG > 0
      if (PREDICT_FALSE (clib_bitmap_get (sm->worker_thread_indices,
					  vm->thread_index) == 0))
	goto drop_not_enqueued;
#endif
      /* for aggregate type enqueue dropping of the packets is not allowed.
       * The engines should make sure all packets are sent.
       */
      enqueued = (sm->enqueue_aggregate_handler) (vm, buffers, scheduler_nexts,
						  n_buffers);
      sm->aggregate_enqueued[vm->thread_index] += enqueued;
      ASSERT (enqueued == n_buffers);

      break;
    default:
      goto drop_not_enqueued;
      break;
    }

drop_not_enqueued:
  if (enqueued < n_buffers && drop_on_congestion)
    vlib_buffer_free (vm, buffers + enqueued, n_buffers - enqueued);

  return enqueued;
}

always_inline void
vnet_scheduler_disable_dispatch_node (vlib_main_t *vm)
{
  vnet_scheduler_main_t *sm = &scheduler_main;

  vlib_node_set_state (vm, sm->dispatch_node_index, VLIB_NODE_STATE_DISABLED);
}

/**
 * Create a scheduler instance
 *
 * @param distribute_node_index			distribute_node_index
 **/
int vnet_scheduler_create_instance (vlib_main_t *vm,
				    char *distribute_target_node_name,
				    char *aggregeate_target_node_name,
				    u16 *distribute_next_index,
				    u16 *aggregate_next_index);

int vnet_scheduler_change_thread_role (vlib_main_t *vm,
				       u32 *producer_thread_indices, u32 n_pti,
				       u32 *worker_thread_indices, u32 n_wti,
				       u32 *consumer_thread_indices,
				       u32 n_cti);

void vnet_scheduler_enable_disable (int is_enable);

#endif /* SRC_VLIB_VMBUS_EVENT_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
