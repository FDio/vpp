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
#include <vlib/vlib.h>
#include <vnet/scheduler/scheduler.h>

vnet_scheduler_main_t scheduler_main;

int
vnet_scheduler_create_instance (vlib_main_t *vm,
				char *distribute_target_node_name,
				char *aggregeate_target_node_name,
				u16 *distribute_next_index,
				u16 *aggregate_next_index)
{
  vnet_scheduler_main_t *sm = &scheduler_main;
  vlib_node_t *sd, *pn;
  uword index;
  uword *p;

  /* register all next nodes */
  sd = vlib_get_node_by_name (vm, (u8 *) "scheduler-dispatch");

  p = hash_get_mem (sm->next_nodes_index_by_name, distribute_target_node_name);
  if (!p)
    {
      pn = vlib_get_node_by_name (vm, (u8 *) distribute_target_node_name);
      if (!pn)
	{
	  clib_error ("No Node with Name %s exist",
		      distribute_target_node_name);
	  return -1;
	}
      index =
	vlib_node_add_named_next (vm, sd->index, distribute_target_node_name);
      *distribute_next_index = index;
      hash_set_mem (sm->next_nodes_index_by_name, distribute_target_node_name,
		    index);
    }
  else
    *distribute_next_index = (u16) p[0];

  p = hash_get_mem (sm->next_nodes_index_by_name, aggregeate_target_node_name);
  if (!p)
    {
      pn = vlib_get_node_by_name (vm, (u8 *) aggregeate_target_node_name);
      if (!pn)
	{
	  clib_error ("No Node with Name %s exist",
		      aggregeate_target_node_name);
	  return -1;
	}
      index =
	vlib_node_add_named_next (vm, sd->index, aggregeate_target_node_name);
      *aggregate_next_index = index;
      hash_set_mem (sm->next_nodes_index_by_name, aggregeate_target_node_name,
		    index);
    }
  else
    *aggregate_next_index = (u32) p[0];

  return 0;
}

u32
vnet_scheduler_register_engine (
  vlib_main_t *vm, char *name, char *desc, int prio,
  vnet_scheduler_enqueue_dequeue_handler_t *enqueue_distribute_handler,
  vnet_scheduler_enqueue_dequeue_handler_t *enqueue_aggregate_handler,
  vnet_scheduler_enqueue_dequeue_handler_t *dequeue_distribute_handler,
  vnet_scheduler_enqueue_dequeue_handler_t *dequeue_aggregate_handler,
  vnet_scheduler_thread_set_state_t *set_thread_state_handler,
  vnet_scheduler_thread_role_cfg_t *thread_role_config_handler)
{
  u32 ei;
  vnet_scheduler_main_t *sm = &scheduler_main;
  vnet_scheduler_engine_t *p;

  vec_add2 (sm->engines, p, 1);
  ei = p - sm->engines;

  p->name = name;
  p->desc = desc;
  p->enqueue_distribute_handler = enqueue_distribute_handler;
  p->enqueue_aggregate_handler = enqueue_aggregate_handler;
  p->dequeue_distribute_handler = dequeue_distribute_handler;
  p->dequeue_aggregate_handler = dequeue_aggregate_handler;
  p->set_thread_state_handler = set_thread_state_handler;
  p->thread_role_config_handler = thread_role_config_handler;
  p->priority = prio;

  hash_set_mem (sm->engine_index_by_name, p->name, p - sm->engines);

  if (sm->active_engine_index == (u16) ~0)
    {
      sm->active_engine_index = ei;
      sm->enqueue_distribute_handler = enqueue_distribute_handler;
      sm->enqueue_aggregate_handler = enqueue_aggregate_handler;
      sm->dequeue_distribute_handler = dequeue_distribute_handler;
      sm->dequeue_aggregate_handler = dequeue_aggregate_handler;
      sm->set_thread_state_handler = set_thread_state_handler;
    }
  else
    {
      if (sm->engines[sm->active_engine_index].priority < prio)
	{
	  sm->active_engine_index = ei;
	  sm->enqueue_distribute_handler = enqueue_distribute_handler;
	  sm->enqueue_aggregate_handler = enqueue_aggregate_handler;
	  sm->dequeue_distribute_handler = dequeue_distribute_handler;
	  sm->dequeue_aggregate_handler = dequeue_aggregate_handler;
	  sm->set_thread_state_handler = set_thread_state_handler;
	}
    }

  return ei;
}

static void
vnet_scheduler_enable_dispatch (void)
{
  vnet_scheduler_main_t *sm = &scheduler_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 skip_master = vlib_num_workers () > 0, i;

  for (i = skip_master; i < tm->n_vlib_mains; i++)
    {
      vnet_scheduler_thread_state_hint_t hint;
      vnet_scheduler_per_thread_data_t *ptd = sm->per_thread_data + i;
      vlib_main_t *vm = vlib_get_main_by_index (i);
      vlib_node_state_t state =
	vlib_node_get_state (vm, sm->dispatch_node_index);

      hint = vnet_scheduler_is_worker (i) ?
	       VNET_SCHEDULER_THREAD_STATE_WORKER_ENABLE :
	       VNET_SCHEDULER_THREAD_STATE_WORKER_DISABLE;
      hint |= vnet_scheduler_is_consumer (i) ?
		VNET_SCHEDULER_THREAD_STATE_CONSUMER_ENABLE :
		VNET_SCHEDULER_THREAD_STATE_CONSUMER_DISABLE;

      CLIB_MEMORY_STORE_BARRIER ();

      ptd->state_change_hint = hint;

      hint &= VNET_SCHEDULER_THREAD_STATE_WORKER_ENABLE |
	      VNET_SCHEDULER_THREAD_STATE_CONSUMER_ENABLE;

      if (hint && state == VLIB_NODE_STATE_DISABLED)
	vlib_node_set_state (vm, sm->dispatch_node_index, sm->dispatch_mode);
    }
}

int
vnet_scheduler_change_thread_role (vlib_main_t *vm,
				   u32 *producer_thread_indices, u32 n_pti,
				   u32 *worker_thread_indices, u32 n_wti,
				   u32 *consumer_thread_indices, u32 n_cti)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_scheduler_main_t *sm = &scheduler_main;
  vnet_scheduler_engine_t *e;
  clib_bitmap_t *pt = 0, *wt = 0, *ct = 0;
  u32 i, change_state = 0;
  u32 n_pt, n_wt, n_ct;
  int ret = 0;

  clib_bitmap_validate (pt, tm->n_vlib_mains - 1);
  clib_bitmap_validate (wt, tm->n_vlib_mains - 1);
  clib_bitmap_validate (ct, tm->n_vlib_mains - 1);

  for (i = 0; i < n_pti; i++)
    clib_bitmap_set_no_check (pt, producer_thread_indices[i], 1);
  for (i = 0; i < n_wti; i++)
    clib_bitmap_set_no_check (wt, worker_thread_indices[i], 1);
  for (i = 0; i < n_cti; i++)
    {
      clib_bitmap_set_no_check (ct, consumer_thread_indices[i], 1);
      /* for multiple components enabling scheduler at the same time,
       * the consumer threads are likely to be producers too. Although
       * it may not be that optimal (consumers may be heavily loaded)
       * but minimized the configuration complexity and can work in
       * most cases.
       */
      if (sm->ref_cnt)
	clib_bitmap_set_no_check (pt, consumer_thread_indices[i], 1);
    }

  n_pt = clib_bitmap_count_set_bits (pt);
  n_wt = clib_bitmap_count_set_bits (wt);
  n_ct = clib_bitmap_count_set_bits (ct);

  if (!n_pt || !n_wt || !n_ct || n_pt % n_ct != 0)
    {
      ret = -EINVAL;
      goto error_exit;
    }

  vec_foreach (e, sm->engines)
    {
      ret = (e->thread_role_config_handler) (vm, pt, wt, ct);
      if (ret < 0)
	goto error_exit;
    }

  if (!clib_bitmap_is_equal (pt, sm->producer_thread_indices))
    {
      clib_bitmap_zero (sm->producer_thread_indices);
      CLIB_MEMORY_STORE_BARRIER ();
      clib_bitmap_or (sm->producer_thread_indices, pt);
      change_state++;
    }

  if (!clib_bitmap_is_equal (wt, sm->worker_thread_indices))
    {
      clib_bitmap_zero (sm->worker_thread_indices);
      CLIB_MEMORY_STORE_BARRIER ();
      clib_bitmap_or (sm->worker_thread_indices, wt);
      change_state++;
    }

  if (!clib_bitmap_is_equal (ct, sm->consumer_thread_indices))
    {
      clib_bitmap_zero (sm->consumer_thread_indices);
      CLIB_MEMORY_STORE_BARRIER ();
      clib_bitmap_or (sm->consumer_thread_indices, ct);
      change_state++;
    }

  /* even some threads does not require waking up, temporarily active
   * scheduler-dispatch and let the engine to decide if to fall back to
   * sleep.
   */
  if (change_state && sm->ref_cnt)
    vnet_scheduler_enable_dispatch ();

  return 0;

error_exit:
  clib_bitmap_free (pt);
  clib_bitmap_free (wt);
  clib_bitmap_free (ct);
  return ret;
}

void
vnet_scheduler_enable_disable (int is_enable)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_scheduler_main_t *sm = &scheduler_main;
  vnet_scheduler_engine_t *e;
  int ret;

  if (is_enable)
    {
      if (clib_bitmap_count_set_bits (sm->producer_thread_indices) == 0 &&
	  clib_bitmap_count_set_bits (sm->worker_thread_indices) == 0 &&
	  clib_bitmap_count_set_bits (sm->consumer_thread_indices) == 0)
	{
	  vlib_thread_main_t *tm = vlib_get_thread_main ();

	  if (tm->n_vlib_mains == 1)
	    {
	      /* only single main thread */
	      clib_bitmap_set_no_check (sm->producer_thread_indices, 0, 1);
	    }
	  else
	    {
	      u32 i;

	      /* main thread not attend scheduling, all worker threads are
	       * involved */
	      for (i = 1; i < tm->n_vlib_mains; i++)
		{
		  CLIB_MEMORY_STORE_BARRIER ();
		  clib_bitmap_set_no_check (sm->producer_thread_indices, i, 1);
		}
	    }

	  CLIB_MEMORY_STORE_BARRIER ();
	  clib_bitmap_or (sm->worker_thread_indices,
			  sm->producer_thread_indices);
	  CLIB_MEMORY_STORE_BARRIER ();
	  clib_bitmap_or (sm->consumer_thread_indices,
			  sm->producer_thread_indices);

	  vec_foreach (e, sm->engines)
	    {
	      ret = (e->thread_role_config_handler) (
		vm, sm->producer_thread_indices, sm->worker_thread_indices,
		sm->consumer_thread_indices);
	      ASSERT (ret == 0);
	    }
	}

      sm->ref_cnt += 1;
    }
  else
    {
      if (sm->ref_cnt == 1)
	{
	  /* to safely disable scheduler infra the crypto dispatch can only
	   * be disabled by engine. The way to configure this way is to clear
	   * all thread bits.
	   */
	  CLIB_MEMORY_STORE_BARRIER ();
	  clib_bitmap_zero (sm->producer_thread_indices);
	  clib_bitmap_zero (sm->worker_thread_indices);
	  clib_bitmap_zero (sm->consumer_thread_indices);

	  vec_foreach (e, sm->engines)
	    {
	      ret = (e->thread_role_config_handler) (
		vm, sm->producer_thread_indices, sm->worker_thread_indices,
		sm->consumer_thread_indices);
	      ASSERT (ret == 0);
	    }
	}

      if (sm->ref_cnt != 0)
	sm->ref_cnt--;
    }

  vnet_scheduler_enable_dispatch ();
}

clib_error_t *
vnet_scheduler_init (vlib_main_t *vm)
{
  vnet_scheduler_main_t *sm = &scheduler_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_time_t time;

  sm->active_engine_index = ~0;
  sm->engine_index_by_name = hash_create_string (0, sizeof (uword));
  sm->dispatch_node_index =
    vlib_get_node_by_name (vm, (u8 *) "scheduler-dispatch")->index;
  sm->next_nodes_index_by_name = hash_create_string (0, sizeof (uword));

  vec_validate_aligned (sm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  clib_bitmap_validate (sm->producer_thread_indices, tm->n_vlib_mains - 1);
  clib_bitmap_validate (sm->worker_thread_indices, tm->n_vlib_mains - 1);
  clib_bitmap_validate (sm->consumer_thread_indices, tm->n_vlib_mains - 1);

  sm->dispatch_mode = VLIB_NODE_STATE_POLLING;

  vec_validate (sm->distribute_enqueued, tm->n_vlib_mains - 1);
  vec_validate (sm->distribute_dequeued, tm->n_vlib_mains - 1);
  vec_validate (sm->aggregate_enqueued, tm->n_vlib_mains - 1);
  vec_validate (sm->aggregate_dequeued, tm->n_vlib_mains - 1);
  vec_validate (sm->distribute_empty_poll, tm->n_vlib_mains - 1);
  vec_validate (sm->aggregate_empty_poll, tm->n_vlib_mains - 1);
  vec_validate (sm->last_distribute_enqueued, tm->n_vlib_mains - 1);
  vec_validate (sm->last_distribute_dequeued, tm->n_vlib_mains - 1);
  vec_validate (sm->last_aggregate_enqueued, tm->n_vlib_mains - 1);
  vec_validate (sm->last_aggregate_dequeued, tm->n_vlib_mains - 1);
  clib_time_init (&time);
  sm->freq = time.clocks_per_second;
  sm->last_time = clib_cpu_time_now ();

  return 0;
}

VLIB_INIT_FUNCTION (vnet_scheduler_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
