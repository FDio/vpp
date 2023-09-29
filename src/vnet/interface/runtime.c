/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/interface/tx_queue_funcs.h>
#include <vlib/unix/unix.h>

VLIB_REGISTER_LOG_CLASS (if_rxq_log, static) = {
  .class_name = "interface",
  .subclass_name = "runtime",
};

#define log_debug(fmt, ...) vlib_log_debug (if_rxq_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...)   vlib_log_err (if_rxq_log.class, fmt, __VA_ARGS__)

static char *node_state_str[] = {
  [VLIB_NODE_STATE_DISABLED] = "disabled",
  [VLIB_NODE_STATE_POLLING] = "polling",
  [VLIB_NODE_STATE_INTERRUPT] = "interrupt",
};

static int
poll_data_sort (void *a1, void *a2)
{
  vnet_hw_if_rxq_poll_vector_t *pv1 = a1;
  vnet_hw_if_rxq_poll_vector_t *pv2 = a2;

  if (pv1->dev_instance > pv2->dev_instance)
    return 1;
  else if (pv1->dev_instance < pv2->dev_instance)
    return -1;
  else if (pv1->queue_id > pv2->queue_id)
    return 1;
  else if (pv1->queue_id < pv2->queue_id)
    return -1;
  else
    return 0;
}

void
vnet_hw_if_update_runtime_data (vnet_main_t *vnm, u32 hw_if_index)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  u32 node_index = hi->input_node_index;
  vnet_hw_if_rx_queue_t *rxq;
  vnet_hw_if_rxq_poll_vector_t *pv, **d = 0, **a = 0;
  vnet_hw_if_output_node_runtime_t *new_out_runtimes = 0;
  vlib_node_state_t *per_thread_node_state = 0;
  u32 n_threads = vlib_get_n_threads ();
  u16 *per_thread_node_adaptive = 0;
  int something_changed_on_rx = 0;
  int something_changed_on_tx = 0;
  clib_bitmap_t *pending_int = 0;
  int last_int = -1;

  log_debug ("update node '%U' triggered by interface %v",
	     format_vlib_node_name, vm, node_index, hi->name);

  if (!vec_len (hi->rx_queue_indices) && !vec_len (hi->tx_queue_indices))
    return;

  vec_validate (d, n_threads - 1);
  vec_validate (a, n_threads - 1);
  vec_validate_init_empty (per_thread_node_state, n_threads - 1,
			   VLIB_NODE_STATE_DISABLED);
  vec_validate_init_empty (per_thread_node_adaptive, n_threads - 1, 0);

  /* find out desired node state on each thread */
  pool_foreach (rxq, im->hw_if_rx_queues)
    {
      u32 ti = rxq->thread_index;
      vnet_hw_interface_t *rxq_hi;

      ASSERT (rxq->mode != VNET_HW_IF_RX_MODE_UNKNOWN);
      ASSERT (rxq->mode != VNET_HW_IF_RX_MODE_DEFAULT);

      rxq_hi = vnet_get_hw_interface (vnm, rxq->hw_if_index);

      if (rxq_hi->input_node_index != node_index)
	continue;

      if (rxq->mode == VNET_HW_IF_RX_MODE_POLLING)
	{
	  per_thread_node_state[ti] = VLIB_NODE_STATE_POLLING;
	  per_thread_node_adaptive[ti] = 0;
	}

      if (per_thread_node_state[ti] == VLIB_NODE_STATE_POLLING)
	continue;

      if (rxq->mode == VNET_HW_IF_RX_MODE_INTERRUPT ||
	  rxq->mode == VNET_HW_IF_RX_MODE_ADAPTIVE)
	per_thread_node_state[ti] = VLIB_NODE_STATE_INTERRUPT;

      if (rxq->mode == VNET_HW_IF_RX_MODE_ADAPTIVE)
	per_thread_node_adaptive[ti] = 1;
    }

  /* construct per-thread polling vectors */
  pool_foreach (rxq, im->hw_if_rx_queues)
    {
      u32 ti = rxq->thread_index;
      vnet_hw_interface_t *rxq_hi;

      rxq_hi = vnet_get_hw_interface (vnm, rxq->hw_if_index);

      if (rxq_hi->input_node_index != node_index)
	continue;

      if (rxq->mode == VNET_HW_IF_RX_MODE_INTERRUPT ||
	  rxq->mode == VNET_HW_IF_RX_MODE_ADAPTIVE)
	last_int = clib_max (last_int, rxq - im->hw_if_rx_queues);

      if (per_thread_node_adaptive[ti])
	{
	  vec_add2_aligned (a[ti], pv, 1, CLIB_CACHE_LINE_BYTES);
	  pv->dev_instance = rxq->dev_instance;
	  pv->queue_id = rxq->queue_id;
	}

      if (per_thread_node_state[ti] != VLIB_NODE_STATE_POLLING)
	continue;

      vec_add2_aligned (d[ti], pv, 1, CLIB_CACHE_LINE_BYTES);
      pv->dev_instance = rxq->dev_instance;
      pv->queue_id = rxq->queue_id;
    }

  /* sort poll vectors and compare them with active ones to avoid
   * unnecesary barrier */
  for (int i = 0; i < n_threads; i++)
    {
      vlib_main_t *ovm = vlib_get_main_by_index (i);
      vlib_node_state_t old_state;
      vec_sort_with_function (d[i], poll_data_sort);

      old_state = vlib_node_get_state (ovm, node_index);
      if (per_thread_node_state[i] != old_state)
	{
	  something_changed_on_rx = 1;
	  log_debug ("state changed for node %U on thread %u from %s to %s",
		     format_vlib_node_name, vm, node_index, i,
		     node_state_str[old_state],
		     node_state_str[per_thread_node_state[i]]);
	}

      /* check if something changed */
      if (something_changed_on_rx == 0)
	{
	  vnet_hw_if_rx_node_runtime_t *rt;
	  rt = vlib_node_get_runtime_data (ovm, node_index);
	  if (vec_len (rt->rxq_vector_int) != vec_len (d[i]))
	    something_changed_on_rx = 1;
	  else if (memcmp (d[i], rt->rxq_vector_int,
			   vec_len (d[i]) * sizeof (**d)))
	    something_changed_on_rx = 1;
	  if (clib_interrupt_get_n_int (rt->rxq_interrupts) != last_int + 1)
	    something_changed_on_rx = 1;

	  if (something_changed_on_rx == 0 && per_thread_node_adaptive[i])
	    {
	      if (vec_len (rt->rxq_vector_poll) != vec_len (a[i]))
		something_changed_on_rx = 1;
	      else if (memcmp (a[i], rt->rxq_vector_poll,
			       vec_len (a[i]) * sizeof (**a)))
		something_changed_on_rx = 1;
	    }
	}
    }

  if (vec_len (hi->tx_queue_indices) > 0)
    {
      new_out_runtimes = vec_dup_aligned (hi->output_node_thread_runtimes,
					  CLIB_CACHE_LINE_BYTES);
      vec_validate_aligned (new_out_runtimes, n_threads - 1,
			    CLIB_CACHE_LINE_BYTES);

      for (u32 i = 0; i < vec_len (new_out_runtimes); i++)
	{
	  vnet_hw_if_output_node_runtime_t *rt;
	  rt = vec_elt_at_index (new_out_runtimes, i);
	  u32 n_queues = 0, total_queues = vec_len (hi->tx_queue_indices);
	  rt->frame = 0;
	  rt->lookup_table = 0;

	  for (u32 j = 0; j < total_queues; j++)
	    {
	      u32 queue_index = hi->tx_queue_indices[j];
	      vnet_hw_if_tx_frame_t frame = { .shared_queue = 0,
					      .hints = 7,
					      .queue_id = ~0 };
	      vnet_hw_if_tx_queue_t *txq =
		vnet_hw_if_get_tx_queue (vnm, queue_index);
	      if (!clib_bitmap_get (txq->threads, i))
		continue;

	      log_debug ("tx queue data changed for interface %v, thread %u "
			 "(queue_id %u)",
			 hi->name, i, txq->queue_id);
	      something_changed_on_tx = 1;

	      frame.queue_id = txq->queue_id;
	      frame.shared_queue = txq->shared_queue;
	      vec_add1 (rt->frame, frame);
	      n_queues++;
	    }

	  // don't initialize rt->n_queues above
	  if (rt->n_queues != n_queues)
	    {
	      something_changed_on_tx = 1;
	      rt->n_queues = n_queues;
	    }
	  /*
	   * It is only used in case of multiple txq.
	   */
	  if (rt->n_queues > 0)
	    {
	      if (!is_pow2 (n_queues))
		n_queues = max_pow2 (n_queues);

	      vec_validate_aligned (rt->lookup_table, n_queues - 1,
				    CLIB_CACHE_LINE_BYTES);

	      for (u32 k = 0; k < vec_len (rt->lookup_table); k++)
		{
		  rt->lookup_table[k] = rt->frame[k % rt->n_queues].queue_id;
		  log_debug ("tx queue lookup table changed for interface %v, "
			     "(lookup table [%u]=%u)",
			     hi->name, k, rt->lookup_table[k]);
		}
	    }
	}
    }
  else
    /* interface deleted */
    something_changed_on_tx = 1;

  if (something_changed_on_rx || something_changed_on_tx)
    {
      int with_barrier;

      if (vlib_worker_thread_barrier_held ())
	{
	  with_barrier = 0;
	  log_debug ("%s", "already running under the barrier");
	}
      else
	with_barrier = 1;

      if (with_barrier)
	vlib_worker_thread_barrier_sync (vm);

      if (something_changed_on_rx)
	{
	  for (int i = 0; i < n_threads; i++)
	    {
	      vlib_main_t *vm = vlib_get_main_by_index (i);
	      vnet_hw_if_rx_node_runtime_t *rt;
	      rt = vlib_node_get_runtime_data (vm, node_index);
	      pv = rt->rxq_vector_int;
	      rt->rxq_vector_int = d[i];
	      d[i] = pv;

	      if (per_thread_node_adaptive[i])
		{
		  pv = rt->rxq_vector_poll;
		  rt->rxq_vector_poll = a[i];
		  a[i] = pv;
		}

	      if (rt->rxq_interrupts)
		{
		  void *in = rt->rxq_interrupts;
		  int int_num = -1;
		  while ((int_num = clib_interrupt_get_next (in, int_num)) !=
			 -1)
		    {
		      clib_interrupt_clear (in, int_num);
		      pending_int = clib_bitmap_set (pending_int, int_num, 1);
		      last_int = clib_max (last_int, int_num);
		    }
		}

	      vlib_node_set_state (vm, node_index, per_thread_node_state[i]);
	      vlib_node_set_flag (vm, node_index, VLIB_NODE_FLAG_ADAPTIVE_MODE,
				  per_thread_node_adaptive[i]);

	      if (last_int >= 0)
		clib_interrupt_resize (&rt->rxq_interrupts, last_int + 1);
	      else
		clib_interrupt_free (&rt->rxq_interrupts);
	    }
	}
      if (something_changed_on_tx)
	{
	  vnet_hw_if_output_node_runtime_t *t;
	  t = hi->output_node_thread_runtimes;
	  hi->output_node_thread_runtimes = new_out_runtimes;
	  new_out_runtimes = t;
	}

      if (with_barrier)
	vlib_worker_thread_barrier_release (vm);
    }
  else
    log_debug ("skipping update of node '%U', no changes detected",
	       format_vlib_node_name, vm, node_index);

  if (pending_int)
    {
      int i;
      clib_bitmap_foreach (i, pending_int)
	{
	  vnet_hw_if_rx_queue_set_int_pending (vnm, i);
	}
      clib_bitmap_free (pending_int);
    }

  for (int i = 0; i < n_threads; i++)
    {
      vec_free (d[i]);
      vec_free (a[i]);
      if (new_out_runtimes)
	{
	  vec_free (new_out_runtimes[i].frame);
	  vec_free (new_out_runtimes[i].lookup_table);
	}
    }

  vec_free (d);
  vec_free (a);
  vec_free (per_thread_node_state);
  vec_free (per_thread_node_adaptive);
  vec_free (new_out_runtimes);
}
