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
#include <vlib/unix/unix.h>

/* *INDENT-OFF* */
VLIB_REGISTER_LOG_CLASS (if_rxq_log, static) = {
  .class_name = "interface",
  .subclass_name = "runtime",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};
/* *INDENT-ON* */

#define log_debug(fmt,...) vlib_log_debug(if_rxq_log.class, fmt, __VA_ARGS__)
#define log_err(fmt,...) vlib_log_err(if_rxq_log.class, fmt, __VA_ARGS__)

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
vnet_hw_if_update_runtime_data (vnet_main_t * vnm, u32 hw_if_index)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  u32 node_index = hi->input_node_index;
  vnet_hw_if_rx_queue_t *rxq;
  vnet_hw_if_rxq_poll_vector_t *pv, **d = 0;
  vlib_node_state_t *per_thread_node_state = 0;
  u32 n_threads = vec_len (vlib_mains);
  int something_changed = 0;

  log_debug ("update node '%U' triggered by interface %s",
	     format_vlib_node_name, vm, node_index, hi->name);

  vec_validate (d, n_threads - 1);
  vec_validate_init_empty (per_thread_node_state, n_threads - 1,
			   VLIB_NODE_STATE_DISABLED);

  /* *INDENT-OFF* */
  pool_foreach (rxq, im->hw_if_rx_queues, ({
    vnet_hw_interface_t *hi;
    uword flags;
    hi = vnet_get_hw_interface (vnm, rxq->hw_if_index);

    if (hi->input_node_index != node_index)
      continue;

    ASSERT (rxq->mode != VNET_HW_IF_RX_MODE_UNKNOWN);
    ASSERT (rxq->mode != VNET_HW_IF_RX_MODE_DEFAULT);

    flags = vnet_sw_interface_get_flags (vnm, hi->sw_if_index);
    if ((flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
      {
        log_debug ("skip interface %s (admin down)", hi->name);
        continue;
      }

    if (rxq->mode == VNET_HW_IF_RX_MODE_INTERRUPT ||
	rxq->mode == VNET_HW_IF_RX_MODE_ADAPTIVE)
      {
        per_thread_node_state[rxq->thread_index] = VLIB_NODE_STATE_INTERRUPT;
	continue;
      }

    vec_add2_aligned (d[rxq->thread_index], pv, 1, CLIB_CACHE_LINE_BYTES);
    pv->dev_instance = hi->dev_instance;
    pv->queue_id = rxq->queue_id;

  }));
  /* *INDENT-ON* */

  for (int i = 0; i < n_threads; i++)
    {
      vlib_node_state_t old_state;
      char *node_state_str[] = {
	[VLIB_NODE_STATE_DISABLED] = "disabled",
	[VLIB_NODE_STATE_POLLING] = "polling",
	[VLIB_NODE_STATE_INTERRUPT] = "interrupt",
      };
      vec_sort_with_function (d[i], poll_data_sort);
      if (vec_len (d[i]) > 0)
	per_thread_node_state[i] = VLIB_NODE_STATE_POLLING;

      old_state = vlib_node_get_state (vlib_mains[i], hi->input_node_index);
      if (per_thread_node_state[i] != old_state)
	{
	  something_changed = 1;
	  log_debug ("state changed for node %U on thread %u from %s to %s",
		     format_vlib_node_name, vm, node_index, i,
		     node_state_str[old_state],
		     node_state_str[per_thread_node_state[i]]);
	}

      /* check if something changed */
      if (something_changed == 0)
	{
	  vnet_device_input_runtime_t *rt;
	  rt = vlib_node_get_runtime_data (vlib_mains[i], node_index);
	  if (vec_len (rt->rxq_poll_vector) != vec_len (d[i]))
	    something_changed = 1;
	  else if (memcmp (d[i], rt->rxq_poll_vector,
			   vec_len (d[i]) * sizeof (*d)))
	    something_changed = 1;
	}
    }

  if (something_changed)
    {
      int with_barrier = vlib_worker_thread_barrier_held () == 0;
      if (with_barrier)
	vlib_worker_thread_barrier_sync (vm);
      for (int i = 0; i < n_threads; i++)
	{
	  vlib_main_t *vm = vlib_mains[i];
	  vnet_device_input_runtime_t *rt;
	  rt = vlib_node_get_runtime_data (vm, node_index);
	  pv = rt->rxq_poll_vector;
	  rt->rxq_poll_vector = d[i];
	  d[i] = pv;
	  vlib_node_set_state (vm, hi->input_node_index,
			       per_thread_node_state[i]);
	}
      if (with_barrier)
	vlib_worker_thread_barrier_release (vm);
    }
  else
    log_debug ("skipping update of node '%U', no changes detected",
	       format_vlib_node_name, vm, node_index);

  for (int i = 0; i < n_threads; i++)
    vec_free (d[i]);
  vec_free (d);
  vec_free (per_thread_node_state);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
