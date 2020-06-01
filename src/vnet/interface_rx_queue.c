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

static u32
next_thread_index (vnet_main_t * vnm, u32 thread_index)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  if (vdm->first_worker_thread_index == 0)
    return 0;

  if (thread_index != 0 &&
      (thread_index < vdm->first_worker_thread_index ||
       thread_index > vdm->last_worker_thread_index))
    {
      thread_index = vdm->next_worker_thread_index++;
      if (vdm->next_worker_thread_index > vdm->last_worker_thread_index)
	vdm->next_worker_thread_index = vdm->first_worker_thread_index;
    }

  return thread_index;
}

static int
device_queue_sort (void *a1, void *a2)
{
  vnet_device_and_queue_t *dq1 = a1;
  vnet_device_and_queue_t *dq2 = a2;

  if (dq1->dev_instance > dq2->dev_instance)
    return 1;
  else if (dq1->dev_instance < dq2->dev_instance)
    return -1;
  else if (dq1->queue_id > dq2->queue_id)
    return 1;
  else if (dq1->queue_id < dq2->queue_id)
    return -1;
  else
    return 0;
}

static void
update_device_and_queue_runtime_data (vnet_main_t * vnm, u32 node_index)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi;
  vnet_hw_if_rx_queue_t *rxq;
  vnet_device_and_queue_t **list = 0, *dq;
  vnet_device_input_runtime_t *rt;
  int is_polling = 0;

  vec_validate (list, vec_len (vlib_mains) - 1);

  /* *INDENT-OFF* */
  pool_foreach (rxq, im->hw_if_rx_queues, ({
    hi = vnet_get_hw_interface (vnm, rxq->hw_if_index);
    if (hi->input_node_index == node_index)
      {
       // vnet_hw_interface_t *hi;
	vec_add2 (list[rxq->thread_index], dq, 1);
	//hi = vnet_get_hw_interface (vnm, rxq->hw_if_index);
	dq->dev_instance = hi->dev_instance;
	dq->queue_id = rxq->queue_id;
	dq->mode = rxq->mode;
	if (rxq->mode == VNET_HW_IF_RX_MODE_POLLING)
	  is_polling = 1;
      }
  }));
  /* *INDENT-ON* */

  for (int i = 0; i < vec_len (list); i++)
    if (list[i])
      vec_sort_with_function (list[i], device_queue_sort);


  vlib_worker_thread_barrier_sync (vm);

  /* *INDENT-OFF* */
  foreach_vlib_main(({
    rt = vlib_node_get_runtime_data (this_vlib_main, node_index);
    if (list[this_vlib_main->thread_index])
      {
        vec_free (rt->devices_and_queues);
        rt->devices_and_queues = list[this_vlib_main->thread_index];
	if (is_polling)
          rt->enabled_node_state = VLIB_NODE_STATE_POLLING;
	else
	  rt->enabled_node_state = VLIB_NODE_STATE_INTERRUPT;
      }
  }));
  /* *INDENT-ON* */

  vlib_worker_thread_barrier_release (vm);

  /* *INDENT-OFF* */
  foreach_vlib_main(({
    rt = vlib_node_get_runtime_data (this_vlib_main, node_index);
    if (rt->devices_and_queues)
       vlib_node_set_state (this_vlib_main, node_index, rt->enabled_node_state);
    }));
  /* *INDENT-ON* */

  vec_free (list);
}

void
vnet_hw_if_update_runtime_data (vnet_main_t * vnm, u32 hw_if_index)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  update_device_and_queue_runtime_data (vnm, hi->input_node_index);
}

u32
vnet_hw_if_register_rx_queue (vnet_main_t * vnm, u32 hw_if_index,
			      u32 queue_id, u32 thread_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_hw_if_rx_queue_t *rxq;
  uword *p = hash_get (hi->rx_queue_index_by_rx_queue_id, queue_id);
  u32 queue_index;

  if (p)
    clib_panic ("Trying to register already registered queue id (%u) in the "
		"interface %v\n", queue_id, hi->name);

  thread_index = next_thread_index (vnm, thread_index);

  pool_get_zero (im->hw_if_rx_queues, rxq);
  queue_index = rxq - im->hw_if_rx_queues;
  vec_add1 (hi->rx_queue_indices, queue_index);
  hash_set (hi->rx_queue_index_by_rx_queue_id, queue_id, queue_index);
  rxq->hw_if_index = hw_if_index;
  rxq->queue_id = queue_id;
  rxq->thread_index = thread_index;
  rxq->mode = VNET_HW_IF_RX_MODE_POLLING;
  update_device_and_queue_runtime_data (vnm, hi->input_node_index);
  return queue_index;
}

void
vnet_hw_if_unregister_rx_queue (vnet_main_t * vnm, u32 queue_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_if_rx_queue_t *rxq;
  rxq = vnet_hw_if_get_rx_queue (vnm, queue_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, rxq->hw_if_index);

  hash_unset (hi->rx_queue_index_by_rx_queue_id, rxq->queue_id);

  for (int i = 0; i < vec_len (hi->rx_queue_indices); i++)
    if (hi->rx_queue_indices[i] == queue_index)
      {
	vec_del1 (hi->rx_queue_indices, i);
	break;
      }

  pool_put_index (im->hw_if_rx_queues, queue_index);
}

void
vnet_hw_if_unregister_all_rx_queues (vnet_main_t * vnm, u32 hw_if_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);

  for (int i = 0; i < vec_len (hi->rx_queue_indices); i++)
    pool_put_index (im->hw_if_rx_queues, hi->rx_queue_indices[i]);

  vec_free (hi->rx_queue_indices);
  hash_free (hi->rx_queue_index_by_rx_queue_id);
  vnet_hw_if_update_runtime_data (vnm, hw_if_index);
}

void
vnet_hw_if_set_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
			vnet_hw_if_rx_mode mode)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_if_rx_queue_t *rxq;
  int update_needed = 0;

  ASSERT (vec_len (hi->rx_queue_indices) > 0);

  if (mode == VNET_HW_IF_RX_MODE_DEFAULT)
    mode  = hi->default_rx_mode;

  for (int i = 0; i < vec_len (hi->rx_queue_indices); i++)
    {
      rxq = pool_elt_at_index (im->hw_if_rx_queues, hi->rx_queue_indices[i]);
      if (rxq->mode != mode)
	{
	  rxq->mode = mode;
	  update_needed = 1;
	}
    }

  if (update_needed)
    vnet_hw_if_update_runtime_data (vnm, hw_if_index);
}

u32
vnet_hw_if_get_rx_queue_index_by_queue_id (vnet_main_t * vnm, u32 hw_if_index,
					   u32 queue_id)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  uword *p = hash_get (hi->rx_queue_index_by_rx_queue_id, queue_id);
  return p ? p[0] : ~0;
}

u32
vnet_hw_if_get_rx_queue_numa_node (vnet_main_t * vnm, u32 queue_index)
{
  vnet_hw_if_rx_queue_t *rxq = vnet_hw_if_get_rx_queue (vnm, queue_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, rxq->hw_if_index);
  return hi->numa_node;
}

u32
vnet_hw_if_get_rx_queue_thread_index (vnet_main_t * vnm, u32 queue_index)
{
  vnet_hw_if_rx_queue_t *rxq = vnet_hw_if_get_rx_queue (vnm, queue_index);
  return rxq->thread_index;
}

void
vnet_hw_if_set_rx_queue_file_index (vnet_main_t * vnm, u32 queue_index,
				    u32 file_index)
{
  vnet_hw_if_rx_queue_t *rxq = vnet_hw_if_get_rx_queue (vnm, queue_index);

  rxq->file_index = file_index;
  clib_file_set_polling_thread (&file_main, file_index, rxq->thread_index);
}

void
vnet_hw_if_set_input_node (vnet_main_t * vnm, u32 hw_if_index, u32 node_index)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  hi->input_node_index = node_index;
}

void
vnet_hw_if_set_rx_queue_mode (vnet_main_t * vnm, u32 queue_index,
			      vnet_hw_if_rx_mode mode)
{
  vnet_hw_if_rx_queue_t *rxq = vnet_hw_if_get_rx_queue (vnm, queue_index);

  rxq->mode = mode;
  vnet_hw_if_update_runtime_data (vnm, rxq->hw_if_index);
}

void
vnet_hw_if_set_rx_queue_thread_index (vnet_main_t * vnm, u32 queue_index,
				      u32 thread_index)
{
  vnet_hw_if_rx_queue_t *rxq = vnet_hw_if_get_rx_queue (vnm, queue_index);

  rxq->thread_index = thread_index;
  vnet_hw_if_update_runtime_data (vnm, rxq->hw_if_index);
}

vnet_hw_if_rx_mode
vnet_hw_if_get_rx_queue_mode (vnet_main_t * vnm, u32 queue_index)
{
  return vnet_hw_if_get_rx_queue (vnm, queue_index)->mode;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
