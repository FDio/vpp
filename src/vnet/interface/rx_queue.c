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
#include <vnet/interface/rx_queue_funcs.h>
#include <vlib/unix/unix.h>

/* *INDENT-OFF* */
VLIB_REGISTER_LOG_CLASS (if_rxq_log, static) = {
  .class_name = "interface",
  .subclass_name = "rx-queue",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG, //FIXME
};
/* *INDENT-ON* */

#define log_debug(fmt,...) vlib_log_debug(if_rxq_log.class, fmt, __VA_ARGS__)
#define log_err(fmt,...) vlib_log_err(if_rxq_log.class, fmt, __VA_ARGS__)

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


static u64
rx_queue_key (u32 hw_if_index, u32 queue_id)
{
  return ((u64) hw_if_index << 32) | queue_id;
}

u32
vnet_hw_if_get_rx_queue_index_by_id (vnet_main_t * vnm, u32 hw_if_index,
				     u32 queue_id)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  u64 key = rx_queue_key (hw_if_index, queue_id);
  uword *p = hash_get_mem (im->rxq_index_by_hw_if_index_and_queue_id, &key);
  return p ? p[0] : ~0;
}

u32
vnet_hw_if_register_rx_queue (vnet_main_t * vnm, u32 hw_if_index,
			      u32 queue_id, u32 thread_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_hw_if_rx_queue_t *rxq;
  u64 key = rx_queue_key (hw_if_index, queue_id);
  u32 queue_index;

  if (hash_get_mem (im->rxq_index_by_hw_if_index_and_queue_id, &key))
    clib_panic ("Trying to register already registered queue id (%u) in the "
		"interface %v\n", queue_id, hi->name);

  thread_index = next_thread_index (vnm, thread_index);

  pool_get_zero (im->hw_if_rx_queues, rxq);
  queue_index = rxq - im->hw_if_rx_queues;
  vec_add1 (hi->rx_queue_indices, queue_index);
  hash_set_mem_alloc (&im->rxq_index_by_hw_if_index_and_queue_id, &key,
		      queue_index);
  rxq->hw_if_index = hw_if_index;
  rxq->dev_instance = hi->dev_instance;
  rxq->queue_id = queue_id;
  rxq->thread_index = thread_index;
  rxq->mode = VNET_HW_IF_RX_MODE_POLLING;
  rxq->file_index = ~0;

  log_debug ("register: interface %s queue-id %u thread %u", hi->name,
	     queue_id, thread_index);

  return queue_index;
}

void
vnet_hw_if_unregister_rx_queue (vnet_main_t * vnm, u32 queue_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_if_rx_queue_t *rxq;
  rxq = vnet_hw_if_get_rx_queue (vnm, queue_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, rxq->hw_if_index);
  u64 key;

  key = ((u64) rxq->hw_if_index << 32) | rxq->queue_id;
  hash_unset_mem_free (&im->rxq_index_by_hw_if_index_and_queue_id, &key);

  for (int i = 0; i < vec_len (hi->rx_queue_indices); i++)
    if (hi->rx_queue_indices[i] == queue_index)
      {
	vec_del1 (hi->rx_queue_indices, i);
	break;
      }

  log_debug ("unregister: interface %s queue-id %u", hi->name, rxq->queue_id);
  pool_put_index (im->hw_if_rx_queues, queue_index);
}

void
vnet_hw_if_unregister_all_rx_queues (vnet_main_t * vnm, u32 hw_if_index)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);

  log_debug ("unregister_all: interface %s", hi->name);

  for (int i = 0; i < vec_len (hi->rx_queue_indices); i++)
    vnet_hw_if_unregister_rx_queue (vnm, hi->rx_queue_indices[i]);

  vec_free (hi->rx_queue_indices);
}

void
vnet_hw_if_set_rx_queue_file_index (vnet_main_t * vnm, u32 queue_index,
				    u32 file_index)
{
  vnet_hw_if_rx_queue_t *rxq = vnet_hw_if_get_rx_queue (vnm, queue_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, rxq->hw_if_index);

  rxq->file_index = file_index;
  clib_file_set_polling_thread (&file_main, file_index, rxq->thread_index);
  log_debug ("set_file_index: interface %s queue-id %u file-index %u",
	     hi->name, rxq->queue_id, file_index);
}

void
vnet_hw_if_set_input_node (vnet_main_t * vnm, u32 hw_if_index, u32 node_index)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  hi->input_node_index = node_index;
  log_debug ("set_input_node: node %U for interface %s",
	     format_vlib_node_name, vm, node_index, hi->name);
}

int
vnet_hw_if_set_rx_queue_mode (vnet_main_t * vnm, u32 queue_index,
			      vnet_hw_if_rx_mode mode)
{
  vnet_hw_if_rx_queue_t *rxq = vnet_hw_if_get_rx_queue (vnm, queue_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, rxq->hw_if_index);
  vnet_device_class_t *dc = vnet_get_device_class (vnm, hi->dev_class_index);

  ASSERT (mode != VNET_HW_IF_RX_MODE_UNKNOWN);

  if (mode == VNET_HW_IF_RX_MODE_DEFAULT)
    mode = hi->default_rx_mode;

  if (rxq->mode == mode)
    {
      log_debug ("set_rx_queue_mode: interface %s queue-id %u mode "
		 "unchanged (%U)", hi->name, rxq->queue_id,
		 format_vnet_hw_if_rx_mode, mode);
      return 0;
    }

  if ((mode == VNET_HW_IF_RX_MODE_INTERRUPT ||
       mode == VNET_HW_IF_RX_MODE_ADAPTIVE) && rxq->file_index == ~0)
    {
      log_debug ("set_rx_queue_mode: interface %s queue-id %u interrupt mode "
		 "not supported", hi->name, rxq->queue_id);
      return VNET_API_ERROR_UNSUPPORTED;
    }

  if (dc->rx_mode_change_function)
    {
      clib_error_t *err = dc->rx_mode_change_function (vnm, rxq->hw_if_index,
						       rxq->queue_id, mode);
      if (err)
	{
	  log_err ("setting rx mode on the interface %s queue-id %u failed.\n"
		   "   %U", hi->name, rxq->queue_id, format_clib_error, err);
	  clib_error_free (err);
	  return VNET_API_ERROR_UNSUPPORTED;
	}
    }

  rxq->mode = mode;
  log_debug ("set_rx_queue_mode: interface %s queue-id %u mode set to %U",
	     hi->name, rxq->queue_id, format_vnet_hw_if_rx_mode, mode);
  return 0;
}

vnet_hw_if_rx_mode
vnet_hw_if_get_rx_queue_mode (vnet_main_t * vnm, u32 queue_index)
{
  vnet_hw_if_rx_queue_t *rxq = vnet_hw_if_get_rx_queue (vnm, queue_index);
  return rxq->mode;
}

void
vnet_hw_if_set_rx_queue_thread_index (vnet_main_t * vnm, u32 queue_index,
				      u32 thread_index)
{
  vnet_hw_if_rx_queue_t *rxq = vnet_hw_if_get_rx_queue (vnm, queue_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, rxq->hw_if_index);

  rxq->thread_index = thread_index;

  if (rxq->file_index != ~0)
    clib_file_set_polling_thread (&file_main, rxq->file_index, thread_index);

  log_debug ("set_rx_queue_thread_index: interface %s queue-id %u "
	     "thread-index set to %u", hi->name, rxq->queue_id, thread_index);
}


void
vnet_hw_if_generate_rxq_int_poll_vector (vlib_main_t * vm,
					 vlib_node_runtime_t * node)
{
  vnet_hw_if_rx_node_runtime_t *rt = (void *) node->runtime_data;
  vnet_main_t *vnm = vnet_get_main ();
  int int_num = -1;

  ASSERT (node->state == VLIB_NODE_STATE_INTERRUPT);

  vec_reset_length (rt->rxq_poll_vector);

  while ((int_num = clib_interrupt_get_next (rt->rxq_interrupts,
					     int_num)) != -1)
    {
      vnet_hw_if_rx_queue_t *rxq = vnet_hw_if_get_rx_queue (vnm, int_num);
      vnet_hw_if_rxq_poll_vector_t *pv;

      clib_interrupt_clear (rt->rxq_interrupts, int_num);

      vec_add2 (rt->rxq_poll_vector, pv, 1);
      pv->dev_instance = rxq->dev_instance;
      pv->queue_id = rxq->queue_id;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
