/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/interface/tx_queue.h>
#include <vnet/interface/tx_queue_funcs.h>

VLIB_REGISTER_LOG_CLASS (if_txq_log, static) = {
  .class_name = "interface",
  .subclass_name = "tx-queue",
};

vnet_interface_txq_main_t vnet_interface_txq_main;

static u32
next_thread_index (vnet_main_t *vnm, u32 thread_index)
{
  vnet_interface_txq_main_t *vitm = &vnet_interface_txq_main;
  if (vitm->first_worker_thread_index == 0)
    return 0;

  if (thread_index != 0 && (thread_index < vitm->first_worker_thread_index ||
			    thread_index > vitm->last_worker_thread_index))
    {
      thread_index = vitm->next_worker_thread_index++;
      if (vitm->next_worker_thread_index > vitm->last_worker_thread_index)
	vitm->next_worker_thread_index = vitm->first_worker_thread_index;
    }

  return thread_index;
}

u32
vnet_hw_if_get_tx_queue_index_by_thread_index (vnet_main_t *vnm,
					       u32 hw_if_index,
					       u32 thread_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  u64 key = tx_queue_key (hw_if_index, thread_index);
  uword *p =
    hash_get_mem (im->txq_index_by_hw_if_index_and_thread_index, &key);
  return p ? p[0] : ~0;
}

void
vnet_hw_if_register_tx_queue (vnet_main_t *vnm, u32 hw_if_index, u32 queue_id,
			      u32 thread_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_hw_if_tx_queue_t *txq;
  u64 key;
  u32 queue_index;

  thread_index = next_thread_index (vnm, thread_index);
  key = tx_queue_key (hw_if_index, thread_index);
  uword *p =
    hash_get_mem (im->txq_index_by_hw_if_index_and_thread_index, &key);
  if (p)
    {
      txq = pool_elt_at_index (im->hw_if_tx_queues, p[0]);
      vec_add1 (txq->queue_ids, queue_id);
      log_debug ("register: interface %v queue-id %u thread %u", hi->name,
		 queue_id, thread_index);
    }
  else
    {
      pool_get_zero (im->hw_if_tx_queues, txq);
      queue_index = txq - im->hw_if_tx_queues;
      vec_add1 (hi->tx_queue_indices, queue_index);
      hash_set_mem_alloc (&im->txq_index_by_hw_if_index_and_thread_index, &key,
			  queue_index);
      txq->hw_if_index = hw_if_index;
      txq->dev_instance = hi->dev_instance;
      vec_add1 (txq->queue_ids, queue_id);
      txq->thread_index = thread_index;

      log_debug ("register: interface %v queue-id %u thread %u", hi->name,
		 queue_id, thread_index);
    }
}

void
vnet_hw_if_unregister_tx_queue (vnet_main_t *vnm, u32 queue_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_if_tx_queue_t *txq;
  txq = vnet_hw_if_get_tx_queue (vnm, queue_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, txq->hw_if_index);
  u64 key;

  key = ((u64) txq->hw_if_index << 32) | txq->thread_index;
  hash_unset_mem_free (&im->txq_index_by_hw_if_index_and_thread_index, &key);

  for (int i = 0; i < vec_len (hi->tx_queue_indices); i++)
    if (hi->tx_queue_indices[i] == queue_index)
      {
	vec_del1 (hi->tx_queue_indices, i);
	break;
      }

  for (int i = 0; i < vec_len (txq->queue_ids); i++)
    log_debug ("unregister: interface %v queue-id %u", hi->name,
	       txq->queue_ids[0]);
  vec_free (txq->queue_ids);
  pool_put_index (im->hw_if_tx_queues, queue_index);
}

void
vnet_hw_if_unregister_all_tx_queues (vnet_main_t *vnm, u32 hw_if_index)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);

  log_debug ("unregister_all: interface %v", hi->name);

  for (int i = 0; i < vec_len (hi->tx_queue_indices); i++)
    vnet_hw_if_unregister_tx_queue (vnm, hi->tx_queue_indices[i]);

  vec_free (hi->tx_queue_indices);
}

static clib_error_t *
vnet_interface_txq_init (vlib_main_t *vm)
{
  vnet_interface_txq_main_t *vitm = &vnet_interface_txq_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_thread_registration_t *tr;
  uword *p;

  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  tr = p ? (vlib_thread_registration_t *) p[0] : 0;
  if (tr && tr->count > 0)
    {
      vitm->first_worker_thread_index = tr->first_index;
      vitm->next_worker_thread_index = tr->first_index;
      vitm->last_worker_thread_index = tr->first_index + tr->count - 1;
    }
  return 0;
}

VLIB_INIT_FUNCTION (vnet_interface_txq_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
