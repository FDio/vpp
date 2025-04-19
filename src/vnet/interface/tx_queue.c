/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/devices/devices.h>
#include <vnet/interface/tx_queue_funcs.h>
#include <vlib/unix/unix.h>

VLIB_REGISTER_LOG_CLASS (if_txq_log, static) = {
  .class_name = "interface",
  .subclass_name = "tx-queue",
};

#define log_debug(fmt, ...) vlib_log_debug (if_txq_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...)   vlib_log_err (if_txq_log.class, fmt, __VA_ARGS__)

static u64
tx_queue_key (u32 hw_if_index, u32 queue_id)
{
  return ((u64) hw_if_index << 32) | queue_id;
}

u32
vnet_hw_if_get_tx_queue_index_by_id (vnet_main_t *vnm, u32 hw_if_index,
				     u32 queue_id)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  u64 key = tx_queue_key (hw_if_index, queue_id);
  uword *p = hash_get_mem (im->txq_index_by_hw_if_index_and_queue_id, &key);
  return p ? p[0] : ~0;
}

u32
vnet_hw_if_register_tx_queue (vnet_main_t *vnm, u32 hw_if_index, u32 queue_id)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_hw_if_tx_queue_t *txq;
  u64 key = tx_queue_key (hw_if_index, queue_id);
  u32 queue_index;

  if (hash_get_mem (im->txq_index_by_hw_if_index_and_queue_id, &key))
    clib_panic ("Trying to register already registered queue id (%u) in the "
		"interface %v\n",
		queue_id, hi->name);

  pool_get_zero (im->hw_if_tx_queues, txq);
  queue_index = txq - im->hw_if_tx_queues;
  vec_add1 (hi->tx_queue_indices, queue_index);
  hash_set_mem_alloc (&im->txq_index_by_hw_if_index_and_queue_id, &key,
		      queue_index);
  txq->hw_if_index = hw_if_index;
  txq->queue_id = queue_id;

  log_debug ("register: interface %v queue-id %u", hi->name, queue_id);

  return queue_index;
}

void
vnet_hw_if_unregister_tx_queue (vnet_main_t *vnm, u32 queue_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_if_tx_queue_t *txq;
  txq = vnet_hw_if_get_tx_queue (vnm, queue_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, txq->hw_if_index);
  u64 key;

  key = tx_queue_key (txq->hw_if_index, txq->queue_id);
  hash_unset_mem_free (&im->txq_index_by_hw_if_index_and_queue_id, &key);

  for (int i = 0; i < vec_len (hi->tx_queue_indices); i++)
    if (hi->tx_queue_indices[i] == queue_index)
      {
	vec_del1 (hi->tx_queue_indices, i);
	break;
      }

  log_debug ("unregister: interface %v queue-id %u", hi->name, txq->queue_id);
  clib_bitmap_free (txq->threads);
  pool_put_index (im->hw_if_tx_queues, queue_index);
}

void
vnet_hw_if_unregister_all_tx_queues (vnet_main_t *vnm, u32 hw_if_index)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_if_tx_queue_t *txq;
  u64 key;

  log_debug ("unregister_all: interface %v", hi->name);

  for (int i = 0; i < vec_len (hi->tx_queue_indices); i++)
    {
      txq = vnet_hw_if_get_tx_queue (vnm, hi->tx_queue_indices[i]);
      key = tx_queue_key (txq->hw_if_index, txq->queue_id);
      hash_unset_mem_free (&im->txq_index_by_hw_if_index_and_queue_id, &key);

      clib_bitmap_free (txq->threads);
      pool_put_index (im->hw_if_tx_queues, hi->tx_queue_indices[i]);
    }

  vec_free (hi->tx_queue_indices);
}

void
vnet_hw_if_tx_queue_assign_thread (vnet_main_t *vnm, u32 queue_index,
				   clib_thread_index_t thread_index)
{
  vnet_hw_if_tx_queue_t *txq = vnet_hw_if_get_tx_queue (vnm, queue_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, txq->hw_if_index);
  txq->threads = clib_bitmap_set (txq->threads, thread_index, 1);
  if (clib_bitmap_count_set_bits (txq->threads) > 1)
    txq->shared_queue = 1;
  log_debug (
    "assign_thread: interface %v queue-id %u thread %u queue-shared %s",
    hi->name, txq->queue_id, thread_index,
    (txq->shared_queue == 1 ? "yes" : "no"));
}

void
vnet_hw_if_tx_queue_unassign_thread (vnet_main_t *vnm, u32 queue_index,
				     clib_thread_index_t thread_index)
{
  vnet_hw_if_tx_queue_t *txq = vnet_hw_if_get_tx_queue (vnm, queue_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, txq->hw_if_index);
  txq->threads = clib_bitmap_set (txq->threads, thread_index, 0);
  if (clib_bitmap_count_set_bits (txq->threads) < 2)
    txq->shared_queue = 0;
  log_debug (
    "unassign_thread: interface %v queue-id %u thread %u queue-shared %s",
    hi->name, txq->queue_id, thread_index,
    (txq->shared_queue == 1 ? "yes" : "no"));
}
