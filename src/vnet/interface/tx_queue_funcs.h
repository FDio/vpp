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

#ifndef included_vnet_interface_tx_queue_funcs_h
#define included_vnet_interface_tx_queue_funcs_h

#include <vnet/vnet.h>
#include <vnet/multi-txq/multi_txq.h>

#define VNET_HW_TXQ_INDEX_SET 1

#define VNET_HW_IF_TXQ_UNIQUE 1
#define VNET_HW_IF_TXQ_SHARED 2

/* funciton declarations */
u32 vnet_hw_if_get_tx_queue_index_by_thread_index (vnet_main_t *vnm,
						   u32 hw_if_index,
						   u32 thread_index);
void vnet_hw_if_register_tx_queues (vnet_main_t *vnm, u32 hw_if_index,
				    u32 *queue_ids, u32 *flags);
void vnet_hw_if_unregister_tx_queue (vnet_main_t *vnm, u32 queue_index);
void vnet_hw_if_unregister_all_tx_queues (vnet_main_t *vnm, u32 hw_if_index);

/* inline functions */
static_always_inline u64
tx_queue_key (u32 hw_if_index, u32 thread_index)
{
  return ((u64) hw_if_index << 32) | thread_index;
}

static_always_inline vnet_hw_if_tx_queue_t *
vnet_hw_if_get_tx_queue (vnet_main_t *vnm, u32 queue_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  if (pool_is_free_index (im->hw_if_tx_queues, queue_index))
    return 0;
  return pool_elt_at_index (im->hw_if_tx_queues, queue_index);
}

static_always_inline u32
vnet_hw_if_get_tx_queue_thread_index (vnet_main_t *vnm, u32 queue_index)
{
  vnet_hw_if_tx_queue_t *txq = vnet_hw_if_get_tx_queue (vnm, queue_index);
  return txq->thread_index;
}

static_always_inline u32
vnet_hw_if_get_tx_queue_id_by_thread_index (vnet_main_t *vnm, u32 hw_if_index,
					    u32 thread_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  u64 key = tx_queue_key (hw_if_index, thread_index);
  uword *p =
    hash_get_mem (im->txq_index_by_hw_if_index_and_thread_index, &key);
  if (p)
    {
      vnet_hw_if_tx_queue_t *txq =
	pool_elt_at_index (im->hw_if_tx_queues, p[0]);
      ASSERT (vec_len (txq->queue_ids) > 0);
      return txq->queue_ids[0];
    }
  return 0;
}

static_always_inline u32 *
vnet_hw_if_get_tx_queue_ids (vnet_main_t *vnm, u32 hw_if_index,
			     u32 thread_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  u64 key = tx_queue_key (hw_if_index, thread_index);
  uword *p =
    hash_get_mem (im->txq_index_by_hw_if_index_and_thread_index, &key);
  if (p)
    {
      vnet_hw_if_tx_queue_t *txq =
	pool_elt_at_index (im->hw_if_tx_queues, p[0]);
      ASSERT (vec_len (txq->queue_ids) > 0);
      return txq->queue_ids;
    }
  return 0;
}

static_always_inline u32
vnet_hw_if_get_tx_queue_id (vlib_main_t *vm, vlib_frame_t *frame,
			    u32 hw_if_index)
{
  u32 qid;
  if (frame->flags & VNET_HW_TXQ_INDEX_SET)
    {
      qid = *(u32 *) vlib_frame_scalar_args (frame);
    }
  else
    qid = vnet_hw_if_get_tx_queue_id_by_thread_index (
      vnet_get_main (), hw_if_index, vm->thread_index);

  return qid;
}

static_always_inline int
vnet_hw_if_txq_cmp_cli_api (vnet_hw_if_tx_queue_t **a,
			    vnet_hw_if_tx_queue_t **b)
{
  vnet_main_t *vnm;
  vnet_hw_interface_t *hif_a;
  vnet_hw_interface_t *hif_b;

  if (*a == *b)
    return 0;

  if (a[0]->thread_index != b[0]->thread_index)
    return 2 * (a[0]->thread_index > b[0]->thread_index) - 1;

  vnm = vnet_get_main ();
  hif_a = vnet_get_hw_interface (vnm, a[0]->hw_if_index);
  hif_b = vnet_get_hw_interface (vnm, b[0]->hw_if_index);

  if (hif_a->tx_node_index != hif_b->tx_node_index)
    return 2 * (hif_a->tx_node_index > hif_b->tx_node_index) - 1;

  if (a[0]->hw_if_index != b[0]->hw_if_index)
    return 2 * (a[0]->hw_if_index > b[0]->hw_if_index) - 1;

  if (a[0]->queue_ids[0] != b[0]->queue_ids[0])
    return 2 * (a[0]->queue_ids[0] > b[0]->queue_ids[0]) - 1;

  ASSERT (0);
  return ~0;
}

#endif /* included_vnet_interface_tx_queue_funcs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
