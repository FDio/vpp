/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>

/* funciton declarations */

u32 vnet_hw_if_get_tx_queue_index_by_id (vnet_main_t *vnm, u32 hw_if_index,
					 u32 queue_id);
u32 vnet_hw_if_register_tx_queue (vnet_main_t *vnm, u32 hw_if_index,
				  u32 queue_id);
void vnet_hw_if_unregister_tx_queue (vnet_main_t *vnm, u32 queue_index);
void vnet_hw_if_unregister_all_tx_queues (vnet_main_t *vnm, u32 hw_if_index);
void vnet_hw_if_tx_queue_assign_thread (vnet_main_t *vnm, u32 queue_index,
					u32 thread_index);
void vnet_hw_if_tx_queue_unassign_thread (vnet_main_t *vnm, u32 queue_index,
					  u32 thread_index);

/* inline functions */

static_always_inline vnet_hw_if_tx_queue_t *
vnet_hw_if_get_tx_queue (vnet_main_t *vnm, u32 queue_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  if (pool_is_free_index (im->hw_if_tx_queues, queue_index))
    return 0;
  return pool_elt_at_index (im->hw_if_tx_queues, queue_index);
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

  vnm = vnet_get_main ();
  hif_a = vnet_get_hw_interface (vnm, a[0]->hw_if_index);
  hif_b = vnet_get_hw_interface (vnm, b[0]->hw_if_index);

  if (hif_a->tx_node_index != hif_b->tx_node_index)
    return 2 * (hif_a->tx_node_index > hif_b->tx_node_index) - 1;

  if (a[0]->hw_if_index != b[0]->hw_if_index)
    return 2 * (a[0]->hw_if_index > b[0]->hw_if_index) - 1;

  if (a[0]->queue_id != b[0]->queue_id)
    return 2 * (a[0]->queue_id > b[0]->queue_id) - 1;

  ASSERT (0);
  return ~0;
}
