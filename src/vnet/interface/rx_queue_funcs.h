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

/* funciton declarations */

u32 vnet_hw_if_get_rx_queue_index_by_id (vnet_main_t *vnm, u32 hw_if_index,
					 u32 queue_id);
u32 vnet_hw_if_register_rx_queue (vnet_main_t *vnm, u32 hw_if_index,
				  u32 queue_id, u32 thread_idnex);
void vnet_hw_if_unregister_rx_queue (vnet_main_t *vnm, u32 queue_index);
void vnet_hw_if_unregister_all_rx_queues (vnet_main_t *vnm, u32 hw_if_index);
void vnet_hw_if_set_rx_queue_file_index (vnet_main_t *vnm, u32 queue_index,
					 u32 file_index);
void vnet_hw_if_set_input_node (vnet_main_t *vnm, u32 hw_if_index,
				u32 node_index);
int vnet_hw_if_set_rx_queue_mode (vnet_main_t *vnm, u32 queue_index,
				  vnet_hw_if_rx_mode mode);
vnet_hw_if_rx_mode vnet_hw_if_get_rx_queue_mode (vnet_main_t *vnm,
						 u32 queue_index);
void vnet_hw_if_set_rx_queue_thread_index (vnet_main_t *vnm, u32 queue_index,
					   u32 thread_index);
vnet_hw_if_rxq_poll_vector_t *
vnet_hw_if_generate_rxq_int_poll_vector (vlib_main_t *vm,
					 vlib_node_runtime_t *node);

/* inline functions */

static_always_inline vnet_hw_if_rx_queue_t *
vnet_hw_if_get_rx_queue (vnet_main_t *vnm, u32 queue_index)
{
  vnet_interface_main_t *im = &vnm->interface_main;
  if (pool_is_free_index (im->hw_if_rx_queues, queue_index))
    return 0;
  return pool_elt_at_index (im->hw_if_rx_queues, queue_index);
}

static_always_inline void
vnet_hw_if_rx_queue_set_int_pending (vnet_main_t *vnm, u32 queue_index)
{
  vnet_hw_if_rx_queue_t *rxq = vnet_hw_if_get_rx_queue (vnm, queue_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, rxq->hw_if_index);
  vlib_main_t *vm = vlib_get_main_by_index (rxq->thread_index);
  vnet_hw_if_rx_node_runtime_t *rt;
  if (PREDICT_FALSE (rxq->mode != VNET_HW_IF_RX_MODE_INTERRUPT &&
		     rxq->mode != VNET_HW_IF_RX_MODE_ADAPTIVE))
    return;
  rt = vlib_node_get_runtime_data (vm, hi->input_node_index);
  if (vm == vlib_get_main ())
    clib_interrupt_set (rt->rxq_interrupts, queue_index);
  else
    clib_interrupt_set_atomic (rt->rxq_interrupts, queue_index);
  vlib_node_set_interrupt_pending (vm, hi->input_node_index);
}

static_always_inline vnet_hw_if_rxq_poll_vector_t *
vnet_hw_if_get_rxq_poll_vector (vlib_main_t *vm, vlib_node_runtime_t *node)
{
  vnet_hw_if_rx_node_runtime_t *rt = (void *) node->runtime_data;
  vnet_hw_if_rxq_poll_vector_t *pv = rt->rxq_vector_int;

  if (PREDICT_FALSE (node->state == VLIB_NODE_STATE_INTERRUPT))
    pv = vnet_hw_if_generate_rxq_int_poll_vector (vm, node);
  else if (node->flags & VLIB_NODE_FLAG_ADAPTIVE_MODE)
    pv = rt->rxq_vector_poll;

  return pv;
}

static_always_inline u8
vnet_hw_if_get_rx_queue_numa_node (vnet_main_t *vnm, u32 queue_index)
{
  vnet_hw_if_rx_queue_t *rxq = vnet_hw_if_get_rx_queue (vnm, queue_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, rxq->hw_if_index);
  return hi->numa_node;
}

static_always_inline u32
vnet_hw_if_get_rx_queue_thread_index (vnet_main_t *vnm, u32 queue_index)
{
  vnet_hw_if_rx_queue_t *rxq = vnet_hw_if_get_rx_queue (vnm, queue_index);
  return rxq->thread_index;
}

static_always_inline int
vnet_hw_if_rxq_cmp_cli_api (vnet_hw_if_rx_queue_t **a,
			    vnet_hw_if_rx_queue_t **b)
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

  if (hif_a->input_node_index != hif_b->input_node_index)
    return 2 * (hif_a->input_node_index > hif_b->input_node_index) - 1;

  if (a[0]->hw_if_index != b[0]->hw_if_index)
    return 2 * (a[0]->hw_if_index > b[0]->hw_if_index) - 1;

  if (a[0]->queue_id != b[0]->queue_id)
    return 2 * (a[0]->queue_id > b[0]->queue_id) - 1;

  ASSERT (0);
  return ~0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
