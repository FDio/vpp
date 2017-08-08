/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef included_vnet_vnet_device_h
#define included_vnet_vnet_device_h

#include <vnet/unix/pcap.h>
#include <vnet/l3_types.h>

typedef enum
{
  VNET_DEVICE_INPUT_NEXT_IP4_NCS_INPUT,
  VNET_DEVICE_INPUT_NEXT_IP4_INPUT,
  VNET_DEVICE_INPUT_NEXT_IP6_INPUT,
  VNET_DEVICE_INPUT_NEXT_MPLS_INPUT,
  VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT,
  VNET_DEVICE_INPUT_NEXT_DROP,
  VNET_DEVICE_INPUT_N_NEXT_NODES,
} vnet_device_input_next_t;

#define VNET_DEVICE_INPUT_NEXT_NODES {					\
    [VNET_DEVICE_INPUT_NEXT_DROP] = "error-drop",			\
    [VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT] = "ethernet-input",		\
    [VNET_DEVICE_INPUT_NEXT_IP4_NCS_INPUT] = "ip4-input-no-checksum",	\
    [VNET_DEVICE_INPUT_NEXT_IP4_INPUT] = "ip4-input",			\
    [VNET_DEVICE_INPUT_NEXT_IP6_INPUT] = "ip6-input",			\
    [VNET_DEVICE_INPUT_NEXT_MPLS_INPUT] = "mpls-input",			\
}

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* total input packet counter */
  u64 aggregate_rx_packets;
} vnet_device_per_worker_data_t;

typedef struct
{
  vnet_device_per_worker_data_t *workers;
  uword first_worker_thread_index;
  uword last_worker_thread_index;
  uword next_worker_thread_index;
} vnet_device_main_t;

extern vnet_device_main_t vnet_device_main;
extern vlib_node_registration_t device_input_node;
extern const u32 device_input_next_node_advance[];

#define vnet_thread_is_valid(vdm, thread_index) \
    (((thread_index) == 0) || \
	(thread_index >= (vdm)->first_worker_thread_index && \
	    thread_index <= (vdm)->last_worker_thread_index))

/**
 * Bind input node to a given interface.
 * This will overwrite any existing runtime data.
 */
static inline void
vnet_hw_interface_set_input_node (vnet_main_t * vnm, u32 hw_if_index,
				  u32 node_index)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  hw->input_node_index = node_index;
  vlib_main_t **vm;
  vec_foreach(vm, vlib_mains) {
    vnet_hw_interface_rx_runtime_t rt = {};
    rt.enabled_node_state = VLIB_NODE_STATE_DISABLED;
    vec_validate(rt.queues_per_rss, 0);
    vlib_node_set_runtime_data(*vm, node_index, &rt, sizeof(rt));
  }
}

/*
 * Assign a given thread index and rss slot to a given queue.
 */
int vnet_hw_interface_set_rx_thread (vnet_main_t * vnm, u32 hw_if_index,
				     u16 queue_id,
				     u32 thread_index, u16 rss_slot);

int vnet_hw_interface_get_rx_thread (vnet_main_t * vnm, u32 hw_if_index,
				     u16 queue_id,
				     u32 *thread_index, u16 *rss_slot);

int vnet_hw_interface_set_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
				   u16 queue_id,
				   vnet_hw_interface_rx_mode mode);
int vnet_hw_interface_get_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
				   u16 queue_id,
				   vnet_hw_interface_rx_mode * mode);

int vnet_hw_interface_enable_rx_queue (vnet_main_t * vnm, u32 hw_if_index,
				       u16 queue_id, u8 disable);

int vnet_hw_interface_set_rx_queue_rss_mask (vnet_main_t * vnm, u32 hw_if_index,
				             u32 thread_index, u16 rss_mask);

/*
 * Enable or disable a queue index on this interface.
 * Only enabled queues will be assigned to threads to transmit packets.
 */
int vnet_hw_interface_enable_tx_queue(vnet_main_t * vnm,
				      u32 hw_if_index, u16 queue_id,
				      u8 disable);

static_always_inline vnet_interface_tx_queue_runtime_t *
vnet_hw_interface_get_tx_queue(vlib_main_t *vm,
			       vnet_interface_tx_runtime_t *rt)
{
  ASSERT(vec_len(rt->tx_queue_per_rss) >= rt->rss_mask);
  return &rt->tx_queue_per_rss[vm->main_loop_count & rt->rss_mask];
}

/*
 * rss is used to make sure that packets received on a given rx queue
 * are always going out through the same tx queue.
 */
int vnet_hw_interface_set_tx_rss_mask (vnet_main_t * vnm, u32 hw_if_index,
				       u32 thread_index, u16 rss_mask);

/*
 * Assigns a queue to a given thread and rss slot.
 */
int vnet_hw_interface_set_tx_queue_thread (vnet_main_t * vnm, u32 hw_if_index,
					   u32 thread_index, u16 rss_slot,
					   u16 queue_id);

static inline u64
vnet_get_aggregate_rx_packets (void)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  u64 sum = 0;
  vnet_device_per_worker_data_t *pwd;

  vec_foreach (pwd, vdm->workers) sum += pwd->aggregate_rx_packets;

  return sum;
}

static inline void
vnet_device_increment_rx_packets (u32 thread_index, u64 count)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  vnet_device_per_worker_data_t *pwd;

  pwd = vec_elt_at_index (vdm->workers, thread_index);
  pwd->aggregate_rx_packets += count;
}

static_always_inline void
vnet_device_input_set_interrupt_pending (vnet_main_t * vnm, u32 hw_if_index,
					 u16 queue_id)
{
  vlib_main_t *vm;
  vnet_hw_interface_t *hw;
  vnet_hw_interface_rx_queue_runtime_t *dq;
  uword idx;

  hw = vnet_get_hw_interface (vnm, hw_if_index);
  idx = hw->rx_queues[queue_id].thread_index;
  vm = vlib_mains[idx];
  ASSERT(hw->rx_queues[queue_id].current_rx_queue_runtime != NULL);
  dq = hw->rx_queues[queue_id].current_rx_queue_runtime;
  clib_smp_swap(&dq->interrupt_pending, 1);
  vlib_node_set_interrupt_pending (vm, hw->input_node_index);
}

static_always_inline int
vnet_device_input_should_rx_queue (vlib_main_t *vm,
				   vnet_hw_interface_rx_runtime_t *rt,
				   vnet_hw_interface_rx_queue_runtime_t *dq)
{
  /* Always rx if the queue is in polling mode. */
  if ((dq)->mode == VNET_HW_INTERFACE_RX_MODE_POLLING)
    return 1;

  /* rx if we have a pending interrupt */
  if (clib_smp_swap(&dq->interrupt_pending, 0)) {
      /* Keep running the thread until a full round of rss */
      rt->last_interrupt_rss = (vm->main_loop_count - 1) & rt->rss_mask;
      return 1;
  }

  return 0;
}

static_always_inline void
vnet_device_input_rx_finish (vlib_main_t *vm, vlib_node_runtime_t *node,
			     vnet_hw_interface_rx_runtime_t *rt)
{
  /* If we had an interrupt during the last rss round, keep finishing it. */
  if (rt->last_interrupt_rss != (vm->main_loop_count & rt->rss_mask))
    vlib_node_set_interrupt_pending(vm, node->node_index);
  else
    rt->last_interrupt_rss++;
}

#define foreach_device_and_queue(vm, rt, dq) \
  vec_foreach (dq, (rt)->queues_per_rss[(vm)->main_loop_count & (rt)->rss_mask]) \
    if (vnet_device_input_should_rx_queue(vm, rt, dq))

#endif /* included_vnet_vnet_device_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
