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
  vlib_node_t *n = vlib_get_node (vlib_get_main (), node_index);
  DBG_VNET ("set %U input node to %s(%d)",
	    format_vnet_hw_interface_name, vnm, hw, n->name, node_index);

  hw->input_node_index = node_index;
  if (n->runtime_data_bytes != sizeof (vnet_hw_interface_rx_runtime_t))
    {
      /*
       * TODO: find a more element way to initialize the input node only once.
       */
      DBG_VNET ("Initialize input runtime for node %v (%d)",
		n->name, node_index);
      vlib_main_t **vm;
      vec_foreach (vm, vlib_mains)
      {
	vnet_hw_interface_rx_runtime_t rt = { };
	rt.enabled_node_state = VLIB_NODE_STATE_DISABLED;
	vec_validate (rt.queues_per_rss, 0);
	vlib_node_set_runtime_data (*vm, node_index, &rt, sizeof (rt));
      }
    }
}

/**
 * Enable or disable an rx queue.
 *
 * This is not supposed to be called for configuration, but by the device
 * driver only.
 */
int vnet_hw_interface_enable_rx_queue (vnet_main_t * vnm, u32 hw_if_index,
				       u16 queue_id, u8 disable);

/**
 * Defines the rss mask of a given thread for a given interface.
 * The rss mask indicates how many different RX slots will be used by
 * the specified thread when receiving packets on the provided interface.
 */
int vnet_hw_interface_set_rx_queue_rss_mask (vnet_main_t * vnm,
					     u32 hw_if_index,
					     u32 thread_index, u16 rss_mask);

/**
 * Assign a given thread index and rss slot to a given queue.
 */
int vnet_hw_interface_set_rx_thread (vnet_main_t * vnm, u32 hw_if_index,
				     u16 queue_id,
				     u32 thread_index, u16 rss_slot);

/**
 * Returns the thread and rss slot currently assigned to the requested queue.
 */
int vnet_hw_interface_get_rx_thread (vnet_main_t * vnm, u32 hw_if_index,
				     u16 queue_id,
				     u32 * thread_index, u16 * rss_slot);

/**
 * Set the rx mode for a given queue.
 */
int vnet_hw_interface_set_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
				   u16 queue_id,
				   vnet_hw_interface_rx_mode mode);

/**
 * Get the rx mode of a given queue.
 */
int vnet_hw_interface_get_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
				   u16 queue_id,
				   vnet_hw_interface_rx_mode * mode);



/**
 * Enable or disable a queue index on this interface.
 * Only enabled queues will be assigned to threads to transmit packets.
 * This function must not be used by users for configuration, but only by
 * device drivers.
 */
int vnet_hw_interface_enable_tx_queue (vnet_main_t * vnm,
				       u32 hw_if_index, u16 queue_id,
				       u8 disable);

/**
 * Sets the rss mask for a given interface and thread.
 * The rss mask indicates how many slots will be used by the specified thread
 * when transmitting packets on the specified interface.
 */
int vnet_hw_interface_set_tx_rss_mask (vnet_main_t * vnm, u32 hw_if_index,
				       u32 thread_index, u16 rss_mask);

/**
 * Returns the tx queue structure that must be used during the current
 * transmission.
 */
static_always_inline vnet_interface_tx_queue_runtime_t *
vnet_hw_interface_get_tx_queue (vlib_main_t * vm,
				vnet_interface_tx_runtime_t * rt)
{
  ASSERT (vec_len (rt->tx_queue_per_rss) >= rt->rss_mask);
  return &rt->tx_queue_per_rss[vm->main_loop_count & rt->rss_mask];
}



/**
 * Assigns a queue to a specific thread and rss slot.
 * The queue ID VNET_HW_QUEUE_INVALID can be used to unset any previous
 * configuration and move back to automatic assignment.
 */
int vnet_hw_interface_set_tx_thread (vnet_main_t * vnm, u32 hw_if_index,
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
  /* ASSERT (hw->rx_queues[queue_id].current_rx_queue_runtime != NULL); */
  if (PREDICT_TRUE (hw->rx_queues[queue_id].current_rx_queue_runtime != NULL))
    {
      /* This should always be the case, but it might be better not to crash
       * when a driver gets crazy. */
      dq = hw->rx_queues[queue_id].current_rx_queue_runtime;
      clib_smp_swap (&dq->interrupt_pending, 1);
      vlib_node_set_interrupt_pending (vm, hw->input_node_index);
    }
  else
    {
      clib_warning ("Tried to interrupt disabled queue (%d %d)",
		    hw_if_index, queue_id);
    }
}

static_always_inline void
vnet_device_input_rx_finish (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vnet_hw_interface_rx_runtime_t * rt)
{
  if (rt->last_interrupt_rss == 0xffff)
    {
      /* If we are not in a full round. Start one since we have been
       * called. */
      rt->last_interrupt_rss = (vm->main_loop_count - 1) & rt->rss_mask;
    }

  /* If we had an interrupt during the last rss round, keep finishing it. */
  if ((rt->last_interrupt_rss ^ vm->main_loop_count) & rt->rss_mask)
    {
      /* We are not at the end yet */
      if (node->state != VLIB_NODE_STATE_POLLING)
	vlib_node_set_interrupt_pending (vm, node->node_index);
    }
  else
    {
      /* End of the round. Do not reschedule */
      rt->last_interrupt_rss = 0xffff;
    }
}

#define foreach_device_and_queue(vm, rt, dq) \
  vec_foreach (dq, (rt)->queues_per_rss[(vm)->main_loop_count & (rt)->rss_mask]) \
    if ((dq)->mode == VNET_HW_INTERFACE_RX_MODE_POLLING ||  \
	clib_smp_swap (&dq->interrupt_pending, 0))

#endif /* included_vnet_vnet_device_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
