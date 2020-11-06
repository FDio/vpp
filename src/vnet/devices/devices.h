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

#include <vppinfra/pcap.h>
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

typedef struct
{
  u32 hw_if_index;
  u32 dev_instance;
  u16 queue_id;
  vnet_hw_if_rx_mode mode;
  u32 interrupt_pending;
} vnet_device_and_queue_t;

typedef struct
{
  vnet_device_and_queue_t *devices_and_queues;
  vlib_node_state_t enabled_node_state;
  u32 pad;
} vnet_device_input_runtime_t;

extern vnet_device_main_t vnet_device_main;
extern vlib_node_registration_t device_input_node;
extern const u32 device_input_next_node_advance[];
extern const u32 device_input_next_node_flags[];

static inline void
vnet_hw_interface_set_input_node (vnet_main_t * vnm, u32 hw_if_index,
				  u32 node_index)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  hw->input_node_index = node_index;
}

void vnet_hw_interface_assign_rx_thread (vnet_main_t * vnm, u32 hw_if_index,
					 u16 queue_id, uword thread_index);
int vnet_hw_interface_unassign_rx_thread (vnet_main_t * vnm, u32 hw_if_index,
					  u16 queue_id);
int vnet_hw_interface_set_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
				   u16 queue_id, vnet_hw_if_rx_mode mode);
int vnet_hw_interface_get_rx_mode (vnet_main_t * vnm, u32 hw_if_index,
				   u16 queue_id, vnet_hw_if_rx_mode * mode);

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

static_always_inline uword
vnet_get_device_input_thread_index (vnet_main_t * vnm, u32 hw_if_index,
				    u16 queue_id)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  ASSERT (queue_id < vec_len (hw->input_node_thread_index_by_queue));
  return hw->input_node_thread_index_by_queue[queue_id];
}

static_always_inline void
vnet_device_input_set_interrupt_pending (vnet_main_t * vnm, u32 hw_if_index,
					 u16 queue_id)
{
  vlib_main_t *vm;
  vnet_hw_interface_t *hw;
  vnet_device_input_runtime_t *rt;
  vnet_device_and_queue_t *dq;
  uword idx;

  hw = vnet_get_hw_interface (vnm, hw_if_index);
  idx = vnet_get_device_input_thread_index (vnm, hw_if_index, queue_id);
  vm = vlib_mains[idx];
  rt = vlib_node_get_runtime_data (vm, hw->input_node_index);
  idx = hw->dq_runtime_index_by_queue[queue_id];
  dq = vec_elt_at_index (rt->devices_and_queues, idx);

  clib_atomic_store_rel_n (&(dq->interrupt_pending), 1);

  vlib_node_set_interrupt_pending (vm, hw->input_node_index);
}

/*
 * Acquire RMW Access
 * Paired with Release Store in vnet_device_input_set_interrupt_pending
 */
#define foreach_device_and_queue(var,vec)                       \
  for (var = (vec); var < vec_end (vec); var++)                 \
    if ((var->mode == VNET_HW_IF_RX_MODE_POLLING)               \
        || clib_atomic_swap_acq_n (&((var)->interrupt_pending), 0))

#endif /* included_vnet_vnet_device_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
