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
