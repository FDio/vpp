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
    [VNET_DEVICE_INPUT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",	\
    [VNET_DEVICE_INPUT_NEXT_IP6_INPUT] = "ip6-input",			\
    [VNET_DEVICE_INPUT_NEXT_MPLS_INPUT] = "mpls-input",			\
}

#endif /* included_vnet_vnet_device_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
