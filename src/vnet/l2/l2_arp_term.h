/*
 * l2/l2_arp_term.c: IP v4 ARP L2 BD termination
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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

#include <vnet/ip/ip46_address.h>
#include <vnet/ethernet/arp_packet.h>

typedef struct l2_arp_term_publish_ctx_t_
{
  u32 sw_if_index;
  ip46_type_t type;
  ip46_address_t ip;
  mac_address_t mac;
} l2_arp_term_publish_event_t;

enum
{
  L2_ARP_TERM_EVENT_PUBLISH,
};

typedef struct l2_arp_term_main_t_
{
  bool publish;

  l2_arp_term_publish_event_t *publish_events;

} l2_arp_term_main_t;

extern l2_arp_term_main_t l2_arp_term_main;
extern vlib_node_registration_t l2_arp_term_process_node;

extern void l2_arp_term_set_publisher_node (bool on);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
