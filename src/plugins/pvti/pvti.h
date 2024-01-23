
/*
 * pvti.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) <current-year> <your-organization>
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
#ifndef __included_pvti_h__
#define __included_pvti_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

typedef struct
{
  ip_address_t local_ip;
  ip_address_t remote_ip;
  u16 remote_port;
  u16 local_port;
  u32 sw_if_index;
  u32 hw_if_index;
} pvti_if_t;

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* interface pool */
  pvti_if_t *if_pool;

  /* if_index in the pool above by sw_if_index */
  index_t *if_index_by_sw_if_index;

  /* indices by port */
  index_t **if_indices_by_port;

  /* on/off switch for the periodic function */
  u8 periodic_timer_enabled;
  /* Node index, non-zero if the periodic process has been created */
  u32 periodic_node_index;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} pvti_main_t;

extern pvti_main_t pvti_main;

extern vlib_node_registration_t pvti_node;
extern vlib_node_registration_t pvti4_input_node;
extern vlib_node_registration_t pvti4_output_node;
extern vlib_node_registration_t pvti6_input_node;
extern vlib_node_registration_t pvti6_output_node;
extern vlib_node_registration_t pvti_periodic_node;

/* Periodic function events */
#define PVTI_EVENT1			   1
#define PVTI_EVENT2			   2
#define PVTI_EVENT_PERIODIC_ENABLE_DISABLE 3

void pvti_create_periodic_process (pvti_main_t *);

#endif /* __included_pvti_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
