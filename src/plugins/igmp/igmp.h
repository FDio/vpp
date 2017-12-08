/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _IGMP_H_
#define _IGMP_H_

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/adj/adj_mcast.h>

enum
{
  IGMP_PROCESS_EVENT_START = 1,
  IGMP_PROCESS_EVENT_STOP = 2,
} igmp_process_event_t;

typedef struct igmp_config_key_t_
{
  ip46_address_t saddr;
  ip46_address_t gaddr;
  u32 sw_if_index;
} igmp_config_key_t;

struct igmp_config_t_;

typedef struct igmp_config_t_ igmp_config_t;

/* populate supplied bufefr with IGMP message */
typedef void (create_msg_t) (igmp_config_t * conf, vlib_buffer_t * b);

typedef struct igmp_config_t_
{
  /** time of last message report */
  f64 last_send;

  /** IGMP message report interval */
  f64 interval;

  /** VPP interface identification */
  u32 sw_if_index;

  /** source address */
  ip46_address_t saddr;
  /** group address */
  ip46_address_t gaddr;

  /* mcast adj index */
  adj_index_t adj_index;

  /* next type of message to be created */
  create_msg_t *next_create_msg;

  /* mark configuration for deletion */
  u8 pending_del;

  /* igmp config hash key */
  igmp_config_key_t *key;

  /* linked list next/prev */
  igmp_config_t *next, *prev;

} igmp_config_t;

typedef struct
{
  /** API message ID base */
  u16 msg_id_base;

  /* get config context by config key */
  uword *igmp_config_context_by_key;

  /** pointer to IGMP config with smallest timeout remaining */
  igmp_config_t *configs;

  /** buffer cache */
  u32 **buffers;

} igmp_main_t;

extern igmp_main_t igmp_main;
extern vlib_node_registration_t igmp_process_node;
extern vlib_node_registration_t igmp_input_node;

int igmp_configure (vlib_main_t * vm, u8 enable, u32 sw_if_index,
		    ip46_address_t saddr, ip46_address_t gaddr);
clib_error_t *igmp_plugin_api_hookup (vlib_main_t * vm);

#endif /* _IGMP_H_ */
