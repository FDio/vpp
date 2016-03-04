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

#ifndef __vnet_cop_h__
#define __vnet_cop_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

typedef enum {
  VNET_COP_IP4,
  VNET_COP_IP6,
  VNET_COP_DEFAULT,
  VNET_N_COPS,
} vnet_cop_t;

typedef enum {
  /* First check src address against whitelist */
  IP4_RX_COP_WHITELIST,
  IP6_RX_COP_WHITELIST,
  DEFAULT_RX_COP_WHITELIST,

  /* Pkts not otherwise dropped go to xxx-input */
  IP4_RX_COP_INPUT,
  IP6_RX_COP_INPUT,
  DEFAULT_RX_COP_INPUT,

  /* Going, going, gone... */
  RX_COP_DROP,

  COP_RX_N_FEATURES,
} cop_feature_type_t;

typedef struct {
  vnet_config_main_t config_main;
  u32 * config_index_by_sw_if_index;
} cop_config_main_t;

typedef struct {
  u32 fib_index;
} cop_config_data_t;

typedef struct {
  cop_config_main_t cop_config_mains[VNET_N_COPS];

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} cop_main_t;

cop_main_t cop_main;

extern vlib_node_registration_t cop_input_node;

int cop_interface_enable_disable (u32 sw_if_index, int enable_disable);

typedef struct {
  u32 sw_if_index;
  u8 ip4;
  u8 ip6;
  u8 default_cop;
  u32 fib_id;
} cop_whitelist_enable_disable_args_t;

int cop_whitelist_enable_disable (cop_whitelist_enable_disable_args_t *a);

#endif /* __vnet_cop_h__ */
