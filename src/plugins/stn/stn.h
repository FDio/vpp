/*
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
 */

#ifndef SRC_PLUGINS_STN_STN_H_
#define SRC_PLUGINS_STN_STN_H_

#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vppinfra/bihash_16_8.h>

typedef struct {
  ip46_address_t address;
  u32 next_node_index;
  u32 sw_if_index;
} stn_rule_t;

typedef struct {
  /* pool of stn rules */
  stn_rule_t *rules;

  /* number of rules */
  u32 n_rules;

  /* hash table used to retrieve the rule from the ip address */
  clib_bihash_16_8_t rule_by_address_table;

  u32 punt_to_stn_ip4_next_index;
  u32 punt_to_stn_ip6_next_index;

  u16 msg_id_base;
} stn_main_t;

typedef struct {
  /** Destination address of intercepted packets */
  ip46_address_t address;
  /** TX interface to send packets to */
  u32 sw_if_index;
  /** Whether to delete the rule */
  u8 del;
} stn_rule_add_del_args_t;

/**
 * Add or delete an stn rule.
 */
int stn_rule_add_del (stn_rule_add_del_args_t *args);

extern stn_main_t stn_main;

clib_error_t *
stn_api_init (vlib_main_t * vm, stn_main_t * sm);

#endif /* SRC_PLUGINS_STN_STN_H_ */
