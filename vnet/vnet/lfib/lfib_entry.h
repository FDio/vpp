/*
 * lfib.h: The Label/MPLS FIB
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

#ifndef __LFIB_ENTRY_H__
#define __LFIB_ENTRY_H__

#include <vnet/vnet.h>
#include <vnet/mpls/packet.h>
#include <vnet/fib/fib_types.h>
#include <vnet/dpo/dpo.h>
#include <vnet/lfib/lfib.h>

#define LFIB_ENTRY_FORMAT_BRIEF  (0<<0)
#define LFIB_ENTRY_FORMAT_DETAIL (1<<0)

extern fib_node_index_t lfib_entry_create_from_ip_fib_entry(
    fib_node_index_t fib_index,
    mpls_label_t label,
    mpls_eos_bit_t eos,
    fib_node_index_t fib_entry_index);

extern void lfib_entry_update_from_ip_fib_entry (fib_node_index_t lfei);

extern void lfib_entry_show(fib_node_index_t lfe,
			    int flags,
			    vlib_main_t * vm);

extern void lfib_entry_lock(fib_node_index_t lfei);
extern void lfib_entry_unlock(fib_node_index_t lfei);

extern const dpo_id_t *lfib_entry_contribute_forwarding(fib_node_index_t lfei);
extern mpls_label_t lfib_entry_get_key(fib_node_index_t lfei);
extern u32 lfib_entry_get_fib_index(fib_node_index_t lfei);

extern fib_node_index_t lfib_entry_create(fib_node_index_t lfib_index,
                                          mpls_label_t label,
                                          mpls_eos_bit_t eos,
                                          const fib_route_path_t *paths);

extern fib_node_index_t lfib_entry_special_create(fib_node_index_t lfib_index,
                                                  mpls_label_t label,
                                                  mpls_eos_bit_t eos,
                                                  const dpo_id_t *dpo);

extern void lfib_entry_path_add2(fib_node_index_t lfei,
                                 const fib_route_path_t *paths);

#endif
