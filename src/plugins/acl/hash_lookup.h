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

#ifndef _ACL_HASH_LOOKUP_H_
#define _ACL_HASH_LOOKUP_H_

#include <stddef.h>
#include "acl.h"

/*
 * Do the necessary to logically apply the ACL to the existing vector of ACLs looked up
 * during the packet processing
 */

void hash_acl_apply(acl_main_t *am, u32 sw_if_index, u8 is_input, int acl_index);

/* Remove the ACL from the packet processing lookups on a given interface */

void hash_acl_unapply(acl_main_t *am, u32 sw_if_index, u8 is_input, int acl_index);

/*
 * Add an ACL or delete an ACL. ACL may already have been referenced elsewhere,
 * so potentially we also need to do the work to enable the lookups.
 */

void hash_acl_add(acl_main_t *am, int acl_index);
void hash_acl_delete(acl_main_t *am, int acl_index);

/*
 * Do the work required to match a given 5-tuple from the packet,
 * and return the action as well as populate the values pointed
 * to by the *_match_p pointers and maybe trace_bitmap.
 */

u8
hash_multi_acl_match_5tuple (u32 sw_if_index, fa_5tuple_t * pkt_5tuple, int is_l2,
                       int is_ip6, int is_input, u32 * acl_match_p,
                       u32 * rule_match_p, u32 * trace_bitmap);


/*
 * The debug function to show the contents of the ACL lookup hash
 */
void show_hash_acl_hash(vlib_main_t * vm, acl_main_t *am, u32 verbose);

/* Debug functions to turn validate/trace on and off */
void acl_plugin_hash_acl_set_validate_heap(acl_main_t *am, int on);
void acl_plugin_hash_acl_set_trace_heap(acl_main_t *am, int on);

#endif
