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
#include "lookup_context.h"
#include "acl.h"

/*
 * Do the necessary to logically apply the ACL to the existing vector of ACLs looked up
 * during the packet processing
 */

void hash_acl_apply(acl_main_t *am, u32 lc_index, int acl_index, u32 acl_position);

/* Remove the ACL from the packet processing in a given lookup context */

void hash_acl_unapply(acl_main_t *am, u32 lc_index, int acl_index);

/*
 * Add an ACL or delete an ACL. ACL may already have been referenced elsewhere,
 * so potentially we also need to do the work to enable the lookups.
 */

void hash_acl_add(acl_main_t *am, int acl_index);
void hash_acl_delete(acl_main_t *am, int acl_index);

/* return if there is already a filled-in hash acl info */
int hash_acl_exists(acl_main_t *am, int acl_index);

#endif
