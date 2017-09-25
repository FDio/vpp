/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef __FIB_TRKR_H__
#define __FIB_TRKR_H__

#include <vnet/fib/fib_table.h>

/**
 * APIs to register a dependency on, i.e. to track, an entry in the
 * FIB table
 */
typedef struct fib_trkr_t_
{
    /**
     * The FIB entry tracked
     */
    fib_node_index_t ftk_fei;

    /**
     * Sibling index on the Fib Entry
     */
    u32 ftk_sibling;
} fib_trkr_t;

/**
 * Add a tracker on an address
 */
extern void fib_trkr_addr_add(u32 fib_index,
                              const ip46_address_t *addr,
                              fib_node_type_t child_type,
                              fib_node_index_t child_index,
                              fib_trkr_t *tkrk);

extern void fib_trkr_release(fib_trkr_t *tkrk);

#endif
