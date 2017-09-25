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

#include <vnet/fib/fib_trkr.h>

/**
 * Add a tracker on an address
 */
void
fib_trkr_addr_add (u32 fib_index,
                   const ip46_address_t *addr,
                   fib_node_type_t child_type,
                   fib_node_index_t child_index,
                   fib_trkr_t *trkr)
{
    fib_prefix_t pfx;
    fib_prefix_from_ip46_addr(addr, &pfx);

    trkr->ftk_fei = fib_table_entry_special_add(fib_index,
                                                &pfx,
                                                FIB_SOURCE_RR,
                                                FIB_ENTRY_FLAG_NONE);
    trkr->ftk_sibling = fib_entry_child_add(trkr->ftk_fei,
                                            child_type,
                                            child_index);
}

void
fib_trkr_release (fib_trkr_t *trkr)
{
    fib_entry_child_remove(trkr->ftk_fei,
                           trkr->ftk_sibling);
    fib_table_entry_delete_index(trkr->ftk_fei,
                                 FIB_SOURCE_RR);
}
