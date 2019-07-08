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

#include <vppinfra/mem.h>

/* Vector of all bihashes */
void **clib_all_bihashes;
static void **clib_all_bihash_heap;

void *clib_all_bihash_set_heap (void)
{
    if (PREDICT_FALSE(clib_all_bihash_heap == 0))
        clib_all_bihash_heap = clib_mem_get_heap();

    return clib_mem_set_heap(clib_all_bihash_heap);
}
