/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __MFIB_ENTRY_COVER_H__
#define __MFIB_ENTRY_COVER_H__

#include <vnet/mfib/mfib_entry.h>

/**
 * callback function used when walking the covered entries
 */
typedef int (*mfib_entry_covered_walk_t)(mfib_entry_t *cover,
                                         fib_node_index_t covered,
                                         void *ctx);

extern u32 mfib_entry_cover_track(mfib_entry_t *cover,
                                  fib_node_index_t covered);

extern void mfib_entry_cover_untrack(mfib_entry_t *cover,
                                     u32 tracked_index);

extern void mfib_entry_cover_walk(mfib_entry_t *cover,
                                  mfib_entry_covered_walk_t walk,
                                  void *ctx);

extern void mfib_entry_cover_change_notify(fib_node_index_t cover_index,
                                           fib_node_index_t covered_index);
extern void mfib_entry_cover_update_notify(mfib_entry_t *cover);

#endif
