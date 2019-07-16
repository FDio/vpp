/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef __FIB_TRACKER_H__
#define __FIB_TRACKER_H__

#include <vnet/fib/fib_entry.h>

/**
 * Trackers are used on FIB entries by objects that which to track the
 * changing state of the entry. For example a tunnel would track its
 * destination address to be informed of reachability changes.
 *
 * The benefit of this aproach is that each time a new client tracks the
 * entry it doesn't RR source it. When an entry is sourced all its children
 * are updated. Thus, new clients tracking an entry is O(n^2). With the
 * tracker as indirection, the entry is sourced only once.
 */

/**
 * Track a FIB entry
 * @param fib_index The FIB the entry is in
 * @param prefix The Prefix of the entry to track
 * @param child_type The type of object that is tracking this entry
 * @param child_index The pool index of the object tracking
 * @param sigbling [RETURNED] The sibling index of the child on the tracker
 * @return The index of the FIB entry
 */
extern fib_node_index_t fib_entry_track(u32 fib_index,
                                        const fib_prefix_t *prefix,
                                        fib_node_type_t child_type,
                                        index_t child_index,
                                        u32 *sibling);

/**
 * Stop tracking a FIB entry
 * @param fei FIB entry index (as returned from the track API above)
 * @param sibling Sibling index (as returned from the track API above)
 */
extern void fib_entry_untrack(fib_node_index_t fei,
                              u32 sibling);

extern void fib_entry_track_module_init(void);

#endif
