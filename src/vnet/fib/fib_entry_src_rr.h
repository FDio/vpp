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

#ifndef __FIB_ENTRY_SRC_RR_H__
#define __FIB_ENTRY_SRC_RR_H__

#include "fib_entry_src.h"

/*
 * the flags that an RR sourced entry can inherit from its cover
 */
#define FIB_ENTRY_FLAGS_RR_INHERITED (FIB_ENTRY_FLAG_CONNECTED | \
                                      FIB_ENTRY_FLAG_ATTACHED)

/*
 * fib_entry_src_rr_resolve_via_connected
 *
 * Resolve via a connected cover.
 */
void
fib_entry_src_rr_resolve_via_connected (fib_entry_src_t *src,
					const fib_entry_t *fib_entry,
					const fib_entry_t *cover);

/*
 * use the path-list of the cover, unless it would form a loop.
 * that is unless the cover is via this entry.
 * If a loop were to form it would be a 1 level loop (i.e. X via X),
 * and there would be 2 locks on the path-list; one since its used
 * by the cover, and 1 from here. The first lock will go when the
 * cover is removed, the second, and last, when the covered walk
 * occurs during the cover's removel - this is not a place where
 * we can handle last lock gone.
 * In short, don't let the loop form. The usual rules of 'we must
 * let it form so we know when it breaks' don't apply here, since
 * the loop will break when the cover changes, and this function
 * will be called again when that happens.
 */
void
fib_entry_src_rr_use_covers_pl (fib_entry_src_t *src,
                                const fib_entry_t *fib_entry,
                                const fib_entry_t *cover);


/*
 * fib_entry_src_rr_cover_update
 *
 * This entry's cover has changed. This entry
 * will need to re-inheret.
 */
fib_entry_src_cover_res_t
fib_entry_src_rr_cover_change (fib_entry_src_t *src,
			       const fib_entry_t *fib_entry);

/*
 * fib_entry_src_rr_cover_update
 *
 * This entry's cover has updated its forwarding info. This entry
 * will need to re-inheret.
 */
fib_entry_src_cover_res_t
fib_entry_src_rr_cover_update (fib_entry_src_t *src,
			       const fib_entry_t *fib_entry);

#endif
