/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef __FIB_ENTRY_COVER_H__
#define __FIB_ENTRY_COVER_H__

#include "fib_entry.h"

/**
 * callback function used when walking the covered entries
 */
typedef walk_rc_t (*fib_entry_covered_walk_t)(fib_entry_t *cover,
                                              fib_node_index_t covered,
                                              void *ctx);

extern u32 fib_entry_cover_track(fib_entry_t *cover,
				 fib_node_index_t covered);

extern void fib_entry_cover_untrack(fib_entry_t *cover,
				    u32 tracked_index);

extern void fib_entry_cover_walk(fib_entry_t *cover,
				 fib_entry_covered_walk_t walk,
				 void *ctx);

extern void fib_entry_cover_change_notify(fib_node_index_t cover_index,
					  fib_node_index_t covered_index);
extern void fib_entry_cover_update_notify(fib_entry_t *cover);

#endif
