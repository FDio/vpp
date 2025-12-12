/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
