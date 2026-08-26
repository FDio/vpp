/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/* teib_internal.h: TEIB internals shared by the implementation and the CLI.
 *                  Not part of the public API.
 */

#ifndef __TEIB_INTERNAL_H__
#define __TEIB_INTERNAL_H__

#include <vnet/teib/teib.h>

/**
 * Walk every entry, yielding its index. Used by the CLI, which prints the
 * index and formats the entry from it.
 */
typedef walk_rc_t (*teib_walk_index_cb_t) (index_t tei, void *ctx);

extern void teib_walk_index (teib_walk_index_cb_t fn, void *ctx);

extern u8 *format_teib_entry (u8 *s, va_list *args);

#endif
