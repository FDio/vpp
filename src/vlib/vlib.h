/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* vlib.h: top-level include file */

#ifndef included_vlib_h
#define included_vlib_h

#include <vppinfra/clib.h>
#include <vppinfra/elf_clib.h>
#include <vppinfra/callback.h>

/* Generic definitions. */
#include <vlib/defs.h>

/* Forward declarations of structs to avoid circular dependencies. */
struct vlib_main_t;
struct vlib_global_main_t;
typedef u32 vlib_log_class_t;

/* All includes in alphabetical order. */
#include <vlib/physmem.h>
#include <vlib/buffer.h>
#include <vlib/cli.h>
#include <vlib/counter.h>
#include <vlib/error.h>
#include <vlib/init.h>
#include <vlib/node.h>
#include <vlib/punt.h>
#include <vlib/trace.h>
#include <vlib/log.h>

/* Main include depends on other vlib/ includes so we put it last. */
#include <vlib/main.h>

/* Inline/extern function declarations. */
#include <vlib/threads.h>
#include <vlib/physmem_funcs.h>
#include <vlib/buffer_funcs.h>
#include <vlib/tw_funcs.h>
#include <vlib/error_funcs.h>
#include <vlib/format_funcs.h>
#include <vlib/node_funcs.h>
#include <vlib/trace_funcs.h>
#include <vlib/global_funcs.h>
#include <vlib/buffer_node.h>

#endif /* included_vlib_h */
