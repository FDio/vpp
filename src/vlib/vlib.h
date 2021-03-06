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
/*
 * vlib.h: top-level include file
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

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
#include <vlib/error_funcs.h>
#include <vlib/format_funcs.h>
#include <vlib/node_funcs.h>
#include <vlib/trace_funcs.h>
#include <vlib/global_funcs.h>
#include <vlib/buffer_node.h>

#endif /* included_vlib_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
