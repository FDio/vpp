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

#ifndef __MEM_USAGE_H__
#define __MEM_USAGE_H__

#include <vlib/vlib.h>

/**
 * Standard function that provides cute formatting of objects
 */
extern void memory_usage_show (vlib_main_t *vm, const char *name,
			       u32 in_use_elts, u32 allocd_elts,
			       size_t size_elt);

/**
 * Callback function the system will invoke on the module to display
 * its memory usage
 */
typedef void (*memory_usage_fn_t) (vlib_main_t *vm);

/**
 * Register a callback function
 */
extern void memory_usage_register (memory_usage_fn_t fn);

#endif
