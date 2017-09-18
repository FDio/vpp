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


#include <vnet/fib/fib_entry_src.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_path.h>
#include <vnet/fib/fib_walk.h>
#include <vnet/fib/fib_path_list.h>

static clib_error_t *
fib_module_init (vlib_main_t * vm)
{
    clib_error_t * error;

    if ((error = vlib_call_init_function (vm, dpo_module_init)))
	return (error);
    if ((error = vlib_call_init_function (vm, adj_module_init)))
	return (error);
    if ((error = vlib_call_init_function (vm, ip4_mtrie_module_init)))
	return (error);

    fib_entry_module_init();
    fib_entry_src_module_init();
    fib_path_module_init();
    fib_path_list_module_init();
    fib_walk_module_init();

    return (NULL);
}

VLIB_INIT_FUNCTION (fib_module_init);
