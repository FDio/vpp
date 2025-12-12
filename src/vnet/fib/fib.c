/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#include <vnet/fib/fib_entry_src.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_path.h>
#include <vnet/fib/fib_walk.h>
#include <vnet/fib/fib_path_list.h>

static clib_error_t *
fib_module_init (vlib_main_t * vm)
{
    fib_source_module_init();
    fib_entry_module_init();
    fib_entry_src_module_init();
    fib_path_module_init();
    fib_path_list_module_init();
    fib_walk_module_init();

    return (NULL);
}

VLIB_INIT_FUNCTION (fib_module_init) =
{
    .runs_after = VLIB_INITS("dpo_module_init", "adj_module_init"),
};
