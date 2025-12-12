/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#include "fib_entry.h"
#include "fib_entry_src.h"

/**
 * Source initialisation Function
 */
static void
fib_entry_src_simple_init (fib_entry_src_t *src)
{
    src->fes_flags = FIB_ENTRY_SRC_FLAG_NONE;
}

/**
 * Source deinitialisation Function
 */
static void
fib_entry_src_simple_deinit (fib_entry_src_t *src)
{
}

static void
fib_entry_src_simple_remove (fib_entry_src_t *src)
{
    src->fes_pl = FIB_NODE_INDEX_INVALID;
}

static void
fib_entry_src_simple_add (fib_entry_src_t *src,
                          const fib_entry_t *entry,
                          fib_entry_flag_t flags,
                          dpo_proto_t proto,
                          const dpo_id_t *dpo)
{
    src->fes_pl =
	fib_path_list_create_special(proto,
                                     fib_entry_src_flags_2_path_list_flags(flags),
                                     dpo);
}

static void
fib_entry_src_simple_path_swap (fib_entry_src_t *src,
                                const fib_entry_t *entry,
                                fib_path_list_flags_t pl_flags,
                                const fib_route_path_t *rpaths)
{
    src->fes_pl = fib_path_list_create((FIB_PATH_LIST_FLAG_SHARED | pl_flags),
				       rpaths);
}

const static fib_entry_src_vft_t simple_src_vft = {
    .fesv_init = fib_entry_src_simple_init,
    .fesv_deinit = fib_entry_src_simple_deinit,
    .fesv_add = fib_entry_src_simple_add,
    .fesv_remove = fib_entry_src_simple_remove,
    .fesv_path_swap = fib_entry_src_simple_path_swap,
};

void
fib_entry_src_simple_register (void)
{
    fib_entry_src_behaviour_register(FIB_SOURCE_BH_SIMPLE, &simple_src_vft);
}
