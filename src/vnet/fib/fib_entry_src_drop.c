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
fib_entry_src_drop_init (fib_entry_src_t *src)
{
    src->fes_flags = FIB_ENTRY_SRC_FLAG_NONE;
}

static void
fib_entry_src_drop_remove (fib_entry_src_t *src)
{
    src->fes_pl = FIB_NODE_INDEX_INVALID;
}

static void
fib_entry_src_drop_add (fib_entry_src_t *src,
				 const fib_entry_t *entry,
				 fib_entry_flag_t flags,
				 dpo_proto_t proto,
				 const dpo_id_t *dpo)
{
    src->fes_pl = fib_path_list_create_special(proto,
					       FIB_PATH_LIST_FLAG_DROP,
					       dpo);
}

const static fib_entry_src_vft_t drop_src_vft = {
    .fesv_init = fib_entry_src_drop_init,
    .fesv_add = fib_entry_src_drop_add,
    .fesv_remove = fib_entry_src_drop_remove,
};

void
fib_entry_src_drop_register (void)
{
    fib_entry_src_behaviour_register(FIB_SOURCE_BH_DROP,
                                     &drop_src_vft);
}


