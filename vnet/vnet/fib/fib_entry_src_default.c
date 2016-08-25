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

#include "fib_entry.h"
#include "fib_entry_src.h"
#include "fib_path_list.h"

/**
 * Source initialisation Function 
 */
static void
fib_entry_src_default_init (fib_entry_src_t *src)
{
}

/**
 * Source deinitialisation Function 
 */
static void
fib_entry_src_default_deinit (fib_entry_src_t *src)
{
}

static void
fib_entry_src_cover_change (fib_entry_src_t *src)
{
}

/**
 * Source deinitialisation Function 
 */
static void
fib_entry_src_default_deinit (fib_entry_src_t *src)
{
}

static void
fib_entry_src_default_path_add (fib_entry_src_t *src,
				fib_protocol_t proto,
				const ip46_address_t *next_hop,
				u32 next_hop_sw_if_index,
				u32 next_hop_fib_index,
				u32 next_hop_weight)
{
}

static void
fib_entry_src_default_path_remove (fib_entry_src_t *src,
				     fib_protocol_t proto,
				     const ip46_address_t *next_hop,
				     u32 next_hop_sw_if_index,
				     u32 next_hop_fib_index,
				     u32 next_hop_weight)
{
}


/*
 * Source activate. 
 * Called when the source is teh new longer best source on the entry
 */
static void
fib_entry_src_default_activate (fib_entry_src_t *src,
				  const fib_entry_t *fib_entry)
{
}

/*
 * Source Deactivate. 
 * Called when the source is no longer best source on the entry
 */
static void
fib_entry_src_default_deactivate (fib_entry_src_t *src,
				    const fib_entry_t *fib_entry)
{
}

static void
fib_entry_src_default_add (fib_entry_src_t *src,
			     fib_entry_flag_t flags,
			     fib_protocol_t proto)
{
}

static void
fib_entry_src_default_remove (fib_entry_src_t *src)			     
{
}

const static fib_entry_src_vft_t default_src_vft = {
    .fesv_init = fib_entry_src_default_init,
    .fesv_deinit = fib_entry_src_default_deinit,
    .fesv_add = fib_entry_src_default_add,
    .fesv_remove = fib_entry_src_default_remove,
    .fesv_path_add = fib_entry_src_default_path_add,
    .fesv_path_remove = fib_entry_src_default_path_remove,
    .fesv_activate = fib_entry_src_default_activate,
    .fesv_deactivate = fib_entry_src_default_deactivate,
};

void
fib_entry_src_default_register (void)
{
    fib_source_t source;

    FOR_EACH_FIB_SOURCE(source) {
	fib_entry_src_register(source, &default_src_vft);    
    }
}
