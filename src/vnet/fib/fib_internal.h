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

#ifndef __FIB_INTERNAL_H__
#define __FIB_INTERNAL_H__

#include <vnet/ip/ip.h>
#include <vnet/dpo/dpo.h>

/**
 * Big train switch; FIB debugs on or off
 */
#undef FIB_DEBUG

extern void fib_prefix_from_mpls_label(mpls_label_t label,
                                       mpls_eos_bit_t eos,
				       fib_prefix_t *prf);

extern int fib_route_path_cmp(const fib_route_path_t *rpath1,
			      const fib_route_path_t *rpath2);

/**
 * @brief
 *  Add or update an entry in the FIB's forwarding table.
 * This is called from the fib_entry code. It is not meant to be used
 * by the client/source.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix for the entry to add/update
 *
 * @param dpo
 *  The data-path object to use for forwarding
 */
extern void fib_table_fwding_dpo_update(u32 fib_index,
					const fib_prefix_t *prefix,
					const dpo_id_t *dpo);
/**
 * @brief
 *  remove an entry in the FIB's forwarding table
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix for the entry to add/update
 *
 * @param dpo
 *  The data-path object to use for forwarding
 */
extern void fib_table_fwding_dpo_remove(u32 fib_index,
					const fib_prefix_t *prefix,
					const dpo_id_t *dpo);


#endif
