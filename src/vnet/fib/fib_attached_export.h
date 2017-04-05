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
/**
 * FIB attached export
 *
 * what's it all about?
 * say one does this:
 *    set int ip table Gig0 2
 *    set int ip addr  Gig0 10.0.0.1/24
 * Ggi0 is in table 2 with a connected address.
 * Now we add a routing matching said connected in a different table
 *    ip route add table 3 10.0.0.0/24 via Gig0
 * How do we expect traffic in table 3 to be forwarded? Clearly out of
 * Ggi0. It's an attached route, hence we are saying that we can ARP for
 * hosts in the attached subnet. and we can. but any ARP entries we send
 * we be received on Gig0, but since Gig0 is in table 2, it will install
 * the adj-fins in table 2. So traffic in table 3 will never hit an adj-fib
 * and hence always the glean, and so thus be effectively dropped.
 * How do we fix this? Attached Export !! All more specfiic entries in table 2
 * that track and are covered by the connected are automatically exported into
 * table 3. Now table 3 also has adj-fibs (and the local) so traffic to hosts
 * is restored.
 */

#ifndef __FIB_ATTACHED_EXPORT_H__
#define __FIB_ATTACHED_EXPORT_H__

#include <vnet/fib/fib_types.h>

extern void fib_attached_export_import(fib_entry_t *fib_entry,
				       fib_node_index_t export_fib);
				       
extern void fib_attached_export_purge(fib_entry_t *fib_entry);

extern void fib_attached_export_covered_added(fib_entry_t *cover,
					      fib_node_index_t covered);
extern void fib_attached_export_covered_removed(fib_entry_t *cover,
						fib_node_index_t covered);
extern void fib_attached_export_cover_change(fib_entry_t *fib_entry);
extern void fib_attached_export_cover_update(fib_entry_t *fib_entry);

extern u8* fib_ae_import_format(fib_node_index_t impi, u8*s);
extern u8* fib_ae_export_format(fib_node_index_t expi, u8*s);

#endif
