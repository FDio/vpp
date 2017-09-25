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

#ifndef __TUNNEL_H__
#define __TUNNEL_H__

#include <vnet/ip/ip.h>
#include <vnet/fib/fib_trkr.h>

/**
 * The tunnel Databse.
 * Herein is maintained a databse of the IP tunnels created.
 * All IP tunnels (e.g. VxLAN, LISP, GRE, etc) can be added to the
 * DB. The data base is optimised for fast retrieval of the tunnel
 * context in the decap data path.
 *
 * Fast retreival is performed based on the matched destination
 * and source FIB entries. This matched enties can be described
 * in only 16 and 28 bits respectively (i.e. a good hash) leaving
 * the tunnel protocol 20 bits of a 64 bit key. The tunnel can
 * thus be matched in the protocol specific DB using a single
 * 64 bit key'd lookup.
 * At this point you might be asking yourself, how are the FIB
 * entry/load-balance IDs constant over the lifetime of the tunnel
 * given that the matching FIB entry for the tunnel srouce may change.
 * The act of tracking a prefix in the FIB will in sert the host prefix
 * and it will remain while it is tracked, and hence the tunnel-ID
 * will remain fixed. Load-balance objects are always inplace modified.
 */

/**
 * bottom 20 bits are available for a tunnel protocol to use to
 * form their own 64 bit key.
 */
typedef u64 tunnel_id_t;

/**
 * Add a source,destination IP address pair to the tunnel decap
 * DB. The tunnel is returned with the lock/refernce count increased.
 *
 * @param: fib_index - VPP's internal FIB index in which the addresses are valid
 * @param src - Tunnel source address
 * @param src - Tunnel destination address
 * @return index of the tunnel
 */
extern index_t tunnel_add_or_lock(u32 fib_index,
                                  const ip46_address_t *src,
                                  const ip46_address_t *dst);

/**
 * Find a tunnel
 *
 * @param: fib_index - VPP's internal FIB index in which the addresses are valid
 * @param src - Tunnel source address
 * @param src - Tunnel destination address
 * @return The index of the tunnel if it exists, INVALID otherwise
 */
extern index_t tunnel_find(u32 fib_index,
                           const ip46_address_t *src,
                           const ip46_address_t *dst);

/**
 * Unlock (decrease the reference count) on a tunnel
 */
extern void tunnel_unlock(index_t tunnel_index);

/**
 * Get the tunnel's unique ID
 */
extern tunnel_id_t tunnel_get_id(index_t tunnel_index);

/**
 * Get the tunnels tracked destination FIB entry. Usefull to
 * get the forwarding information for tunnel stacking.
 */
extern fib_node_index_t tunnel_dst_fib_entry(index_t tunnel_index);

/**
 * Display/show/format a tunnel.
 */
extern u8 *format_tunnel(u8 * s, va_list * args);

/**
 * Build a tunnel ID from the RX and TX indecies. Use in the data-path
 * when performing tunnel decap.
 */
static inline tunnel_id_t
tunnel_mk_id (index_t rx,
              index_t tx)
{
    tunnel_id_t tid;

    /*
     * Form the tunnel ID
     * put a 4 bit shifted TX ID in the high order bits.
     * followed by the RX ID
     */
    tid = tx;
    tid = tid << 16;
    tid |= rx;
    tid = tid << 20;

    return (tid);
}

#endif
