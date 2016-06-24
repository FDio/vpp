/* 
 *------------------------------------------------------------------
 * cnat_bulk_port_defs.h bulk port alloc definitions
 *
 * Copyright (c) 2011-2013 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef __CNAT_BULK_PORT_H__
#define __CNAT_BULK_PORT_H__

#ifndef NO_BULK_LOGGING
#include "cnat_bulk_port_defs.h"

cnat_errno_t
cnat_dynamic_port_alloc_v2_bulk (
        cnat_portmap_v2_t    *pm,
        port_alloc_t          atype,
        port_pair_t           pair_type,
        u32                  *index,
        u32                  *o_ipv4_address,
        u16                  *o_port,
        u16                  static_port_range,
        cnat_user_db_entry_t *udb,
        bulk_alloc_size_t    bulk_size,
        int                  *nfv9_log_req,
        u16                   ip_n_to_1,
        u32                  *rseed_ip);

void cnat_update_bulk_range_cache(cnat_user_db_entry_t *udb, u16 o_port,
        bulk_alloc_size_t bulk_size);

void cnat_port_free_v2_bulk (
        cnat_portmap_v2_t    *pm,
        int                index,
        port_pair_t        ptype,
        u16                base_port,
        cnat_user_db_entry_t *udb,
        u16               static_port_range,
        bulk_alloc_size_t    bulk_size,
        int                *nfv9_log_req);

cnat_errno_t cnat_static_port_alloc_v2_bulk (
        cnat_portmap_v2_t    *pm,
        port_alloc_t         atype,
        port_pair_t          pair_type,
        u32                  i_ipv4_address,
        u16                  i_port,
        u32                  *index,
        u32                  *o_ipv4_address,
        u16                  *o_port,
        u16                  static_port_range,
        cnat_user_db_entry_t *udb,
        bulk_alloc_size_t    bulk_size,
        int                  *nfv9_log_req,
	u16                  ip_n_to_1
	);

cnat_errno_t cnat_dynamic_port_alloc_rtsp_bulk (
        cnat_portmap_v2_t    *pm,
        port_alloc_t         atype,
        port_pair_t          pair_type,
        u16                  i_port,
        u32                  *index,
        u32                  *o_ipv4_address,
        u16                  *o_port,
        u16                  static_port_range,
        cnat_user_db_entry_t *udb,
        bulk_alloc_size_t    bulk_size,
        int                  *nfv9_log_req,
        u32                  *rseed_ip);

cnat_errno_t
cnat_mapped_static_port_alloc_v2_bulk (
        cnat_portmap_v2_t    *pm,
        port_alloc_t         atype,
        u32                  *index,
        u32                   ipv4_address,
        u16                   port,
        cnat_user_db_entry_t *udb,
        bulk_alloc_size_t    bulk_size,
        int                  *nfv9_log_req,
	u16                  ip_n_to_1
	);

#else /* NO_BULK_LOGGING */
/* use older code */
inline cnat_errno_t
cnat_dynamic_port_alloc_v2_bulk (
        cnat_vrfmap_t        *vrf_map,
        port_alloc_t          atype,
        port_pair_t           pair_type,
        u32                  *index,
        u32                  *o_ipv4_address,
        u16                  *o_port,
        u16                  static_port_range,
        u16                  ip_n_to_1,
        u32                  *rseed_ip
       )
{
    return cnat_dynamic_port_alloc_v2(vrf_map->portmap_list, atype,
            pair_type, index, o_ipv4_address, o_port, static_port_range,
           ip_n_to_1, rseed_ip); 
}

inline void cnat_port_free_v2_bulk (
        cnat_portmap_v2_t  *pm,
        int                index,
        port_pair_t        ptype,
        u16                base_port,
        cnat_user_db_entry_t *udb, 
        u16               static_port_range);
{
    return cnat_port_free_v2(pm, index, ptype, base_port,
            static_port_range);
}

inline cnat_errno_t cnat_static_port_alloc_v2_bulk (
        cnat_portmap_v2_t    *pm,
        port_alloc_t         atype,
        port_pair_t          pair_type,
        u32                  i_ipv4_address,
        u16                  i_port,
        u32                  *index,
        u32                  *o_ipv4_address,
        u16                  *o_port,
        u16                  static_port_range)
{
    return cnat_static_port_alloc_v2 (pm, atype, pair_type,
            i_ipv4_address, i_port, index, o_ipv4_address, o_port);
}

inline cnat_errno_t
cnat_mapped_static_port_alloc_v2_bulk (
        cnat_portmap_v2_t    *pm,
        port_alloc_t         atype,
        u32                  *index,
        u32                   ipv4_address,
        u16                   port)
{
    return cnat_mapped_static_port_alloc_v2(pm, atype, index
            ipv4_address, port);
}

#endif /* NO_BULK_LOGGING */
#endif /* __CNAT_BULK_PORT_H__ */
