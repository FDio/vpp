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
 * @brief bier_fmask_db : The BIER fmask Database
 */

#ifndef __BIER_FMASK_DB_H__
#define __BIER_FMASK_DB_H__

#include <vnet/ip/ip.h>

#include <vnet/bier/bier_types.h>

/**
 * Foward declarations
 */
struct bier_fmask_t_;

typedef enum bier_hdr_type_t_ {
    BIER_HDR_IN_IP6,
    BIER_HDR_O_MPLS,
} bier_hdr_type_t;

typedef struct bier_fmask_id_t_ {
    /**
     * Type of BIER header this fmask supports
     */
    bier_hdr_type_t bfmi_hdr_type;

    /**
     * next-hop of the peer
     */
    ip46_address_t bfmi_nh;
} bier_fmask_id_t;

extern u32
bier_fmask_db_find_or_create_and_lock(index_t bti,
                                      const bier_fmask_id_t *fmid,
                                      const fib_route_path_t *rpath);

extern u32
bier_fmask_db_find(index_t bti,
                   const bier_fmask_id_t *fmid);

extern void
bier_fmask_db_remove(index_t bti,
                     const bier_fmask_id_t *fmid);

#endif
