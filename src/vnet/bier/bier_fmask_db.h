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

#include <vnet/fib/fib_types.h>

/**
 * BIER header encapulsation types
 */
typedef enum bier_hdr_type_t_ {
    /**
     * BIER Header in MPLS networks
     */
    BIER_HDR_O_MPLS,

    /**
     * BIER header in non-MPLS networks
     */
    BIER_HDR_O_OTHER,
} __attribute__((packed)) bier_hdr_type_t;

/**
 * BIER next-hop type
 */
typedef enum bier_nh_type_t_ {
    /**
     * BIER Header in MPLS networks
     */
    BIER_NH_IP,

    /**
     * BIER header in non-MPLS networks
     */
    BIER_NH_UDP,
} __attribute__((packed)) bier_nh_type_t;

/**
 * A key/ID for a BIER forwarding Mas (FMask).
 * This is a simplified version of a fib_route_path_t.
 */
typedef struct bier_fmask_id_t_ {
    union {
        /**
         * next-hop of the peer
         */
        ip46_address_t bfmi_nh;

        /**
         * ID of the next-hop object, e.g. a UDP-encap
         */
        u32 bfmi_id;
    };
    /**
     * The BIER table this fmask is in
     */
    index_t bfmi_bti;

    /**
     * Type of BIER header this fmask supports
     */
    bier_hdr_type_t bfmi_hdr_type;

    /**
     * Union discriminatrr
     */
    bier_nh_type_t bfmi_nh_type;
} __attribute__((packed)) bier_fmask_id_t;

extern index_t
bier_fmask_db_find_or_create_and_lock(index_t bti,
                                      const fib_route_path_t *rpath);
extern index_t bier_fmask_db_find (index_t bti,
                                   const fib_route_path_t *rpath);

extern void bier_fmask_db_remove (const bier_fmask_id_t *fmid);

/**
 * Walk all the BIER fmasks
 */
typedef walk_rc_t (*bier_fmask_walk_fn_t) (index_t bfmi, void *ctx);

extern void bier_fmask_db_walk(bier_fmask_walk_fn_t fn, void *ctx);

#endif
