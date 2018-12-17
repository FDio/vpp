/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __MFIB_ENTRY_SRC_H__
#define __MFIB_ENTRY_SRC_H__

#include <vnet/mfib/mfib_entry.h>

/**
 * MFIB extensions to each path
 */
typedef struct mfib_path_ext_t_
{
    mfib_itf_flags_t mfpe_flags;
    fib_node_index_t mfpe_path;
} mfib_path_ext_t;

/**
 * The source of an MFIB entry
 */
typedef struct mfib_entry_src_t_
{
    /**
     * Which source this is
     */
    mfib_source_t mfes_src;

    /**
     * Route flags
     */
    mfib_entry_flags_t mfes_flags;

    /**
     * The reference count on the entry. this is a u32
     * since there is no path-list sharing in mfib, so the number
     * os children could be high.
     */
    u32 mfes_ref_count;

    /**
     * The path-list of forwarding interfaces
     */
    fib_node_index_t mfes_pl;

    /**
     * RPF-ID
     */
    fib_rpf_id_t mfes_rpf_id;

    /**
     * Hash table of path extensions
     */
    mfib_path_ext_t *mfes_exts;

    /**
     * Covering entry (if needed)
     */
    struct {
        fib_node_index_t mfes_cover;
        u32 mfes_sibling;
    };

    /**
     * The hash table of all interfaces.
     *  This is forwarding time information derived from the paths
     *  and their extensions.
     */
    mfib_itf_t *mfes_itfs;
} mfib_entry_src_t;

/**
 * signals from the sources to the caller
 */
typedef enum mfib_src_res_t_
{
    MFIB_SRC_OK,
    MFIB_SRC_REEVALUATE,
} mfib_src_res_t;

/**
 * A function provided by each source to be invoked when it is activated
 */
typedef void (*mfib_entry_src_activiate_t) (mfib_entry_t*, mfib_entry_src_t*);

/**
 * A function provided by each source to be invoked when it is deactivated
 */
typedef void (*mfib_entry_src_deactiviate_t) (mfib_entry_t*, mfib_entry_src_t*);

/**
 * A function provided by each source to be invoked when the cover changes
 */
typedef mfib_src_res_t (*mfib_entry_src_cover_change_t) (mfib_entry_t*, mfib_entry_src_t*);

/**
 * A function provided by each source to be invoked when the cover is updated
 */
typedef mfib_src_res_t (*mfib_entry_src_cover_update_t) (mfib_entry_t*, mfib_entry_src_t*);

/**
 * Virtual function table provided by each_source
 */
typedef struct mfib_entry_src_vft_t_
{
    mfib_entry_src_activiate_t mev_activate;
    mfib_entry_src_deactiviate_t mev_deactivate;
    mfib_entry_src_cover_change_t mev_cover_change;
    mfib_entry_src_cover_update_t mev_cover_update;
} mfib_entry_src_vft;

extern void mfib_entry_src_register(mfib_source_t, const mfib_entry_src_vft*);

extern void mfib_entry_src_deactivate(mfib_entry_t *mfib_entry,
                                      mfib_entry_src_t *bsrc);

extern void mfib_entry_src_activate(mfib_entry_t *mfib_entry,
                                    mfib_entry_src_t *bsrc);

extern mfib_src_res_t mfib_entry_src_cover_change(mfib_entry_t *mfib_entry,
                                                  mfib_entry_src_t *bsrc);

extern mfib_src_res_t mfib_entry_src_cover_update(mfib_entry_t *mfib_entry,
                                                  mfib_entry_src_t *bsrc);

extern mfib_entry_src_t* mfib_entry_get_best_src(const mfib_entry_t *mfib_entry);

extern void mfib_entry_src_module_init(void);
extern void mfib_entry_src_rr_module_init(void);

#endif
