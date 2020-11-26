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

#ifndef __FIB_ENTRY_SRC_H__
#define __FIB_ENTRY_SRC_H__

#include "fib_entry.h"
#include "fib_path_list.h"
#include "fib_internal.h"

/**
 * Debug macro
 */
extern vlib_log_class_t fib_entry_logger;

#define FIB_ENTRY_DBG(_e, _fmt, _args...)		\
{   		          				\
    vlib_log_debug(fib_entry_logger,                    \
                   "[@%d:[%U]:%U:%U]: " _fmt,           \
                   fib_entry_get_index(_e),		\
                   format_fib_prefix,                   \
                   &_e->fe_prefix,                      \
                   format_fib_entry_flags,              \
                   fib_entry_get_flags_i(_e),           \
                   format_fib_source,                   \
                   fib_entry_get_source_i(_e),          \
                   ##_args);                            \
}

/**
 * Source initialisation Function 
 */
typedef void (*fib_entry_src_init_t)(fib_entry_src_t *src);

/**
 * Source deinitialisation Function 
 */
typedef void (*fib_entry_src_deinit_t)(fib_entry_src_t *src);

/**
 * Source activation. Called when the source is the new best source on the entry.
 * Return non-zero if the entry can now install, 0 otherwise
 */
typedef int (*fib_entry_src_activate_t)(fib_entry_src_t *src,
					 const fib_entry_t *fib_entry);

/**
 * Source re-activation. Called when the source is updated and remains
 * the best source.
 */
typedef int (*fib_entry_src_reactivate_t)(fib_entry_src_t *src,
                                          const fib_entry_t *fib_entry);

/**
 * Source Deactivate. 
 * Called when the source is no longer best source on the entry
 */
typedef void (*fib_entry_src_deactivate_t)(fib_entry_src_t *src,
					   const fib_entry_t *fib_entry);

/**
 * Source Add.
 * Called when the source is added to the entry
 */
typedef void (*fib_entry_src_add_t)(fib_entry_src_t *src,
				    const fib_entry_t *entry,
				    fib_entry_flag_t flags,
				    dpo_proto_t proto,
				    const dpo_id_t *dpo);

/**
 * Source Remove.
 */
typedef void (*fib_entry_src_remove_t)(fib_entry_src_t *src);

/**
 * Result from a cover update/change
 */
typedef struct fib_entry_src_cover_res_t_ {
    u16 install;
    fib_node_bw_reason_flag_t bw_reason;
} fib_entry_src_cover_res_t;

/**
 * Cover changed. the source should re-evaluate its cover.
 */
typedef fib_entry_src_cover_res_t (*fib_entry_src_cover_change_t)(
    fib_entry_src_t *src,
    const fib_entry_t *fib_entry);

/**
 * Cover updated. The cover the source has, has updated (i.e. its forwarding)
 * the source may need to re-evaluate.
 */
typedef fib_entry_src_cover_res_t (*fib_entry_src_cover_update_t)(
    fib_entry_src_t *src,
    const fib_entry_t *fib_entry);

/**
 * Forwarding updated. Notification that the forwarding information for the
 * entry has been updated. This notification is sent to all sources, not just
 * the active best.
 */
typedef void (*fib_entry_src_fwd_update_t)(fib_entry_src_t *src,
					   const fib_entry_t *fib_entry,
					   fib_source_t best_source);

/**
 * Installed. Notification that the source is now installed as
 * the entry's forwarding source.
 */
typedef void (*fib_entry_src_installed_t)(fib_entry_src_t *src,
					  const fib_entry_t *fib_entry);

/**
 * format.
 */
typedef u8* (*fib_entry_src_format_t)(fib_entry_src_t *src,
				      u8* s);

/**
 * Source path add
 * the source is adding a new path
 */
typedef void (*fib_entry_src_path_add_t)(fib_entry_src_t *src,
					 const fib_entry_t *fib_entry,
					 fib_path_list_flags_t pl_flags,
					 const fib_route_path_t *path);

/**
 * Source path remove
 * the source is remoinvg a path
 */
typedef void (*fib_entry_src_path_remove_t)(fib_entry_src_t *src,
					    fib_path_list_flags_t pl_flags,
					    const fib_route_path_t *path);

/**
 * Source path replace/swap
 * the source is providing a new set of paths
 */
typedef void (*fib_entry_src_path_swap_t)(fib_entry_src_t *src,
					  const fib_entry_t *fib_entry,
					  fib_path_list_flags_t pl_flags,
					  const fib_route_path_t *path);

/**
 * Set source specific opaque data
 */
typedef void (*fib_entry_src_set_data_t)(fib_entry_src_t *src,
                                         const fib_entry_t *fib_entry,
                                         const void *data);

/**
 * Get source specific opaque data
 */
typedef const void* (*fib_entry_src_get_data_t)(fib_entry_src_t *src,
                                                const fib_entry_t *fib_entry);

/**
 * Contribute forwarding to interpose inthe chain
 */
typedef const dpo_id_t* (*fib_entry_src_contribute_interpose_t)(const fib_entry_src_t *src,
                                                         const fib_entry_t *fib_entry);

/**
 * The fib entry flags for this source are changing
 */
typedef void (*fib_entry_src_flag_change_t)(fib_entry_src_t *src,
                                            const fib_entry_t *fib_entry,
                                            fib_entry_flag_t new_flags);

/**
 * The fib entry flags for this source are changing
 */
typedef void (*fib_entry_src_copy_t)(const fib_entry_src_t *orig_src,
                                     const fib_entry_t *fib_entry,
                                     fib_entry_src_t *copy_src);

/**
 * Virtual function table each FIB entry source will register
 */
typedef struct fib_entry_src_vft_t_ {
    fib_entry_src_init_t fesv_init;
    fib_entry_src_deinit_t fesv_deinit;
    fib_entry_src_activate_t fesv_activate;
    fib_entry_src_deactivate_t fesv_deactivate;
    fib_entry_src_reactivate_t fesv_reactivate;
    fib_entry_src_add_t fesv_add;
    fib_entry_src_remove_t fesv_remove;
    fib_entry_src_path_swap_t fesv_path_swap;
    fib_entry_src_path_add_t fesv_path_add;
    fib_entry_src_path_remove_t fesv_path_remove;
    fib_entry_src_cover_change_t fesv_cover_change;
    fib_entry_src_cover_update_t fesv_cover_update;
    fib_entry_src_format_t fesv_format;
    fib_entry_src_installed_t fesv_installed;
    fib_entry_src_fwd_update_t fesv_fwd_update;
    fib_entry_src_get_data_t fesv_get_data;
    fib_entry_src_set_data_t fesv_set_data;
    fib_entry_src_contribute_interpose_t fesv_contribute_interpose;
    fib_entry_src_flag_change_t fesv_flags_change;
    fib_entry_src_copy_t fesv_copy;
} fib_entry_src_vft_t;

#define FOR_EACH_SRC_ADDED(_entry, _src, _source, action)	\
{								\
    vec_foreach(_src, (_entry)->fe_srcs)                        \
    {								\
	if (_src->fes_flags & FIB_ENTRY_SRC_FLAG_ADDED) {	\
	    _source = (_src)->fes_src;				\
            action;						\
	}							\
    }								\
}

#define FIB_ENTRY_SRC_VFT_INVOKE(_fe, esrc, func, args)        \
{                                                              \
    const fib_entry_src_vft_t *_vft;                           \
    fib_node_index_t _fei = fib_entry_get_index(_fe);          \
    _vft = fib_entry_src_get_vft(esrc);                        \
    if (_vft->func) {                                          \
        (esrc)->fes_flags &= ~FIB_ENTRY_SRC_FLAG_STALE;        \
        _vft->func args;                                       \
    }                                                          \
    _fe = fib_entry_get(_fei);                                 \
}

#define FIB_ENTRY_SRC_VFT_INVOKE_AND_RETURN(esrc, func, args)  \
{                                                              \
    const fib_entry_src_vft_t *_vft;                           \
    _vft = fib_entry_src_get_vft(esrc);                        \
    if (_vft->func) {                                          \
        (esrc)->fes_flags &= ~FIB_ENTRY_SRC_FLAG_STALE;        \
        return (_vft->func args);                              \
    }                                                          \
}

#define FIB_ENTRY_SRC_VFT_EXISTS(esrc, func)        \
{                                                   \
    const fib_entry_src_vft_t *_vft;                \
    _vft = fib_entry_src_get_vft(esrc);             \
    (_vft->func);                                   \
}

extern const fib_entry_src_vft_t*fib_entry_src_get_vft(
    const fib_entry_src_t *esrc);

extern fib_entry_src_t * fib_entry_src_find (const fib_entry_t *fib_entry,
                                             fib_source_t source);
extern u8* fib_entry_src_format(fib_entry_t *entry,
				fib_source_t source,
				u8* s);

extern void fib_entry_src_behaviour_register (fib_source_behaviour_t source,
                                              const fib_entry_src_vft_t *vft);

extern fib_entry_src_cover_res_t fib_entry_src_action_cover_change(
    fib_entry_t *entry,
    fib_entry_src_t *esrc);

extern fib_entry_src_cover_res_t fib_entry_src_action_cover_update(
    fib_entry_t *fib_entry,
    fib_entry_src_t *esrc);

extern void fib_entry_src_action_activate(fib_entry_t *fib_entry,
					  fib_source_t source);

extern void fib_entry_src_action_deactivate(fib_entry_t *fib_entry,
					    fib_source_t source);
extern void fib_entry_src_action_reactivate(fib_entry_t *fib_entry,
					    fib_source_t source);

extern fib_entry_t* fib_entry_src_action_add(fib_entry_t *fib_entry,
					     fib_source_t source,
					     fib_entry_flag_t flags,
					     const dpo_id_t *dpo);
extern fib_entry_t* fib_entry_src_action_update(fib_entry_t *fib_entry,
						fib_source_t source,
						fib_entry_flag_t flags,
						const dpo_id_t *dpo);

extern fib_entry_src_flag_t fib_entry_src_action_remove(fib_entry_t *fib_entry,
							fib_source_t source);
extern fib_entry_src_flag_t
fib_entry_src_action_remove_or_update_inherit(fib_entry_t *fib_entry,
                                              fib_source_t source);

extern void fib_entry_src_action_install(fib_entry_t *fib_entry,
					 fib_source_t source);

extern void fib_entry_src_action_uninstall(fib_entry_t *fib_entry);

extern fib_entry_t* fib_entry_src_action_path_add(fib_entry_t *fib_entry,
						  fib_source_t source,
						  fib_entry_flag_t flags,
						  const fib_route_path_t *path);

extern fib_entry_t* fib_entry_src_action_path_swap(fib_entry_t *fib_entry,
						   fib_source_t source,
						   fib_entry_flag_t flags,
						   const fib_route_path_t *path);

extern fib_entry_src_flag_t fib_entry_src_action_path_remove(fib_entry_t *fib_entry,
							     fib_source_t source,
							     const fib_route_path_t *path);

extern fib_entry_t* fib_entry_src_action_installed(fib_entry_t *fib_entry,
                                                   fib_source_t source);
extern void fib_entry_src_inherit (const fib_entry_t *cover,
                                   fib_entry_t *covered);

extern fib_forward_chain_type_t fib_entry_get_default_chain_type(
    const fib_entry_t *fib_entry);
extern fib_source_t fib_entry_get_source_i(const fib_entry_t *fib_entry);
extern fib_entry_flag_t fib_entry_get_flags_i(const fib_entry_t *fib_entry);

extern fib_path_list_flags_t fib_entry_src_flags_2_path_list_flags(
    fib_entry_flag_t eflags);

extern fib_forward_chain_type_t fib_entry_chain_type_fixup(const fib_entry_t *entry,
                                                           fib_forward_chain_type_t fct);

extern void fib_entry_src_mk_lb (fib_entry_t *fib_entry,
				 const fib_entry_src_t *esrc,
				 fib_forward_chain_type_t fct,
				 dpo_id_t *dpo_lb);

extern fib_protocol_t fib_entry_get_proto(const fib_entry_t * fib_entry);
extern dpo_proto_t fib_entry_get_dpo_proto(const fib_entry_t * fib_entry);

extern void fib_entry_source_change(fib_entry_t *fib_entry,
                                    fib_source_t old_source,
                                    fib_source_t new_source);

/*
 * Per-source registration. declared here so we save a separate .h file for each
 */
extern void fib_entry_src_default_register(void);
extern void fib_entry_src_rr_register(void);
extern void fib_entry_src_interface_register(void);
extern void fib_entry_src_interpose_register(void);
extern void fib_entry_src_drop_register(void);
extern void fib_entry_src_simple_register(void);
extern void fib_entry_src_api_register(void);
extern void fib_entry_src_adj_register(void);
extern void fib_entry_src_mpls_register(void);
extern void fib_entry_src_lisp_register(void);

extern void fib_entry_src_module_init(void);

#endif
