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
#ifdef FIB_DEBUG
#define FIB_ENTRY_DBG(_e, _fmt, _args...)		\
{   		          				\
    u8*__tmp = NULL;					\
    __tmp = format(__tmp, "e:[%d:%U",			\
		   fib_entry_get_index(_e),		\
		   format_ip46_address,			\
		   &_e->fe_prefix.fp_addr,		\
		   IP46_TYPE_ANY);			\
    __tmp = format(__tmp, "/%d]:",			\
		   _e->fe_prefix.fp_len);		\
    __tmp = format(__tmp, _fmt, ##_args);		\
    clib_warning("%s", __tmp);				\
    vec_free(__tmp);					\
}
#else
#define FIB_ENTRY_DBG(_e, _fmt, _args...)
#endif

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
 * Virtual function table each FIB entry source will register
 */
typedef struct fib_entry_src_vft_t_ {
    fib_entry_src_init_t fesv_init;
    fib_entry_src_deinit_t fesv_deinit;
    fib_entry_src_activate_t fesv_activate;
    fib_entry_src_deactivate_t fesv_deactivate;
    fib_entry_src_add_t fesv_add;
    fib_entry_src_remove_t fesv_remove;
    fib_entry_src_path_swap_t fesv_path_swap;
    fib_entry_src_path_add_t fesv_path_add;
    fib_entry_src_path_remove_t fesv_path_remove;
    fib_entry_src_cover_change_t fesv_cover_change;
    fib_entry_src_cover_update_t fesv_cover_update;
    fib_entry_src_format_t fesv_format;
    fib_entry_src_installed_t fesv_installed;
    fib_entry_src_get_data_t fesv_get_data;
    fib_entry_src_set_data_t fesv_set_data;
} fib_entry_src_vft_t;

#define FOR_EACH_SRC_ADDED(_entry, _src, _source, action)        \
{                                                                \
    if (fib_entry_has_multiple_srcs(_entry))                     \
    {                                                            \
        vec_foreach(_src, _entry->fe_u_src.fe_srcs)              \
        {                                                        \
            if (_src->fes_flags & FIB_ENTRY_SRC_FLAG_ADDED) {    \
                _source = _src->fes_src;                         \
                do {                                             \
                    action;                                      \
                } while(0);                                      \
            }                                                    \
        }                                                        \
    }                                                            \
    else                                                         \
    {                                                            \
        _src = &_entry->fe_u_src.fe_src;                         \
        if (_src->fes_flags & FIB_ENTRY_SRC_FLAG_ADDED) {        \
            _source = _src->fes_src;                             \
            do {                                                 \
                action;                                          \
            } while(0);                                          \
        }                                                        \
    }                                                            \
}

#define FOR_EACH_SRC(_entry, _src, _source, action)              \
{                                                                \
    if (fib_entry_has_multiple_srcs(_entry))                     \
    {                                                            \
        vec_foreach(_src, _entry->fe_u_src.fe_srcs)              \
        {                                                        \
            _source = _src->fes_src;                             \
            do {                                                 \
                action;                                          \
            } while(0);                                          \
        }                                                        \
    }                                                            \
    else                                                         \
    {                                                            \
        _src = &_entry->fe_u_src.fe_src;                         \
        _source = _src->fes_src;                                 \
        do {                                                     \
            action;                                              \
        } while(0);                                              \
    }                                                            \
}

extern u8* fib_entry_src_format(fib_entry_t *entry,
				fib_source_t source,
				u8* s);

extern void fib_entry_src_register(fib_source_t source,
				   const fib_entry_src_vft_t *vft);

extern void fib_entry_src_action_init(fib_entry_t *entry,
				      fib_source_t source);

extern void fib_entry_src_action_deinit(fib_entry_t *fib_entry,
					fib_source_t source);

extern fib_entry_src_cover_res_t fib_entry_src_action_cover_change(
    fib_entry_t *entry,
    fib_source_t source);

extern fib_entry_src_cover_res_t fib_entry_src_action_cover_update(
    fib_entry_t *fib_entry,
    fib_source_t source);

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

extern void fib_entry_src_action_installed(fib_entry_t *fib_entry,
					   fib_source_t source);

extern fib_forward_chain_type_t fib_entry_get_default_chain_type(
    const fib_entry_t *fib_entry);
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
extern u32 fib_entry_has_multiple_srcs(const fib_entry_t * fib_entry);

/*
 * Per-source registration. declared here so we save a separate .h file for each
 */
extern void fib_entry_src_default_register(void);
extern void fib_entry_src_rr_register(void);
extern void fib_entry_src_interface_register(void);
extern void fib_entry_src_default_route_register(void);
extern void fib_entry_src_special_register(void);
extern void fib_entry_src_api_register(void);
extern void fib_entry_src_adj_register(void);
extern void fib_entry_src_mpls_register(void);
extern void fib_entry_src_lisp_register(void);

extern void fib_entry_src_module_init(void);

#endif
