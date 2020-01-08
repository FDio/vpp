/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef _MATCH_ENGINE_CLASSIFIER_H__
#define _MATCH_ENGINE_CLASSIFIER_H__

#include <vnet/match/engines/classifier/match_classifier_types.h>
#include <vnet/match/engines/classifier/match_classifier_mask_n_tuple.h>
#include <vnet/match/engines/classifier/match_classifier_mask_ip_mac.h>

typedef union match_classifier_mask_class_key_t_
{
  match_classifier_mask_class_key_mask_n_tuple_t mcmck_mask_n_tuple;
  match_classifier_mask_class_key_mask_ip_mac_t mcmck_mask_ip_mac;
} __clib_packed match_classifier_mask_class_key_t;

/**
 * the key and data associated with each unique mask
 */
typedef struct match_classifier_mask_class_t_
{
  match_classifier_mask_class_key_t mcmc_key;

  match_type_t mcmc_type;

  /* Mask data given to the vnet-classifier */
  u8 *mcmc_data;

  /* number of sessions using this mask */
  u32 mcmc_locks;
  u32 mcmc_table;

  /* engine application whose hash this object is in */
  index_t mcmc_engine;

  /* The best rule using this mask - used to sort the tables */
  match_set_pos_t mcmc_best;
} match_classifier_mask_class_t;

static match_classifier_mask_class_t *match_classifier_mask_class_pool;

static inline match_classifier_mask_class_t *
match_classifier_mask_class_get (index_t mcmci)
{
  return (pool_elt_at_index (match_classifier_mask_class_pool, mcmci));
}

typedef void (*match_classifier_mk_sessions_t) (match_classifier_rule_t * mcr,
						const match_set_pos_t * pos,
						match_classifier_engine_t *
						app);
typedef u8 *(*match_classifier_mk_class_data_t) (const
						 match_classifier_mask_class_key_t
						 * mcmck);
typedef int (*match_classifier_key_sort_t) (const
					    match_classifier_mask_class_key_t
					    * k1,
					    const
					    match_classifier_mask_class_key_t
					    * k2);

typedef struct match_classifier_mask_vft_t_
{
  match_classifier_mk_sessions_t mcv_mk_sessions;
  match_classifier_mk_class_data_t mcv_mk_class_data;
  format_function_t *mcv_format_key;
  match_classifier_key_sort_t mcv_sort;
  match_match_t mcv_match[N_AF][MATCH_N_SEMANTICS];
} match_classifier_mask_vft_t;

extern void match_classifier_mask_register (match_type_t mtype,
					    const match_classifier_mask_vft_t
					    * vft);

extern index_t match_classifier_mask_class_add_or_lock (match_type_t mtype,
							match_classifier_engine_t
							* mce,
							const
							match_classifier_mask_class_key_t
							* mcmck,
							const match_set_pos_t
							* msp);
extern void match_classifier_mask_class_unlock (index_t * mcmci);



extern u8 *format_match_classifier_engine (u8 * s, va_list * args);
extern void match_classifier_list_add (match_set_t * ms,
				       index_t msei,
				       const match_set_app_t * msa);
extern void match_classifier_list_replace (match_set_t * ms,
					   index_t msei,
					   const match_set_app_t * msa);
extern void match_classifier_list_delete (match_set_t * ms,
					  index_t msei,
					  const match_set_app_t * msa);
extern void match_classifier_unapply (match_set_t * ms,
				      const match_set_app_t * msa);
extern void match_classifier_apply (match_set_t * ms,
				    match_semantic_t msem,
				    match_set_tag_flags_t flags,
				    match_set_app_t * msa);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
