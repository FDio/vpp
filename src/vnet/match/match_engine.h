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

#ifndef __MATCH_ENGINE_H__
#define __MATCH_ENGINE_H__

#include <vnet/match/match_set.h>

/**
 * Match Engine
 *  a match engine is an abstract entity that 'renderers' set/list/rules
 *  into a data-base that can be consulted at switch time.
 *
 * A example of a concreate instance of an engine is the classifier engine.
 * This engine renders the rules the vnet-classifier tables and sessions.
 */


/**
 * A function to apply/render a set
 * @param ms - the match-set to render
 * @param lnkt - The linkt type of the packets (i.e. the protocol layer
 *               the packets' current pointer will be at in the DP
 * @param flags - The number of VLAN tags the packets will have
 *
 * @return a match-set application ID tha tneeds to be available to the DP
 */
typedef match_set_app_t (*match_set_apply_t) (match_set_t * mt,
					      vnet_link_t linkt,
					      match_set_tag_flags_t flags);
typedef void (*match_set_update_t) (match_set_t * mt,
				    match_set_app_t msa,
				    vnet_link_t linkt,
				    match_set_tag_flags_t flags);
typedef void (*match_set_unapply_t) (match_set_t * mt, match_set_app_t mb);


typedef void (*match_match_t) (vlib_main_t * vm,
			       vlib_buffer_t ** bufs,
			       u32 n_bufs,
			       match_set_app_t * apps,
			       match_set_result_t * results);

typedef void (*match_match_one_t) (vlib_main_t * vm,
				   vlib_buffer_t * buf,
				   match_set_app_t app,
				   f64 now, match_set_result_t * result);

typedef struct match_engine_vft_t_
{
  match_set_apply_t mev_apply;
  match_set_update_t mev_update;
  match_set_unapply_t mev_unapply;
  match_match_t mev_match;
  match_match_one_t mev_match_one;
  format_function_t *mev_format;
} match_engine_vft_t;

extern void match_engine_register (const char *name,
				   match_type_t type,
				   match_semantic_t semantic,
				   u32 priority,
				   const match_engine_vft_t * vft);

extern const match_engine_vft_t *match_engine_get (match_semantic_t semantic,
						   match_type_t type);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
