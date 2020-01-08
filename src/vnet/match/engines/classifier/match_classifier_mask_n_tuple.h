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

#ifndef _MATCH_ENGINE_CLASSIFIER_MASK_N_TUPLE_H__
#define _MATCH_ENGINE_CLASSIFIER_MASK_N_TUPLE_H__

#include <vnet/match/engines/classifier/match_classifier_types.h>

#define foreach_mask_class_key_flags                  \
  _(MATCH_EXACT, 0, "match-exact")                    \
  _(MATCH_PROTO, 1, "match-proto")                    \
  _(MATCH_ICMP_TYPE, 2, "match-icmp-type")            \
  _(MATCH_ICMP_CODE, 3, "match-icmp-code")            \
  _(MATCH_SRC_PORT, 4, "match-src-port")              \
  _(MATCH_DST_PORT, 5, "match-dst-port")              \

typedef enum match_classifier_mask_class_key_flags_t_
{
  MASK_CLASS_KEY_FLAG_NONE = 0,
#define _(a,b,c) MASK_CLASS_KEY_FLAG_##a = (1 << b),
  foreach_mask_class_key_flags
#undef _
} __clib_packed match_classifier_mask_class_key_flags_t;

/**
 * A mask 'class' requires its own vnet-classifier table
 */
typedef struct match_classifier_mask_class_key_mask_n_tuple_t_
{
  ip_address_family_t mcmck_af;
  /* the src and dst IP mask lengths */
  u8 mcmck_ip[VLIB_N_DIR];

  match_classifier_mask_class_key_flags_t mcmck_flags;
  u8 mcmck_tcp_mask;
} match_classifier_mask_class_key_mask_n_tuple_t;


#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
