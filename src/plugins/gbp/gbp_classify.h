/*
 * gbp.h : Group Based Policy
 *
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

#ifndef __GBP_CLASSIFY_H__
#define __GBP_CLASSIFY_H__

#include <plugins/gbp/gbp.h>

typedef enum gbp_src_classify_type_t_
{
  GBP_SRC_CLASSIFY_NULL,
  GBP_SRC_CLASSIFY_PORT,
  GBP_SRC_CLASSIFY_LPM,
} gbp_src_classify_type_t;

#define GBP_SRC_N_CLASSIFY (GBP_SRC_CLASSIFY_LPM + 1)

/**
 * Grouping of global data for the GBP source EPG classification feature
 */
typedef struct gbp_src_classify_main_t_
{
  /**
   * Next nodes for L2 output features
   */
  u32 l2_input_feat_next[GBP_SRC_N_CLASSIFY][32];
} gbp_src_classify_main_t;

extern gbp_src_classify_main_t gbp_src_classify_main;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
