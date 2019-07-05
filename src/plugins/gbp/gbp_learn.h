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

#ifndef __GBP_LEARN_H__
#define __GBP_LEARN_H__

#include <plugins/gbp/gbp.h>

/**
 * The maximum learning rate per-hashed EP
 */
#define GBP_ENDPOINT_HASH_LEARN_RATE (1e-2)

/**
 * Grouping of global data for the GBP source EPG classification feature
 */
typedef struct gbp_learn_main_t_
{
  /**
   * Next nodes for L2 output features
   */
  u32 gl_l2_input_feat_next[32];

  /**
   * logger - VLIB log class
   */
  vlib_log_class_t gl_logger;

  /**
   * throttles for the DP leanring
   */
  throttle_t gl_l2_throttle;
  throttle_t gl_l3_throttle;
} gbp_learn_main_t;

extern gbp_learn_main_t gbp_learn_main;

extern void gbp_learn_enable (u32 sw_if_index);
extern void gbp_learn_disable (u32 sw_if_index);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
