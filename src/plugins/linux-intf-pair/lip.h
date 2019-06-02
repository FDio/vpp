/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef __LIP_H__
#define __LIP_H__

#include <vnet/dpo/dpo.h>

#define LIP_PLUGIN_VERSION_MAJOR 1
#define LIP_PLUGIN_VERSION_MINOR 0

/**
 *
 */
typedef struct lip_t_
{
  u32 lip_host_sw_if_index;
  u32 lip_phy_sw_if_index;
} lip_t;

/**
 * Get an LIP object from its VPP index
 */
extern lip_t *lip_get (index_t index);

/**
 * Find a LIP object from the client's policy ID
 *
 * @param policy_id Client's defined policy ID
 * @return VPP's object index
 */
extern index_t lip_find (u32 policy_id);

/**
 * Create an LIP Policy
 *
 * @return error code
 */
extern int lip_add (u32 host_sw_if_index, u32 phy_sw_if_index);

/**
 * Delete a LIP
 */
extern int lip_delete (u32 host_sw_if_index);

/**
 * Callback function invoked during a walk of all policies
 */
typedef walk_rc_t (*lip_walk_cb_t) (index_t index, void *ctx);

/**
 * Walk/visit each of the LIP policies
 */
extern void lip_walk (lip_walk_cb_t cb, void *ctx);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
