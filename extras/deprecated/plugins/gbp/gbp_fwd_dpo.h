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

#ifndef __GBP_FWD_DPO_H__
#define __GBP_FWD_DPO_H__

#include <vnet/dpo/dpo.h>

/**
 * @brief
 * The GBP FWD DPO. Used in the L3 path to select the correct EPG uplink
 * based on the source EPG.
 */
typedef struct gbp_fwd_dpo_t_
{
  /**
   * The protocol of packets using this DPO
   */
  dpo_proto_t gfd_proto;

  /**
   * number of locks.
   */
  u16 gfd_locks;
} gbp_fwd_dpo_t;

extern void gbp_fwd_dpo_add_or_lock (dpo_proto_t dproto, dpo_id_t * dpo);

extern dpo_type_t gbp_fwd_dpo_get_type (void);

/**
 * @brief pool of all interface DPOs
 */
extern gbp_fwd_dpo_t *gbp_fwd_dpo_pool;

static inline gbp_fwd_dpo_t *
gbp_fwd_dpo_get (index_t index)
{
  return (pool_elt_at_index (gbp_fwd_dpo_pool, index));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
