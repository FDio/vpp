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

#include <vlib/vlib.h>

#include <vc_itf.h>

/**
 * A pair of interfaces
 */
typedef struct lcp_itf_pair_t_
{
  // u32 lip_host_sw_if_index;  /* VPP's sw_if_index for the host tap */
  const char *lip_phy_name;
  /** VPP's sw_if_index for the phy */
  u32 lip_phy_sw_if_index;
  /** linux's name for the tap */
  const char *lip_host_name;
  /** linux's index for the tap */
  u32 lip_vif_index;
  /** namespace in which the tap lives */
  const char *lip_ns;
} lcp_itf_pair_t;


typedef u32 index_t;
#define INDEX_INVALID (~0)

/**
 * Get an interface-pair object from its VPP index
 */
extern lcp_itf_pair_t *lcp_itf_pair_get (index_t index);

/**
 * Find a interface-pair object from the host interface
 *
 * @param host_sw_if_index host interface
 * @return VPP's object index
 */
extern index_t lcp_itf_pair_find_by_host (u32 host_sw_if_index);
extern index_t lcp_itf_pair_find_by_vif (u32 vif_index);

/**
 * Create an interface-pair from PHY and tap name.
 *
 * @return error code
 */
extern int lcp_itf_pair_create (const char *phy_name,
				const char *tap_name, const char *ns);

/**
 * Delete a LCP_ITF_PAIR
 */
extern int lcp_itf_pair_delete (u32 vif_index);

/**
 * Callback for when the state of an interface in VPP changes
 */
extern void lcp_itf_pair_state_change (u32 phy_sw_if_index,
				       vapi_enum_if_status_flags flags);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
