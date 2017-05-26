/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef __MPLS_LOOKUP_H__
#define __MPLS_LOOKUP_H__

#include <vnet/mpls/mpls.h>
#include <vnet/ip/ip.h>

/*
 * Compute flow hash. 
 * We'll use it to select which adjacency to use for this flow.  And other things.
 */
always_inline u32
mpls_compute_flow_hash (const mpls_unicast_header_t * hdr,
                        flow_hash_config_t flow_hash_config)
{
    return (vnet_mpls_uc_get_label(hdr->label_exp_s_ttl));
}

#endif /* __MPLS_LOOKUP_H__ */
