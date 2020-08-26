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

#ifndef __CNAT_NODE_VIP_H__
#define __CNAT_NODE_VIP_H__

#include <vnet/udp/udp.h>

#include <cnat/cnat_types.h>

cnat_source_policy_errors_t cnat_vip_default_source_policy (cnat_session_t *
							    session,
							    vlib_buffer_t * b,
							    ip4_header_t *
							    ip4,
							    ip6_header_t *
							    ip6,
							    udp_header_t *
							    udp0,
							    u32
							    rsession_flags,
							    const
							    cnat_translation_t
							    * ct,
							    cnat_node_ctx_t *
							    ctx,
							    cnat_main_t * cm,
							    vlib_main_t * vm);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
