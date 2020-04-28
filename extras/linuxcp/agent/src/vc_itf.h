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

#ifndef __VC_ITF_H__
#define __VC_ITF_H__

#include <vapi/interface.api.vapi.h>

typedef vapi_payload_sw_interface_details vc_itf_t;

extern const vc_itf_t *vc_itf_find_by_name (const char *name);

extern const char *vc_itf_get_name (u32 phy_sw_if_index);

extern bool vc_itf_populate (vapi_ctx_t vapi_ctx);

typedef void (*vc_itf_event_cb_t) (u32 phy_sw_if_index,
				   vapi_enum_if_status_flags flags);

extern bool vc_itf_reg_events (vapi_ctx_t vapi_ctx,
			       vc_itf_event_cb_t cb, void *ctx);

extern void vc_itf_init (void);

extern void vc_itf_set_admin_state (u32 phy_sw_if_index,
				    vapi_enum_if_status_flags flags);

extern u32 vc_itf_sub_create (u32 parent_phy_sw_if_index, u16 vlan);
extern void vc_itf_sub_delete (u32 sub_phy_sw_if_index);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
