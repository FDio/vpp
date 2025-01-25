/*
 * Copyright (c) 2025 InMon Corp.
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
#ifndef __included_sflow_dlapi_h__
#define __included_sflow_dlapi_h__
/* Dynamic-link API
 * If present, linux-cp plugin will be queried to learn the
 * Linux if_index for each VPP if_index. If that plugin is not
 * compiled and loaded, or if the function symbol is not found,
 * then the interfaces will be reported to NETLINK_USERSOCK
 * without this extra mapping.
 */
#define SFLOW_LCP_LIB		     "linux_cp_plugin.so"
#define SFLOW_LCP_SYM_GET_VIF_BY_PHY "lcp_itf_pair_get_vif_index_by_phy"
#endif /* __included_sflow_dyn_api_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
