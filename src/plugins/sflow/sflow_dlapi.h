/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 InMon Corp.
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
