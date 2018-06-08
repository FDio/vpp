/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#ifndef _IGMP_API_H_
#define _IGMP_API_H_

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>

/**
 * @brief IGMP interface enable/disable
 *  Called by a router to enable/disable the reception of IGMP messages
 *  @param sw_if_index - Interface
 *  @param enable - enable/disable
 *  @param mode - Host (1) or router (0)
 */
int igmp_enable_disable (u32 sw_if_index, u8 enable, u8 mode);

/**
 * @brief igmp listen (RFC3376 Section 2).
 * @param vm - vlib main
 * @param enable - 0 == remove (S,G), else add (S,G), aka. include/exclue
 * @param sw_if_index - interface sw_if_index
 * @param saddr - source address
 * @param gaddr - group address
 * @param cli_api_configured - if zero, an igmp report has been received on interface
 *
 *   Add/del (S,G) on an interface. If user configured,
 *   send a status change report from the interface.
 *   If a report was received on interface notify registered api clients.
 */
int igmp_listen (vlib_main_t * vm, u8 enable, u32 sw_if_index,
		 const ip46_address_t * saddr, const ip46_address_t * gaddr);


#endif /* _IGMP_API_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
