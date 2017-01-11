/*
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief BFD global declarations
 */
#ifndef __included_bfd_api_h__
#define __included_bfd_api_h__

#include <vnet/api_errno.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/bfd/bfd_udp.h>

vnet_api_error_t bfd_udp_add_session (u32 sw_if_index, u32 desired_min_tx_us,
				      u32 required_min_rx_us, u8 detect_mult,
				      const ip46_address_t * local_addr,
				      const ip46_address_t * peer_addr,
				      u32 * bs_index);

vnet_api_error_t bfd_udp_del_session (u32 sw_if_index,
				      const ip46_address_t * local_addr,
				      const ip46_address_t * peer_addr);

vnet_api_error_t bfd_session_set_flags (u32 bs_index, u8 admin_up_down);

#endif /* __included_bfd_api_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
