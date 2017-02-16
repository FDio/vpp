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

#define foreach_bfd_transport(F) \
  F (UDP4, "ip4-rewrite")        \
  F (UDP6, "ip6-rewrite")

typedef enum
{
#define F(t, n) BFD_TRANSPORT_##t,
  foreach_bfd_transport (F)
#undef F
} bfd_transport_e;

vnet_api_error_t
bfd_udp_add_session (u32 sw_if_index, const ip46_address_t * local_addr,
		     const ip46_address_t * peer_addr,
		     u32 desired_min_tx_usec, u32 required_min_rx_usec,
		     u8 detect_mult, u8 is_authenticated, u32 conf_key_id,
		     u8 bfd_key_id);

vnet_api_error_t
bfd_udp_mod_session (u32 sw_if_index, const ip46_address_t * local_addr,
		     const ip46_address_t * peer_addr,
		     u32 desired_min_tx_usec, u32 required_min_rx_usec,
		     u8 detect_mult);

vnet_api_error_t bfd_udp_del_session (u32 sw_if_index,
				      const ip46_address_t * local_addr,
				      const ip46_address_t * peer_addr);

vnet_api_error_t bfd_udp_session_set_flags (u32 sw_if_index,
					    const ip46_address_t * local_addr,
					    const ip46_address_t * peer_addr,
					    u8 admin_up_down);

vnet_api_error_t bfd_auth_set_key (u32 conf_key_id, u8 auth_type, u8 key_len,
				   const u8 * key);

vnet_api_error_t bfd_auth_del_key (u32 conf_key_id);

vnet_api_error_t bfd_udp_auth_activate (u32 sw_if_index,
					const ip46_address_t * local_addr,
					const ip46_address_t * peer_addr,
					u32 conf_key_id, u8 bfd_key_id,
					u8 is_delayed);

vnet_api_error_t bfd_udp_auth_deactivate (u32 sw_if_index,
					  const ip46_address_t * local_addr,
					  const ip46_address_t * peer_addr,
					  u8 is_delayed);

vnet_api_error_t bfd_udp_set_echo_source (u32 loopback_sw_if_index);

vnet_api_error_t bfd_udp_del_echo_source ();

#endif /* __included_bfd_api_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
