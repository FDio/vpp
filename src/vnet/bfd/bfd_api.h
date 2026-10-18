/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
 */

/**
 * @file
 * @brief BFD API declarations
 */
#ifndef __included_bfd_api_h__
#define __included_bfd_api_h__

#include <vnet/api_errno.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip46_address.h>

#define foreach_bfd_transport(F) \
  F (UDP4, "ip4-rewrite")        \
  F (UDP6, "ip6-rewrite")

typedef enum
{
#define F(t, n) BFD_TRANSPORT_##t,
  foreach_bfd_transport (F)
#undef F
} bfd_transport_e;

/**
 * @brief create a new bfd session
 */
vnet_api_error_t bfd_udp_add_session (bool multihop, u32 sw_if_index,
				      const ip46_address_t *local_addr,
				      const ip46_address_t *peer_addr,
				      u32 desired_min_tx_usec,
				      u32 required_min_rx_usec, u8 detect_mult,
				      u8 is_authenticated, u32 conf_key_id,
				      u8 bfd_key_id);

/**
 * @brief create a new or modify an existing bfd session
 */
vnet_api_error_t bfd_udp_upd_session (bool multihop, u32 sw_if_index,
				      const ip46_address_t *local_addr,
				      const ip46_address_t *peer_addr,
				      u32 desired_min_tx_usec,
				      u32 required_min_rx_usec, u8 detect_mult,
				      u8 is_authenticated, u32 conf_key_id,
				      u8 bfd_key_id);

/**
 * @brief modify existing session
 */
vnet_api_error_t bfd_udp_mod_session (bool multihop, u32 sw_if_index,
				      const ip46_address_t *local_addr,
				      const ip46_address_t *peer_addr,
				      u32 desired_min_tx_usec,
				      u32 required_min_rx_usec,
				      u8 detect_mult);

/**
 * @brief delete existing session
 */
vnet_api_error_t bfd_udp_del_session (bool multihop, u32 sw_if_index,
				      const ip46_address_t *local_addr,
				      const ip46_address_t *peer_addr);

/**
 * @brief set session admin down/up
 */
vnet_api_error_t bfd_udp_session_set_flags (vlib_main_t *vm, bool multihop,
					    u32 sw_if_index,
					    const ip46_address_t *local_addr,
					    const ip46_address_t *peer_addr,
					    u8 admin_up_down);

/**
 * @brief create or modify bfd authentication key
 */
vnet_api_error_t bfd_auth_set_key (u32 conf_key_id, u8 auth_type, u8 key_len,
				   const u8 * key);

/**
 * @brief delete existing authentication key
 */
vnet_api_error_t bfd_auth_del_key (u32 conf_key_id);

/**
 * @brief activate authentication for existing session
 */
vnet_api_error_t bfd_udp_auth_activate (bool multihop, u32 sw_if_index,
					const ip46_address_t *local_addr,
					const ip46_address_t *peer_addr,
					u32 conf_key_id, u8 bfd_key_id,
					u8 is_delayed);

/**
 * @brief deactivate authentication for existing session
 */
vnet_api_error_t bfd_udp_auth_deactivate (bool multihop, u32 sw_if_index,
					  const ip46_address_t *local_addr,
					  const ip46_address_t *peer_addr,
					  u8 is_delayed);

/**
 * @brief set echo-source interface
 */
vnet_api_error_t bfd_udp_set_echo_source (u32 loopback_sw_if_index);

/**
 * @brief unset echo-source interface
 */
vnet_api_error_t bfd_udp_del_echo_source ();

/**
 * @brief add S-BFD reflector discriminator
 *
 * src_ip4 and src_ip6 are the sources of replies to requests sent over MPLS
 * paths, to 127/8 and ::ffff:127.0.0.0/104 (RFC 7881). NULL or an all-zero
 * address means an address of the receiving interface is used.
 *
 * The caller must hold the worker barrier. API and CLI handlers are not
 * mp-safe, so VPP takes it before calling them.
 */
vnet_api_error_t bfd_sbfd_reflector_add (u32 discriminator, u8 admin_up, u32 required_min_rx_usec,
					 const ip4_address_t *src_ip4,
					 const ip6_address_t *src_ip6);

/**
 * @brief delete S-BFD reflector discriminator
 *
 * The caller must hold the worker barrier. API and CLI handlers are not
 * mp-safe, so VPP takes it before calling them.
 */
vnet_api_error_t bfd_sbfd_reflector_del (u32 discriminator);

/**
 * @brief modify S-BFD reflector discriminator in place
 *
 * Sets the admin state, required min rx interval and sources of an existing
 * discriminator; the sources as for bfd_sbfd_reflector_add. Like add and
 * del, it runs with the worker barrier held, so it is safe while requests
 * are being answered: each one sees either the old values or the new ones,
 * and the discriminator never goes missing. A request sent over an MPLS
 * path is still dropped as no_src_addr if the new values leave no source
 * for its reply.
 *
 * The caller must hold the worker barrier. API and CLI handlers are not
 * mp-safe, so VPP takes it before calling them.
 */
vnet_api_error_t bfd_sbfd_reflector_mod (u32 discriminator, u8 admin_up, u32 required_min_rx_usec,
					 const ip4_address_t *src_ip4,
					 const ip6_address_t *src_ip6);

#endif /* __included_bfd_api_h__ */
