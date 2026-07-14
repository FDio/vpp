/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/* ipip_types.h: types/functions for ipip. */
#ifndef __included_ipip_types_h__
#define __included_ipip_types_h__

#include <vnet/ip/ip46_address.h>
#include <vnet/tunnel/tunnel.h>

typedef enum
{
  IPIP_TRANSPORT_IP4,
  IPIP_TRANSPORT_IP6,
} __clib_packed ipip_transport_t;

typedef enum
{
  IPIP_MODE_P2P = 0,
  IPIP_MODE_P2MP,
  IPIP_MODE_6RD,
} __clib_packed ipip_mode_t;

typedef struct
{
  ip46_address_t src;
  ip46_address_t dst;
  u32 fib_index;
  ipip_transport_t transport;
  ipip_mode_t mode;
  u16 __pad;
} __clib_packed ipip_tunnel_key_t;

STATIC_ASSERT_SIZEOF (ipip_tunnel_key_t, 5 * sizeof (u64));

/**
 * Function types — used in ikev2_priv.h
 */
extern int ipip_add_tunnel (ipip_transport_t transport, u32 instance, ip46_address_t *src,
			    ip46_address_t *dst, u32 fib_index, tunnel_encap_decap_flags_t flags,
			    ip_dscp_t dscp, tunnel_mode_t mode, u32 *sw_if_indexp);
extern int ipip_del_tunnel (u32 sw_if_index);
extern const u32 *ipip_tunnel_db_find_sw_if_index (const ipip_tunnel_key_t *key);

#endif /* __included_ipip_types_h__ */
