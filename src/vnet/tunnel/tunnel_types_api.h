/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef __TUNNEL_TYPES_API_H__
#define __TUNNEL_TYPES_API_H__

/**
 * Conversion functions to/from (decode/encode) API types to VPP internal types
 */

#include <vnet/tunnel/tunnel.h>
#include <vnet/tunnel/tunnel_types.api_types.h>

/**
 * These enum decode/encodes use 'int' as the type for the enum because
 * one cannot forward declare an enum
 */
extern int tunnel_encap_decap_flags_decode (vl_api_tunnel_encap_decap_flags_t
					    _f,
					    tunnel_encap_decap_flags_t * out);
extern vl_api_tunnel_encap_decap_flags_t
tunnel_encap_decap_flags_encode (tunnel_encap_decap_flags_t f);

extern int tunnel_mode_decode (vl_api_tunnel_mode_t in, tunnel_mode_t * out);
extern vl_api_tunnel_mode_t tunnel_mode_encode (tunnel_mode_t in);

extern int tunnel_flags_decode (vl_api_tunnel_flags_t in, tunnel_flags_t *out);
extern vl_api_tunnel_flags_t tunnel_flags_encode (tunnel_flags_t in);

extern int tunnel_decode (const vl_api_tunnel_t *in, tunnel_t *out);
extern void tunnel_encode (const tunnel_t *in, vl_api_tunnel_t *out);

#endif
