/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

/**
 * Encode/decode function from/to API to internal types
 */
#ifndef __IPSEC_TYPES_API_H__
#define __IPSEC_TYPES_API_H__

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec.api_types.h>

extern int ipsec_proto_decode (vl_api_ipsec_proto_t in,
			       ipsec_protocol_t * out);
extern vl_api_ipsec_proto_t ipsec_proto_encode (ipsec_protocol_t p);

extern int ipsec_crypto_algo_decode (vl_api_ipsec_crypto_alg_t in,
				     ipsec_crypto_alg_t * out);
extern vl_api_ipsec_crypto_alg_t ipsec_crypto_algo_encode (ipsec_crypto_alg_t
							   c);

extern int ipsec_integ_algo_decode (vl_api_ipsec_integ_alg_t in,
				    ipsec_integ_alg_t * out);
extern vl_api_ipsec_integ_alg_t ipsec_integ_algo_encode (ipsec_integ_alg_t i);

extern void ipsec_key_decode (const vl_api_key_t * key, ipsec_key_t * out);
extern void ipsec_key_encode (const ipsec_key_t * in, vl_api_key_t * out);

extern ipsec_sa_flags_t ipsec_sa_flags_decode (vl_api_ipsec_sad_flags_t in);
extern vl_api_ipsec_sad_flags_t ipsec_sad_flags_encode (const ipsec_sa_t *
							sa);

#endif
