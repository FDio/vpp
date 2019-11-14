/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
