/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TLS_TLS_TYPES_H_
#define SRC_VNET_TLS_TLS_TYPES_H_

#include <vppinfra/types.h>

typedef struct tls_alpn_proto_id_
{
  u8 len;
  u8 *base;
} tls_alpn_proto_id_t;

static inline u8
tls_alpn_proto_id_eq (tls_alpn_proto_id_t *actual,
		      tls_alpn_proto_id_t *expected)
{
  if (actual->len != expected->len)
    return 0;
  return memcmp (actual->base, expected->base, expected->len) == 0 ? 1 : 0;
}

tls_alpn_proto_t tls_alpn_proto_by_str (tls_alpn_proto_id_t *alpn_id);

tls_alpn_proto_t tls_get_alpn_selected (u32 ctx_handle);

format_function_t format_tls_alpn_proto;

#endif /* SRC_VNET_TLS_TLS_TYPES_H_ */
