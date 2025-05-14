/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TLS_TLS_ALPN_H_
#define SRC_VNET_TLS_TLS_ALPN_H_

#define foreach_tls_alpn_protos                                               \
  _ (NONE, "none")                                                            \
  _ (HTTP1, "http/1.1")                                                       \
  _ (HTTP2, "h2")

typedef enum tls_alpn_proto_
{
#define _(sym, str) TLS_ALPN_PROTO_##sym,
  foreach_tls_alpn_protos
#undef _
} __clib_packed tls_alpn_proto_t;

tls_alpn_proto_t tls_get_alpn_selected (u32 ctx_handle);

#endif /* SRC_VNET_TLS_TLS_ALPN_H_ */
