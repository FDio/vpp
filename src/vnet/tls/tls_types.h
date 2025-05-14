/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TLS_TLS_TYPES_H_
#define SRC_VNET_TLS_TLS_TYPES_H_

#include <vppinfra/types.h>

#define foreach_tls_alpn_protos                                               \
  _ (NONE, "none")                                                            \
  _ (HTTP_1_1, "http/1.1")                                                    \
  _ (HTTP_2, "h2")                                                            \
  _ (HTTP_3, "h3")                                                            \
  _ (IMAP, "imap")                                                            \
  _ (POP3, "pop3")                                                            \
  _ (SMB2, "smb")                                                             \
  _ (TURN, "stun.turn")                                                       \
  _ (STUN, "stun.nat-discovery")                                              \
  _ (WEBRTC, "webrtc")                                                        \
  _ (CWEBRTC, "c-webrtc")                                                     \
  _ (FTP, "ftp")                                                              \
  _ (MANAGE_SIEVE, "managesieve")                                             \
  _ (COAP_TLS, "coap")                                                        \
  _ (COAP_DSTL, "co")                                                         \
  _ (XMPP_CLIENT, "xmpp-client")                                              \
  _ (XMPP_SERVER, "xmpp-server")                                              \
  _ (ACME_TLS_1, "acme-tls/1")                                                \
  _ (MQTT, "mqtt")                                                            \
  _ (DNS_OVER_TLS, "dot")                                                     \
  _ (NTSKE_1, "ntske/1")                                                      \
  _ (SUN_RPC, "sunrpc")                                                       \
  _ (IRC, "irc")                                                              \
  _ (NNTP, "nntp")                                                            \
  _ (NNSP, "nnsp")                                                            \
  _ (DOQ, "doq")                                                              \
  _ (SIP_2, "sip/2")                                                          \
  _ (TDS_8_0, "tds/8.0")                                                      \
  _ (DICOM, "dicom")                                                          \
  _ (POSTGRESQL, "postgresql")                                                \
  _ (RADIUS_1_0, "radius/1.0")                                                \
  _ (RADIUS_1_1, "radius/1.1")

typedef enum tls_alpn_proto_
{
#define _(sym, str) TLS_ALPN_PROTO_##sym,
  foreach_tls_alpn_protos
#undef _
} __clib_packed tls_alpn_proto_t;

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
