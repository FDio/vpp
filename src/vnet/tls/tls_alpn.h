/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TLS_TLS_ALPN_H_
#define SRC_VNET_TLS_TLS_ALPN_H_

#define foreach_tls_alpn_protos                                               \
  _ (NONE, "none")                                                            \
  _ (HTTP1, "http/1.1")                                                       \
  _ (HTTP2, "h2")                                                             \
  _ (HTTP3, "h3")                                                             \
  _ (IMAP, "imap")                                                            \
  _ (POP3, "pop3")                                                            \
  _ (SMB2, "smb")

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

static inline uword
tls_alpn_proto_hash_key_sum (hash_t *h, uword key)
{
  tls_alpn_proto_id_t *id = uword_to_pointer (key, tls_alpn_proto_id_t *);
  return hash_memory (id->base, id->len, 0);
}

static inline uword
tls_alpn_proto_hash_key_equal (hash_t *h, uword key1, uword key2)
{
  tls_alpn_proto_id_t *id1 = uword_to_pointer (key1, tls_alpn_proto_id_t *);
  tls_alpn_proto_id_t *id2 = uword_to_pointer (key2, tls_alpn_proto_id_t *);
  return id1 && id2 && tls_alpn_proto_id_eq (id1, id2);
}

tls_alpn_proto_t tls_alpn_proto_by_str (tls_alpn_proto_id_t *alpn_id);

tls_alpn_proto_t tls_get_alpn_selected (u32 ctx_handle);

#endif /* SRC_VNET_TLS_TLS_ALPN_H_ */
