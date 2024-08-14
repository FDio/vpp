
/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TLS_TLS_RECORD_H__
#define SRC_VNET_TLS_TLS_RECORD_H__

#include <vppinfra/clib.h>
#include <vppinfra/error.h>

/**
 * TLS record types as per rfc8446#appendix-B.1
 */
#define foreach_tls_content_type                                              \
  _ (INVALID, 0)                                                              \
  _ (CHANGE_CIPHER_SPEC, 20)                                                  \
  _ (ALERT, 21)                                                               \
  _ (HANDSHAKE, 22)                                                           \
  _ (APPLICATION_DATA, 23)                                                    \
  _ (HEARTBEAT, 24) /* RFC 6520 */

typedef enum tls_record_type_
{
#define _(sym, val) TLS_REC_##sym = val,
  foreach_tls_content_type
#undef _
} __clib_packed tls_record_type_t;

typedef struct tls_protocol_version_
{
  u8 major;
  u8 minor;
} __clib_packed tls_protocol_version_t;

#define TLS_MAJOR_VERSION     3
#define TLS_MINOR_VERSION_MIN 0 /**< SSLv3 */
#define TLS_MINOR_VERSION_MAX 4 /**< TLS1.3 */

typedef struct tls_record_header_
{
  tls_record_type_t type;	  /**< content type */
  tls_protocol_version_t version; /**< version (deprecated) */
  u16 length;			  /**< fragment length */
  u8 fragment[0];		  /**< fragment/payload */
} __clib_packed tls_record_header_t;

#define TLS_FRAGMENT_MAX_LEN (1 << 14) /**< 16KB rfc8446 */
/** rfc5246 (TLS1.2) allows 2048 bytes of protection */
#define TLS12_FRAGMENT_MAX_ENC_LEN (TLS_FRAGMENT_MAX_LEN + (2 << 10))
#define TLS13_FRAGMENT_MAX_ENC_LEN (TLS_FRAGMENT_MAX_LEN + 256)
#define TLS_FRAGMENT_MAX_ENC_LEN   TLS12_FRAGMENT_MAX_ENC_LEN

/*
 * Handshake message types as per rfc8446#appendix-B.3
 */
#define foreach_tls_handshake_type                                            \
  _ (HELLO_REQUEST, 0)                                                        \
  _ (CLIENT_HELLO, 1)                                                         \
  _ (SERVER_HELLO, 2)                                                         \
  _ (HELLO_VERIFY_REQUEST, 3)                                                 \
  _ (NEW_SESSION_TICKET, 4)                                                   \
  _ (END_OF_EARLY_DATA, 5)                                                    \
  _ (HELLO_RETRY_REQUEST, 6)                                                  \
  _ (ENCRYPTED_EXTENSIONS, 8)                                                 \
  _ (CERTIFICATE, 11)                                                         \
  _ (SERVER_KEY_EXCHANGE, 12)                                                 \
  _ (CERTIFICATE_REQUEST, 13)                                                 \
  _ (SERVER_HELLO_DONE, 14)                                                   \
  _ (CERTIFICATE_VERIFY, 15)                                                  \
  _ (CLIENT_KEY_EXCHANGE, 16)                                                 \
  _ (FINISHED, 20)                                                            \
  _ (CERTIFICATE_URL, 21)                                                     \
  _ (CERTIFICATE_STATUS, 22)                                                  \
  _ (SUPPLEMENTAL_DATA, 23)                                                   \
  _ (KEY_UPDATE, 24)                                                          \
  _ (MESSAGE_HASH, 254)

typedef enum tls_handshake_type_
{
#define _(sym, val) TLS_HS_##sym = val,
  foreach_tls_handshake_type
#undef _
} tls_handshake_type_t;

typedef struct
{
  u32 msg_type : 8; /**< message type */
  u32 length : 24;  /**< message length */
  u8 message[0];    /**< message contents */
} __clib_packed tls_handshake_msg_t;

static inline u32
tls_handshake_message_len (tls_handshake_msg_t *msg)
{
  u8 *p = (u8 *) msg;
  return p[1] << 16 | p[2] << 8 | p[3];
}

/**
 * https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
 */
#define foreach_tls_hanshake_extensions                                       \
  _ (SERVER_NAME, 0)                                                          \
  _ (MAX_FRAGMENT_LENGTH, 1)                                                  \
  _ (STATUS_REQUEST, 5)                                                       \
  _ (SUPPORTED_GROUPS, 10)                                                    \
  _ (EC_POINT_FORMATS, 11)                                                    \
  _ (SIGNATURE_ALGORITHMS, 13)                                                \
  _ (APPLICATION_LAYER_PROTOCOL_NEGOTIATION, 16)                              \
  _ (SIGNED_CERTIFICATE_TIMESTAMP, 18)                                        \
  _ (CLIENT_CERTIFICATE_TYPE, 19)                                             \
  _ (SERVER_CERTIFICATE_TYPE, 20)                                             \
  _ (PADDING, 21)                                                             \
  _ (TOKEN_BINDING, 24)                                                       \
  _ (RECORD_SIZE_LIMIT, 28)                                                   \
  _ (SESSION_TICKET, 35)                                                      \
  _ (PRE_SHARED_KEY, 41)                                                      \
  _ (EARLY_DATA, 42)                                                          \
  _ (SUPPORTED_VERSIONS, 43)                                                  \
  _ (COOKIE, 44)                                                              \
  _ (PSK_KEY_EXCHANGE_MODES, 45)                                              \
  _ (CERTIFICATE_AUTHORITIES, 47)                                             \
  _ (OID_FILTERS, 48)                                                         \
  _ (SIGNATURE_ALGORITHMS_CERT, 50)                                           \
  _ (POST_HANDSHAKE_AUTH, 49)                                                 \
  _ (KEY_SHARE, 51)                                                           \
  _ (CONNECTION_ID, 54)                                                       \
  _ (QUIC_TRANSPORT_PARAMETERS, 57)                                           \
  _ (TICKET_REQUEST, 58)                                                      \
  _ (DNSSEC_CHAIN, 59)

typedef enum tls_handshake_extension_type_
{
#define _(sym, val) TLS_EXT_##sym = val,
  foreach_tls_hanshake_extensions
#undef _
} tls_handshake_ext_type_t;

/* Base struct for all extensions */
typedef struct tls_handshake_ext_
{
  tls_handshake_ext_type_t type;
  u8 extension[0];
} tls_handshake_ext_t;

typedef struct tls_handshake_ext_server_name_
{
  u8 name_type;
  u8 *host_name;
} tls_handshake_ext_sni_sn_t;

typedef struct tls_handshake_ext_sni_
{
  tls_handshake_ext_t ext;
  tls_handshake_ext_sni_sn_t *names;
} tls_handshake_ext_sni_t;

/* FQDN length as per rfc1035 */
#define TLS_EXT_SNI_MAX_LEN 255

#define foreach_tls_handshake_parse_error                                     \
  _ (OK, "ok")                                                                \
  _ (WANT_MORE, "want_more")                                                  \
  _ (UNSUPPORTED, "unsupported")                                              \
  _ (INVALID_LEN, "invalid_len")                                              \
  _ (SESSION_ID_LEN, "session_id_len")                                        \
  _ (CIPHER_SUITE_LEN, "cipher_suite_len")                                    \
  _ (COMPRESSION_METHOD, "compression_method")                                \
  _ (EXTENSIONS_LEN, "extensions_len")                                        \
  _ (EXT_SNI_NAME_TYPE, "ext_sni_name_type")                                  \
  _ (EXT_SNI_LEN, "ext_sni_len")

typedef enum tls_handshake_parse_error_
{
#define _(sym, str) TLS_HS_PARSE_ERR_##sym,
  foreach_tls_handshake_parse_error
#undef _
} tls_handshake_parse_error_t;

typedef struct tls_hanshake_ext_info_
{
  tls_handshake_ext_type_t type;
  u16 len;
  u8 *data;
} tls_handshake_ext_info_t;

typedef struct tls_handshake_msg_info_
{
  tls_handshake_type_t type;
  u32 len;
  u8 legacy_session_id_len;
  u8 *legacy_session_id;
  u16 cipher_suite_len;
  u8 *cipher_suites;
  u16 extensions_len;
  u8 *extensions;
} tls_handshake_msg_info_t;

static inline u8
tls_record_type_is_valid (tls_record_type_t type)
{
  switch (type)
    {
    case TLS_REC_CHANGE_CIPHER_SPEC:
    case TLS_REC_ALERT:
    case TLS_REC_HANDSHAKE:
    case TLS_REC_APPLICATION_DATA:
    case TLS_REC_HEARTBEAT:
      return 1;
    default:
      return 0;
    }
}

static inline u8
tls_record_hdr_is_valid (tls_record_header_t rec_hdr)
{
  u16 rec_len;

  if (!tls_record_type_is_valid (rec_hdr.type))
    return 0;

  /* Support for SSLv3 and TLS1.0 to TLS1.3 */
  if (rec_hdr.version.major != TLS_MAJOR_VERSION)
    return 0;

  rec_len = clib_net_to_host_u16 (rec_hdr.length);
  if (rec_len == 0 || rec_len > TLS_FRAGMENT_MAX_ENC_LEN)
    return 0;

  return 1;
}

tls_handshake_parse_error_t
tls_handshake_message_try_parse (u8 *msg, int len,
				 tls_handshake_msg_info_t *info);
tls_handshake_parse_error_t
tls_hanshake_extensions_parse (tls_handshake_msg_info_t *info,
			       tls_handshake_ext_info_t **exts);
tls_handshake_parse_error_t
tls_hanshake_extensions_try_parse (tls_handshake_msg_info_t *info,
				   tls_handshake_ext_info_t *req_exts,
				   u32 n_reqs);
tls_handshake_parse_error_t
tls_handshake_ext_parse (tls_handshake_ext_info_t *ext_info,
			 tls_handshake_ext_t *ext);
void tls_handshake_ext_free (tls_handshake_ext_t *ext);

#endif /* SRC_VNET_TLS_TLS_RECORD_H__ */
