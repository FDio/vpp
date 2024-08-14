/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <vnet/tls/tls_record.h>

/*
 * rfc8446#section-4.1.2
 *   struct {
 *       ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
 *       Random random;
 *       opaque legacy_session_id<0..32>;
 *       CipherSuite cipher_suites<2..2^16-2>;
 *       opaque legacy_compression_methods<1..2^8-1>;
 *       Extension extensions<8..2^16-1>;
 *   } ClientHello;
 */
tls_handshake_parse_error_t
tls_handshake_client_hello_parse (u8 *b, int len,
				  tls_handshake_msg_info_t *info)
{
  u8 *p = b;

  if (PREDICT_FALSE (len < 2 + 32 + 1 + 2 + 2 + 2))
    return TLS_HS_PARSE_ERR_INVALID_LEN;
  /* skip legacy version and random */
  p += 2 + 32;
  /* legacy_session_id */
  info->legacy_session_id_len = *p;
  info->legacy_session_id = p + 1;
  p = info->legacy_session_id + info->legacy_session_id_len;
  if (PREDICT_FALSE (p - b >= len))
    return TLS_HS_PARSE_ERR_SESSION_ID_LEN;
  /* cipher_suites */
  info->cipher_suite_len = clib_net_to_host_u16 (*(u16 *) p);
  info->cipher_suites = p + 2;
  p = info->cipher_suites + info->cipher_suite_len;
  if (PREDICT_FALSE (p - b >= len))
    return TLS_HS_PARSE_ERR_CIPHER_SUITE_LEN;
  /* legacy_compression_method, only support null */
  if (PREDICT_FALSE (*p != 1 || *(p + 1) != 0))
    return TLS_HS_PARSE_ERR_COMPRESSION_METHOD;
  p += 2;
  /* extensions */
  info->extensions_len = clib_net_to_host_u16 (*(u16 *) p);
  info->extensions = p + 2;
  if (PREDICT_FALSE (info->extensions + info->extensions_len - b > len))
    return TLS_HS_PARSE_ERR_CIPHER_SUITE_LEN;

  return TLS_HS_PARSE_ERR_OK;
}

typedef tls_handshake_parse_error_t (*tls_handshake_msg_parser) (
  u8 *b, int len, tls_handshake_msg_info_t *info);

static tls_handshake_msg_parser tls_handshake_msg_parsers[] = {
  [TLS_HS_CLIENT_HELLO] = tls_handshake_client_hello_parse,
};

static inline u32
tls_handshake_ext_requested (const tls_handshake_ext_info_t *req_exts,
			     u32 n_reqs, tls_handshake_ext_type_t ext_type)
{
  for (int i = 0; i < n_reqs; i++)
    {
      if (req_exts[i].type == ext_type)
	return i;
    }

  return ~0;
}

tls_handshake_parse_error_t
tls_hanshake_extensions_parse (tls_handshake_msg_info_t *info,
			       tls_handshake_ext_info_t **exts)
{
  tls_handshake_ext_info_t *ext;
  u16 ext_type, ext_len;
  u8 *b, *b_end;

  ASSERT (info->extensions != 0);

  if (info->extensions_len < 2)
    return TLS_HS_PARSE_ERR_EXTENSIONS_LEN;

  b = info->extensions;
  b_end = info->extensions + info->extensions_len;

  while (b < b_end)
    {
      ext_type = clib_net_to_host_u16 (*(u16 *) b);
      b += 2;
      ext_len = clib_net_to_host_u16 (*(u16 *) b);
      b += 2;

      if (b + ext_len > b_end)
	return TLS_HS_PARSE_ERR_EXTENSIONS_LEN;

      vec_add2 (*exts, ext, 1);
      ext->type = ext_type;
      ext->len = ext_len;
      ext->data = b;

      b += ext_len;
    }

  return TLS_HS_PARSE_ERR_OK;
}

tls_handshake_parse_error_t
tls_hanshake_extensions_try_parse (tls_handshake_msg_info_t *info,
				   tls_handshake_ext_info_t *req_exts,
				   u32 n_reqs)
{
  u8 *b, *b_end;
  u16 ext_type, ext_len;
  u32 n_found = 0, ext_pos;

  ASSERT (info->extensions != 0);

  if (info->extensions_len < 2)
    return TLS_HS_PARSE_ERR_EXTENSIONS_LEN;

  b = info->extensions;
  b_end = info->extensions + info->extensions_len;

  while (b < b_end && n_found < n_reqs)
    {
      ext_type = clib_net_to_host_u16 (*(u16 *) b);
      b += 2;
      ext_len = clib_net_to_host_u16 (*(u16 *) b);
      b += 2;

      if (b + ext_len > b_end)
	return TLS_HS_PARSE_ERR_EXTENSIONS_LEN;

      ext_pos = tls_handshake_ext_requested (req_exts, n_reqs, ext_type);
      if (ext_pos == ~0)
	{
	  b += ext_len;
	  continue;
	}

      req_exts[ext_pos].len = ext_len;
      req_exts[ext_pos].data = b;

      b += ext_len;
      n_found++;
    }

  return TLS_HS_PARSE_ERR_OK;
}

tls_handshake_parse_error_t
tls_handshake_message_try_parse (u8 *msg, int len,
				 tls_handshake_msg_info_t *info)
{
  tls_handshake_msg_t *msg_hdr = (tls_handshake_msg_t *) msg;
  u8 *b = msg_hdr->message;

  info->len = tls_handshake_message_len (msg_hdr);
  if (info->len > len)
    return info->len > TLS_FRAGMENT_MAX_ENC_LEN ?
	     TLS_HS_PARSE_ERR_INVALID_LEN :
	     TLS_HS_PARSE_ERR_WANT_MORE;

  if (msg_hdr->msg_type >= ARRAY_LEN (tls_handshake_msg_parsers) ||
      !tls_handshake_msg_parsers[msg_hdr->msg_type])
    return TLS_HS_PARSE_ERR_UNSUPPORTED;

  return tls_handshake_msg_parsers[msg_hdr->msg_type](b, info->len, info);
}

/**
 * As per rfc6066#section-3
 *  struct {
 *      NameType name_type;
 *      select (name_type) {
 *          case host_name: HostName;
 *      } name;
 *  } ServerName;
 *
 *  enum {
 *      host_name(0), (255)
 *  } NameType;
 *
 *  opaque HostName<1..2^16-1>;
 *
 *  struct {
 *      ServerName server_name_list<1..2^16-1>
 *  } ServerNameList;
 */
tls_handshake_parse_error_t
tls_handshake_ext_sni_parse (tls_handshake_ext_info_t *ext_info,
			     tls_handshake_ext_t *ext)
{
  tls_handshake_ext_sni_t *sni = (tls_handshake_ext_sni_t *) ext;
  tls_handshake_ext_sni_sn_t *sn;
  u16 n_names, sn_len;
  u8 *b, *b_end;

  b = ext_info->data;
  b_end = b + ext_info->len;

  sni->ext.type = ext_info->type;
  sni->names = 0;
  n_names = clib_net_to_host_u16 (*(u16 *) b);
  b += 2;

  while (b < b_end && vec_len (sni->names) < n_names)
    {
      /* only host name supported */
      if (b[0] != 0)
	return TLS_HS_PARSE_ERR_EXT_SNI_NAME_TYPE;

      b++;
      /* server name length */
      sn_len = clib_net_to_host_u16 (*(u16 *) b);
      if (sn_len > TLS_EXT_SNI_MAX_LEN)
	return TLS_HS_PARSE_ERR_EXT_SNI_LEN;

      b += 2;

      vec_add2 (sni->names, sn, 1);
      sn->name_type = 0;
      vec_validate (sn->host_name, sn_len - 1);
      clib_memcpy (sn->host_name, b, sn_len);

      b += sn_len;
    }

  return TLS_HS_PARSE_ERR_OK;
}

typedef tls_handshake_parse_error_t (*tls_handshake_ext_parser) (
  tls_handshake_ext_info_t *ext_info, tls_handshake_ext_t *ext);

static tls_handshake_ext_parser tls_handshake_ext_parsers[] = {
  [TLS_EXT_SERVER_NAME] = tls_handshake_ext_sni_parse,
};

tls_handshake_parse_error_t
tls_handshake_ext_parse (tls_handshake_ext_info_t *ext_info,
			 tls_handshake_ext_t *ext)
{
  if (ext_info->type >= ARRAY_LEN (tls_handshake_ext_parsers) ||
      !tls_handshake_ext_parsers[ext_info->type])
    return TLS_HS_PARSE_ERR_UNSUPPORTED;

  return tls_handshake_ext_parsers[ext_info->type](ext_info, ext);
}

static void
tls_handshake_ext_sni_free (tls_handshake_ext_t *ext)
{
  tls_handshake_ext_sni_t *sni = (tls_handshake_ext_sni_t *) ext;
  tls_handshake_ext_sni_sn_t *sn;

  vec_foreach (sn, sni->names)
    vec_free (sn->host_name);

  vec_free (sni->names);
}

typedef void (*tls_handshake_ext_free_fn) (tls_handshake_ext_t *ext);

static tls_handshake_ext_free_fn tls_handshake_ext_free_fns[] = {
  [TLS_EXT_SERVER_NAME] = tls_handshake_ext_sni_free,
};

void
tls_handshake_ext_free (tls_handshake_ext_t *ext)
{
  if (ext->type >= ARRAY_LEN (tls_handshake_ext_free_fns) ||
      !tls_handshake_ext_free_fns[ext->type])
    return;

  tls_handshake_ext_free_fns[ext->type](ext);
}
