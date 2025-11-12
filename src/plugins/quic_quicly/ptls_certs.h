/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_ptls_certs_h__
#define __included_ptls_certs_h__

#include <picotls/openssl.h>
#include <picotls/pembase64.h>

#define PTLS_MAX_CERTS_IN_CONTEXT 16

typedef struct quic_quicly_ptls_cert_list_
{
  size_t count;
  ptls_iovec_t certs[0];
} quic_quicly_ptls_cert_list_t;

int ptls_compare_separator_line (const char *line, const char *begin_or_end,
				 const char *label);

int ptls_get_bio_pem_object (BIO *bio, const char *label, ptls_buffer_t *buf);

int ptls_load_bio_pem_objects (BIO *bio, const char *label, ptls_iovec_t *list,
			       size_t list_max, size_t *nb_objects);

int ptls_load_bio_certificates (ptls_context_t *ctx, BIO *bio);

int load_bio_certificate_chain (ptls_context_t *ctx, const char *cert_data);

int load_bio_private_key (ptls_context_t *ctx, const char *pk_data);

EVP_PKEY *ptls_load_private_key (const char *pk_data);
quic_quicly_ptls_cert_list_t *
ptls_load_certificate_chain (const char *cert_data);
int ptls_assign_private_key (ptls_context_t *ctx, EVP_PKEY *pkey);
int ptls_assign_certificate_chain (ptls_context_t *ctx,
				   quic_quicly_ptls_cert_list_t *cl);

#endif /* __included_ptls_certs_h__ */
