/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_ptls_certs_h__
#define __included_ptls_certs_h__

#include <picotls/openssl.h>
#include <picotls/pembase64.h>

int ptls_compare_separator_line (const char *line, const char *begin_or_end,
				 const char *label);

int ptls_get_bio_pem_object (BIO *bio, const char *label, ptls_buffer_t *buf);

int ptls_load_bio_pem_objects (BIO *bio, const char *label, ptls_iovec_t *list,
			       size_t list_max, size_t *nb_objects);

int ptls_load_bio_certificates (ptls_context_t *ctx, BIO *bio);

int load_bio_certificate_chain (ptls_context_t *ctx, const char *cert_data);

int load_bio_private_key (ptls_context_t *ctx, const char *pk_data);

#endif /* __included_ptls_certs_h__ */
