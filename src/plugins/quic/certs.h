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

#ifndef __included_quic_certs_h__
#define __included_quic_certs_h__


#include <picotls/openssl.h>
#include <picotls/pembase64.h>

int ptls_compare_separator_line (const char *line, const char *begin_or_end,
				 const char *label);

int ptls_get_bio_pem_object (BIO * bio, const char *label,
			     ptls_buffer_t * buf);

int ptls_load_bio_pem_objects (BIO * bio, const char *label,
			       ptls_iovec_t * list, size_t list_max,
			       size_t * nb_objects);

int ptls_load_bio_certificates (ptls_context_t * ctx, BIO * bio);

int load_bio_certificate_chain (ptls_context_t * ctx, const char *cert_data);

int load_bio_private_key (ptls_context_t * ctx, const char *pk_data);


#endif /* __included_quic_certs_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
