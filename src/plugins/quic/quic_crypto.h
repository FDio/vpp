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

#ifndef __included_vpp_quic_crypto_h__
#define __included_vpp_quic_crypto_h__

#include <quicly.h>

struct quic_ctx_t;

extern ptls_cipher_suite_t *quic_crypto_cipher_suites[];

int quic_encrypt_ticket_cb (ptls_encrypt_ticket_t * _self, ptls_t * tls,
			    int is_encrypt, ptls_buffer_t * dst,
			    ptls_iovec_t src);
void quic_crypto_decrypt_packet (quic_ctx_t * qctx,
				 quic_rx_packet_ctx_t * pctx);

#endif /* __included_vpp_quic_crypto_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
