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

#define QUIC_MAX_COALESCED_PACKET 4

extern ptls_cipher_suite_t *quic_crypto_cipher_suites[];

int quic_encrypt_ticket_cb (ptls_encrypt_ticket_t * _self, ptls_t * tls,
			    int is_encrypt, ptls_buffer_t * dst,
			    ptls_iovec_t src);

void quic_crypto_batch_tx_packets ();
void quic_crypto_batch_rx_packets ();
void quic_crypto_finalize_send_packet (quicly_datagram_t * packet);

int quic_crypto_decrypt_packet (quicly_conn_t * conn,
				quicly_decoded_packet_t * packet,
				struct sockaddr *dest_addr,
				struct sockaddr *src_addr);


typedef struct quic_finalize_send_packet_cb_ctx_
{
  size_t payload_from;
  size_t first_byte_at;
  ptls_cipher_context_t *hp;
} quic_finalize_send_packet_cb_ctx;

typedef struct quic_encrypt_cb_ctx_
{
  quicly_datagram_t *packet;
  quic_finalize_send_packet_cb_ctx snd_ctx[QUIC_MAX_COALESCED_PACKET];
  size_t snd_ctx_count;
} quic_encrypt_cb_ctx;

void
quic_crypto_finalize_send_packet_cb (struct st_quicly_crypto_engine_t *engine,
				     quicly_conn_t * conn,
				     ptls_cipher_context_t * hp,
				     ptls_aead_context_t * aead,
				     quicly_datagram_t * packet,
				     size_t first_byte_at,
				     size_t payload_from, int coalesced);

#endif /* __included_vpp_quic_crypto_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
