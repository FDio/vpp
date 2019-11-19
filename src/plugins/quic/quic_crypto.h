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

extern ptls_cipher_suite_t *quic_crypto_cipher_suites[];

void quic_crypto_process ();
void quic_decrypt_process ();
void quic_finalize_send_packet (quicly_datagram_t * packet);

size_t
quic_crypto_aead_decrypt_push (ptls_aead_context_t * _ctx, void *_output,
			       const void *input, size_t inlen,
			       uint64_t decrypted_pn, const void *aad,
			       size_t aadlen);

void
quic_finalize_send_packet_cb (quicly_finalize_send_packet_t * _self,
			      quicly_conn_t * conn,
			      ptls_cipher_context_t * hp,
			      ptls_aead_context_t * aead,
			      quicly_datagram_t * packet,
			      size_t first_byte_at, size_t payload_from,
			      int coalesced);


int
quic_decrypt_packet (quicly_conn_t * conn,
		     quicly_decoded_packet_t * packet,
		     struct sockaddr *dest_addr, struct sockaddr *src_addr);

typedef struct quic_finalize_send_packet_cb_ctx_
{
  uint8_t *payload_from_ptr;
  uint8_t *first_byte_at_ptr;
  size_t payload_from;
  size_t first_byte_at;
  ptls_cipher_context_t *hp;
} quic_finalize_send_packet_cb_ctx;

typedef struct quic_encrypt_cb_ctx_
{
  ptls_cipher_context_t *hp;
  size_t payload_from;
  size_t first_byte_at;
  uint8_t *payload_from_ptr;
  uint8_t *first_byte_at_ptr;
  quicly_datagram_t *packet;
  quic_finalize_send_packet_cb_ctx snd_ctx[5];
  size_t snd_ctx_count;
} quic_encrypt_cb_ctx;


#endif /* __included_vpp_quic_crypto_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
