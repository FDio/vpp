/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#ifndef __included_quic_quicly_cid_enc_h__
#define __included_quic_quicly_cid_enc_h__

#include <quicly.h>

quicly_cid_encryptor_t *quic_quicly_new_cid_encryptor (ptls_iovec_t key);

void quic_quicly_free_cid_encryptor (quicly_cid_encryptor_t *self);

#endif /* __included_quic_quicly_cid_enc_h__ */
