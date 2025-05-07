/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_QUIC_OPENSSL_QUIC_BIO_H_
#define SRC_PLUGINS_QUIC_OPENSSL_QUIC_BIO_H_

#include <vnet/session/session_types.h>

BIO *BIO_new_quic (session_handle_t sh);

#endif /* SRC_PLUGINS_QUIC_OPENSSL_QUIC_BIO_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
