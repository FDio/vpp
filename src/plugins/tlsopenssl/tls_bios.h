/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef SRC_PLUGINS_TLSOPENSSL_TLS_BIO_H_
#define SRC_PLUGINS_TLSOPENSSL_TLS_BIO_H_

#include <vnet/session/session_types.h>

BIO *BIO_new_tls (session_handle_t sh);
BIO *BIO_new_dtls (session_handle_t sh);

#endif /* SRC_PLUGINS_TLSOPENSSL_TLS_BIO_H_ */
