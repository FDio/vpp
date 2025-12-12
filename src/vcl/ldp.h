/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

#ifndef included_ldp_h
#define included_ldp_h

#if (CLIB_DEBUG > 0)
/* Set LDP_DEBUG 2 for connection debug, 3 for read/write debug output */
#define LDP_DEBUG_INIT 1
#else
#define LDP_DEBUG_INIT 0
#endif

#include <vcl/ldp_glibc_socket.h>
#include <vppinfra/error.h>
#include <vppinfra/types.h>

#define LDP_ENV_DEBUG     "LDP_DEBUG"
#define LDP_ENV_APP_NAME  "LDP_APP_NAME"
#define LDP_ENV_SID_BIT   "LDP_SID_BIT"
#define LDP_ENV_TLS_CERT  "LDP_TLS_CERT_FILE"
#define LDP_ENV_TLS_KEY   "LDP_TLS_KEY_FILE"
#define LDP_ENV_TLS_TRANS "LDP_TRANSPARENT_TLS"

#define LDP_SID_BIT_MIN   5
#define LDP_SID_BIT_MAX   30

#define LDP_APP_NAME_MAX  256

#endif /* included_ldp_h */
