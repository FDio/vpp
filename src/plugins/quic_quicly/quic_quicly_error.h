/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_error_h__
#define __included_quic_error_h__

#include <stdarg.h>

#include <vppinfra/format.h>

/* error codes */
#define QUIC_QUICLY_ERROR_FULL_FIFO 0xff10
#define QUIC_QUICLY_APP_ERROR_CLOSE_NOTIFY                                    \
  QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE (0)
#define QUIC_QUICLY_APP_ALLOCATION_ERROR                                      \
  QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE (0x1)
#define QUIC_QUICLY_APP_ACCEPT_NOTIFY_ERROR                                   \
  QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE (0x2)
#define QUIC_QUICLY_APP_CONNECT_NOTIFY_ERROR                                  \
  QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE (0x3)

u8 *quic_quicly_format_err (u8 *s, va_list *args);

#endif /* __included_quic_error_h__ */
