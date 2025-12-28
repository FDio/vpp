/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_error_h__
#define __included_quic_error_h__

#include <stdarg.h>

#include <vppinfra/format.h>

u8 *quic_quicly_format_err (u8 *s, va_list *args);

#endif /* __included_quic_error_h__ */
