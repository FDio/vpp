// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <sasc/sasc.h>
#include "tcp_check.h"

u8 *
format_sasc_tcp_check_session_flags(u8 *s, va_list *args) {
    u32 flags = va_arg(*args, u32);
#define _(name, x, str)                                                                            \
    if (flags & SASC_TCP_CHECK_SESSION_FLAG_##name)                                                \
        s = format(s, "%s", (str));
    foreach_sasc_tcp_check_session_flag
#undef _

        return s;
}
