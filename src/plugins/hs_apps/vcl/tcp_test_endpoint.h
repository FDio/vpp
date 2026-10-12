/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Intel Corporation
 */

#ifndef __tcp_test_endpoint_h__
#define __tcp_test_endpoint_h__

static void
set_tcp_window_clamp_opt (int fd, uint32_t window_clamp)
{

  /* TCP_WINDOW_CLAMP not supported on FreeBSD */
#if !defined(__FreeBSD__)
  (void) setsockopt (fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &window_clamp, sizeof (window_clamp));
#endif
}

#endif /* __tcp_test_endpoint_h__ */
