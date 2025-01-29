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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
