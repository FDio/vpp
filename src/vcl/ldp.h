/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef included_ldp_h
#define included_ldp_h

#if (CLIB_DEBUG > 0)
/* Set LDP_DEBUG 2 for connection debug, 3 for read/write debug output */
#define LDP_DEBUG_INIT 1
#else
#define LDP_DEBUG_INIT 0
#endif

#include <vppinfra/error.h>
#include <vppinfra/types.h>
#include <vcl/ldp_glibc_socket.h>

#define LDP_ENV_DEBUG     "LDP_DEBUG"
#define LDP_ENV_APP_NAME  "LDP_APP_NAME"
#define LDP_ENV_SID_BIT   "LDP_SID_BIT"

#define LDP_SID_BIT_MIN   5
#define LDP_SID_BIT_MAX   30

#define LDP_APP_NAME_MAX  256

#endif /* included_ldp_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
