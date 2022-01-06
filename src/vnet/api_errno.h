/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef included_vnet_api_errno_h
#define included_vnet_api_errno_h

#include <stdarg.h>
#include <vppinfra/types.h>
#include <vppinfra/format.h>
#include <vnet/error.h>

#define foreach_vnet_api_error foreach_vnet_error

typedef enum
{
#define _(a,b,c) VNET_API_ERROR_##a = (b),
  foreach_vnet_api_error
#undef _
    VNET_API_N_ERROR,
} vnet_api_error_t;

format_function_t format_vnet_api_errno;

static_always_inline vnet_api_error_t
vnet_api_error (clib_error_t *err)
{
  if (err->code >= 0)
    return VNET_API_ERROR_BUG;
  return err->code;
}

#endif /* included_vnet_api_errno_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
