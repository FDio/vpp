/*
  Copyright (c) 2017 Cisco and/or its affiliates.

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

/*
 * Note: to instantiate the template multiple times in a single file,
 * #undef __included_cuckoo_template_h__...
 */
#ifndef __included_cuckoo_common_h__
#define __included_cuckoo_common_h__

#include <vppinfra/types.h>

#define CLIB_CUCKOO_OPTIMIZE_PREFETCH 1
#define CLIB_CUCKOO_OPTIMIZE_CMP_REDUCED_HASH 1
#define CLIB_CUCKOO_OPTIMIZE_UNROLL 1
#define CLIB_CUCKOO_OPTIMIZE_USE_COUNT_LIMITS_SEARCH 1

#define foreach_clib_cuckoo_error(F)                \
  F (CLIB_CUCKOO_ERROR_SUCCESS, 0, "success")             \
  F (CLIB_CUCKOO_ERROR_NOT_FOUND, -1, "object not found") \
  F (CLIB_CUCKOO_ERROR_AGAIN, -2, "object busy")

typedef enum
{
#define F(n, v, s) n = v,
  foreach_clib_cuckoo_error (F)
#undef F
} clib_cuckoo_error_e;

typedef struct
{
  uword bucket1;
  uword bucket2;
  u8 reduced_hash;
} clib_cuckoo_lookup_info_t;

#endif /* __included_cuckoo_common_h__ */

/** @endcond */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
