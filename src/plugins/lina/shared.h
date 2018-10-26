/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#ifndef _LINA_H_
#define _LINA_H_

#include <stdint.h>

#define LINA_SHM_MAX_REGIONS 32

typedef struct __attribute__ ((packed, aligned (128)))
{
  uint32_t instance;
  uint32_t n_regions;
  uint64_t region_size[LINA_SHM_MAX_REGIONS];
} lina_msg_t;

typedef struct __attribute__ ((packed, aligned (128)))
{
  uint32_t cookie;
#define LINA_SHM_HDR_COOKIE 0xdeadbeef

} lina_shm_hdr_t;

#endif /* _LINA_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
