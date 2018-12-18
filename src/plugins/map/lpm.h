/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vppinfra/types.h>
#include <vppinfra/bihash_24_8.h>

enum lpm_type_e {
  LPM_TYPE_KEY32,
  LPM_TYPE_KEY128,
};

typedef struct lpm_ {
  void (*add) (struct lpm_ *lpm, void *addr_v, u8 pfxlen, u32 value);
  void (*delete) (struct lpm_ *lpm, void *addr_v, u8 pfxlen);
  u32 (*lookup) (struct lpm_ *lpm, void *addr_v, u8 pfxlen);

  /* IPv4 LPM */
  uword *hash[33];

  /* IPv6 LPM */
  BVT (clib_bihash) bihash;
  uword *prefix_lengths_bitmap;
  u32 prefix_length_refcount[129];
} lpm_t;

lpm_t *lpm_table_init (enum lpm_type_e lpm_type);
