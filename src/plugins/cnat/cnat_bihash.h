/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#ifndef __CNAT_BIHASH_H__

#include <vppinfra/bihash_48_8.h>

typedef clib_bihash_kv_48_8_t cnat_bihash_kv_t;
typedef clib_bihash_48_8_t cnat_bihash_t;

#define cnat_bihash_search_i2_hash  clib_bihash_search_inline_2_with_hash_48_8
#define cnat_bihash_search_i2	    clib_bihash_search_inline_2_48_8
#define cnat_bihash_add_del	    clib_bihash_add_del_48_8
#define cnat_bihash_add_del_hash    clib_bihash_add_del_with_hash_48_8
#define cnat_bihash_hash	    clib_bihash_hash_48_8
#define cnat_bihash_prefetch_bucket clib_bihash_prefetch_bucket_48_8
#define cnat_bihash_prefetch_data   clib_bihash_prefetch_data_48_8
#define cnat_bihash_add_with_overwrite_cb                                     \
  clib_bihash_add_with_overwrite_cb_48_8

#endif /* __CNAT_BIHASH_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
