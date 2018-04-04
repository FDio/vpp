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

#ifndef __GBP_SUBNET_H__
#define __GBP_SUBNET_H__

#include <plugins/gbp/gbp_types.h>

extern int gbp_subnet_add_del (u32 table_id,
			       const fib_prefix_t * pfx,
			       u32 sw_if_index,
			       epg_id_t epg, u8 is_add, u8 is_internal);


typedef int (*gbp_subnet_cb_t) (u32 table_id,
				const fib_prefix_t * pfx,
				u32 sw_if_index,
				epg_id_t epg, u8 is_internal, void *ctx);
extern void gbp_subnet_walk (gbp_subnet_cb_t cb, void *ctx);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
