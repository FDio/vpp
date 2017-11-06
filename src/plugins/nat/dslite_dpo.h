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

#ifndef __included_dslite_dpo_h__
#define __included_dslite_dpo_h__

#include <vnet/vnet.h>
#include <vnet/dpo/dpo.h>

void dslite_dpo_create (dpo_proto_t dproto, u32 aftr_index, dpo_id_t * dpo);

u8 *format_dslite_dpo (u8 * s, va_list * args);

void dslite_dpo_module_init (void);

#endif /* __included_dslite_dpo_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
