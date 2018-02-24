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
/**
 * @brief
 * The IP6 link-local DPO represents the lookup of a packet in the link-local
 * IPv6 FIB
 */

#ifndef __IP6_LL_DPO_H__
#define __IP6_LL_DPO_H__

#include <vnet/dpo/dpo.h>

extern const dpo_id_t *ip6_ll_dpo_get (void);

extern void ip6_ll_dpo_module_init (void);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
