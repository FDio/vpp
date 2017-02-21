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

#ifndef __MAP_DPO_H__
#define __MAP_DPO_H__

#include <vnet/vnet.h>
#include <vnet/dpo/dpo.h>

/**
 * A representation of a MAP DPO
 */

extern void map_dpo_create (dpo_proto_t dproto,
			    u32 domain_index,
			    dpo_id_t *dpo);
extern void map_t_dpo_create (dpo_proto_t dproto,
			      u32 domain_index,
			      dpo_id_t *dpo);

extern u8* format_map_dpo(u8 *s, va_list *args);

/*
 * Encapsulation violation for fast data-path access
 */
extern dpo_type_t map_dpo_type;
extern dpo_type_t map_t_dpo_type;

extern void map_dpo_module_init(void);

#endif
