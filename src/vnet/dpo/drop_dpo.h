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
/**
 * @brief The Drop DPO will drop all packets, no questions asked. It is valid
 * for any packet protocol.
 */

#ifndef __DROP_DPO_H__
#define __DROP_DPO_H__

#include <vnet/dpo/dpo.h>

extern int dpo_is_drop(const dpo_id_t *dpo);

extern const dpo_id_t *drop_dpo_get(dpo_proto_t proto);

extern void drop_dpo_module_init(void);

#endif
