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

#ifndef __QOS_RECORD_H__
#define __QOS_RECORD_H__

#include <vnet/qos/qos_types.h>

extern int qos_record_disable (u32 sw_if_index, qos_source_t input_source);
extern int qos_record_enable (u32 sw_if_index, qos_source_t input_source);

typedef walk_rc_t (*qos_record_walk_cb_t) (u32 sw_if_index,
					   qos_source_t input_source,
					   void *ctx);
void qos_record_walk (qos_record_walk_cb_t fn, void *c);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
