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

#ifndef __QOS_MARK_H__
#define __QOS_MARK_H__

#include <vnet/qos/qos_egress_map.h>

/**
 * enable QoS marking by associating a MAP with an interface.
 * The output_source specifies which protocol/header the QoS value
 * will be written into
 */
extern int qos_mark_enable (u32 sw_if_index,
			    qos_source_t output_source,
			    qos_egress_map_id_t tid);
extern int qos_mark_disable (u32 sw_if_index, qos_source_t output_source);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
