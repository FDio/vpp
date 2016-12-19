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
 * @brief
 * The IP NULL DPO represents the rubbish bin for IP traffic. Without specifying an
 * action (i.e. send IMCP type X to sender) it is equivalent to using a drop DPO.
 * However, in contrast to the drop DPO any route that resovles via a NULL, is
 * considered to 'resolved' by FIB, i.e. a IP NULL is used when the control plane
 * is explicitly expressing the desire to drop packets. Drop DPOs are used
 * internally by FIB when resolution is not possible.
 *
 * Any replies to sender are rate limited.
 */

#ifndef __IP_NULL_DPO_H__
#define __IP_NULL_DPO_H__

#include <vnet/dpo/dpo.h>

/**
 * @brief Actions to take when a packet encounters the NULL DPO
 */
typedef enum ip_null_dpo_action_t_
{
    IP_NULL_ACTION_NONE,
    IP_NULL_ACTION_SEND_ICMP_UNREACH,
    IP_NULL_ACTION_SEND_ICMP_PROHIBIT,
} ip_null_dpo_action_t;

#define IP_NULL_ACTIONS {						\
    [IP_NULL_ACTION_NONE] = "discard",					\
    [IP_NULL_ACTION_SEND_ICMP_UNREACH] = "send-unreachable",		\
    [IP_NULL_ACTION_SEND_ICMP_PROHIBIT] = "send-prohibited",		\
}

#define IP_NULL_DPO_ACTION_NUM (IP_NULL_ACTION_SEND_ICMP_PROHIBIT+1)

extern void ip_null_dpo_add_and_lock (dpo_proto_t proto,
				      ip_null_dpo_action_t action,
				      dpo_id_t *dpo);

extern void ip_null_dpo_module_init(void);

#endif
