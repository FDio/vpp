/*
 * sr.c: ipv6 segment routing
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
 * @file
 * @brief Segment Routing initialization
 *
 */

#include <vnet/vnet.h>
#include <vnet/srv6/sr.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/replicate_dpo.h>

ip6_sr_main_t sr_main;

/**
 * @brief no-op lock function.
 * The lifetime of the SR entry is managed by the control plane
 */
void
sr_dpo_lock (dpo_id_t * dpo)
{
}

/**
 * @brief no-op unlock function.
 * The lifetime of the SR entry is managed by the control plane
 */
void
sr_dpo_unlock (dpo_id_t * dpo)
{
}

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
