/*
 * Copyright (c) 2023 Cisco and/or its affiliates.
 * Copyright (c) 2023 Graphiant.
 *
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

#ifndef __IP_INPUT_TYPES_H__
#define __IP_INPUT_TYPES_H__

typedef enum ip_input_flags_t_
{
  IP_INPUT_FLAGS_NONE = 0,
  IP_INPUT_FLAGS_VERIFY_CHECKSUM = (1 << 0),
} ip_input_flags_t;

typedef enum ip_input_next_t_
{
  IP_INPUT_NEXT_DROP,
  IP_INPUT_NEXT_PUNT,
  IP_INPUT_NEXT_OPTIONS,
  IP_INPUT_NEXT_LOOKUP,
  IP_INPUT_NEXT_LOOKUP_MULTICAST,
  IP_INPUT_NEXT_ICMP_ERROR,
  IP_INPUT_N_NEXT,
} ip_input_next_t;

#endif
