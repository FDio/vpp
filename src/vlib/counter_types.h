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

#ifndef included_vlib_counter_types_h
#define included_vlib_counter_types_h

#include <stdint.h>

/** 64bit counters */
typedef uint64_t counter_t;

/** Combined counter to hold both packets and byte differences.
 */
typedef struct
{
  counter_t packets;			/**< packet counter */
  counter_t bytes;			/**< byte counter  */
} vlib_counter_t;

#endif
