/*
 *------------------------------------------------------------------
 * api_types.h
 *
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
 *------------------------------------------------------------------
 */

#ifndef included_api_types_h
#define included_api_types_h

#include <vppinfra/types.h>
#include <arpa/inet.h>
#include <string.h>

/* VPP API string type */
typedef struct
{
  u32 length;
  u8 buf[0];
} __attribute__ ((packed)) vl_api_string_t;

#endif
