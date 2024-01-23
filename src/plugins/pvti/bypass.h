/*
 * Copyright (c) 2024 Cisco and/or its affiliates.
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
#ifndef __included_pvti_bypass_h__
#define __included_pvti_bypass_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <pvti/pvti.h>
#include <pvti/pvti_if.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  ip_address_t remote_ip;
  u16 remote_port;
  u16 local_port;
  u32 seq;
} pvti_bypass_trace_t;

#define foreach_pvti_bypass_error                                             \
  _ (PROCESSED, "PVTI bypass tunnel packets processed")

typedef enum
{
#define _(sym, str) PVTI_BYPASS_ERROR_##sym,
  foreach_pvti_bypass_error
#undef _
    PVTI_BYPASS_N_ERROR,
} pvti_bypass_error_t;

typedef enum
{
  PVTI_BYPASS_NEXT_DROP,
  PVTI_BYPASS_NEXT_PVTI_INPUT,
  PVTI_BYPASS_N_NEXT,
} pvti_bypass_next_t;

#endif // pvti_bypass_h
