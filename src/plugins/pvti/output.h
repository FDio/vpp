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
#ifndef __included_pvti_output_h__
#define __included_pvti_output_h__

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
  u32 tx_seq;
  u16 underlay_mtu;
  u16 bi0_max_current_length;
  u8 stream_index;
  u8 trace_type;
  u8 packet_data[96];
} pvti_output_trace_t;

#define foreach_pvti_output_error                                             \
  _ (NONE, "No error")                                                        \
  _ (PROCESSED, "Packets processed")                                          \
  _ (ENCAPSULATED, "Packets encapsulated")                                    \
  _ (PEER, "No peer found")                                                   \
  _ (MAKE_PEER, "Could not make peer")                                        \
  _ (RECHARGE0, "Could not recharge 0")                                       \
  _ (RECHARGE1, "Could not recharge 1")                                       \
  _ (NO_PRE_SPACE, "Not enought pre-data space")                              \
  _ (CHOPPED, "Packets chopped")                                              \
  _ (OVERFLOW, "Packets overflowed")                                          \
  _ (OVERFLOW_CANTFIT, "Packets overflowed and cant fit excess")

typedef enum
{
#define _(sym, str) PVTI_OUTPUT_ERROR_##sym,
  foreach_pvti_output_error
#undef _
    PVTI_OUTPUT_N_ERROR,
} pvti_output_error_t;

typedef enum
{
  PVTI_INDEPENDENT_CHUNK = 0,
  PVTI_REASS_CHUNK,
} pvti_chunk_type_t;

#define MAX_CURR_LEN_UNKNOWN 0xffff

typedef enum
{
  PVTI_OUTPUT_NEXT_DROP,
  PVTI_OUTPUT_NEXT_INTERFACE_OUTPUT,
  PVTI_OUTPUT_NEXT_IP4_LOOKUP,
  PVTI_OUTPUT_NEXT_IP6_LOOKUP,
  PVTI_OUTPUT_N_NEXT,
} pvti_output_next_t;

#endif // pvti_output_h
