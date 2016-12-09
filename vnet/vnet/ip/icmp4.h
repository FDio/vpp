/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef included_vnet_icmp4_h
#define included_vnet_icmp4_h

#define foreach_icmp4_error                                             \
  _ (NONE, "valid packets")                                             \
  _ (UNKNOWN_TYPE, "unknown type")                                      \
  _ (INVALID_CODE_FOR_TYPE, "invalid code for type")                    \
  _ (INVALID_HOP_LIMIT_FOR_TYPE, "hop_limit != 255")                    \
  _ (LENGTH_TOO_SMALL_FOR_TYPE, "payload length too small for type")    \
  _ (OPTIONS_WITH_ODD_LENGTH,                                           \
     "total option length not multiple of 8 bytes")                     \
  _ (OPTION_WITH_ZERO_LENGTH, "option has zero length")                 \
  _ (ECHO_REPLIES_SENT, "echo replies sent")                            \
  _ (DST_LOOKUP_MISS, "icmp6 dst address lookup misses")                \
  _ (DEST_UNREACH_SENT, "destination unreachable response sent")	\
  _ (TTL_EXPIRE_SENT, "hop limit exceeded response sent")		\
  _ (PARAM_PROBLEM_SENT, "parameter problem response sent")		\
  _ (DROP, "error message dropped")

typedef enum
{
#define _(f,s) ICMP4_ERROR_##f,
  foreach_icmp4_error
#undef _
} icmp4_error_t;

typedef struct
{
  u8 packet_data[64];
} icmp_input_trace_t;

format_function_t format_icmp4_input_trace;
void ip4_icmp_register_type (vlib_main_t * vm, icmp4_type_t type,
			     u32 node_index);
void icmp4_error_set_vnet_buffer (vlib_buffer_t * b, u8 type, u8 code,
				  u32 data);

#endif /* included_vnet_icmp4_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
