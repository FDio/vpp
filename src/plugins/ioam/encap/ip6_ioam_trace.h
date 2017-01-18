/*
 * trace_util.h -- Trace Profile Utility header
 *
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

#ifndef include_ip6_ioam_trace_h
#define include_ip6_ioam_trace_h

#include <vnet/ip/ip6_hop_by_hop.h>

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct {
  ip6_hop_by_hop_option_t hdr;
  u8 ioam_trace_type;
  u8 data_list_elts_left;
  u32 elts[0]; /* Variable type. So keep it generic */
}) ioam_trace_option_t;
/* *INDENT-ON* */

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
