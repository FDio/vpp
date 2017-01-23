/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * trace_util.h -- Trace Profile Utility header
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

#ifndef PLUGINS_IOAM_PLUGIN_IOAM_ENCAP_IP6_IOAM_TRACE_H_
#define PLUGINS_IOAM_PLUGIN_IOAM_ENCAP_IP6_IOAM_TRACE_H_

#include <vnet/ip/ip6_hop_by_hop_packet.h>
#include <ioam/lib-trace/trace_util.h>

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct {
  ip6_hop_by_hop_option_t hdr;
  ioam_trace_hdr_t trace_hdr;
}) ioam_trace_option_t;
/* *INDENT-ON* */

always_inline void
ip6_hbh_ioam_trace_set_bit (ioam_trace_option_t * trace, u8 trace_bit)
{
  ioam_trace_set_bit (&trace->trace_hdr, trace_bit);
}

always_inline void
ip6_hbh_ioam_trace_reset_bit (ioam_trace_option_t * trace, u8 trace_bit)
{
  ioam_trace_reset_bit (&trace->trace_hdr, trace_bit);
}

#endif /* PLUGINS_IOAM_PLUGIN_IOAM_ENCAP_IP6_IOAM_TRACE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
