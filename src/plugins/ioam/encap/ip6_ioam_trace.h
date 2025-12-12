/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef PLUGINS_IOAM_PLUGIN_IOAM_ENCAP_IP6_IOAM_TRACE_H_
#define PLUGINS_IOAM_PLUGIN_IOAM_ENCAP_IP6_IOAM_TRACE_H_

#include <vnet/ip/ip6_hop_by_hop_packet.h>
#include <ioam/lib-trace/trace_util.h>

typedef CLIB_PACKED(struct {
  ip6_hop_by_hop_option_t hdr;
  ioam_trace_hdr_t trace_hdr;
}) ioam_trace_option_t;

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
