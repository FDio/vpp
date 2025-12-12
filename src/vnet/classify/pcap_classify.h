/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

/* pcap_classify.h - Use the classifier to decide if a packet is captured */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/classify/trace_classify.h>

/** @file pcap_classify.h
 * Use the vpp classifier to decide whether to capture packets
 */

/** @brief vnet_is_packet_pcaped
 * @param vlib_buffer_t *b - packet to capture
 * @return 0 => no capture, 1 => capture
 */

static_always_inline int
vnet_is_packet_pcaped (vnet_pcap_t *pp, vlib_buffer_t *b, u32 sw_if_index)
{
  const u32 pcap_sw_if_index = pp->pcap_sw_if_index;
  const u32 filter_classify_table_index = pp->filter_classify_table_index;
  const vlib_error_t pcap_error_index = pp->pcap_error_index;

  if (pcap_sw_if_index != 0)
    {
      if (~0 == sw_if_index)
	sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      if (pcap_sw_if_index != sw_if_index)
	return 0; /* wrong interface, skip */
    }

  if (pcap_error_index != (vlib_error_t) ~0 && pcap_error_index != b->error)
    return 0; /* wrong error */

  if (pp->pcap_filter_enable &&
      pp->current_filter_function (b, filter_classify_table_index,
				   0 /* full classify */) != 1)
    return 0; /* not matching the filter, skip */

  return 1;
}
