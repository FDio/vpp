/*
 * pcap_classify.h - Use the classifier to decide if a packet is captured
 *
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

  if (pcap_sw_if_index != 0)
    {
      if (~0 == sw_if_index)
	sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      if (pcap_sw_if_index != sw_if_index)
	return 0; /* wrong interface, skip */
    }

  if (filter_classify_table_index != ~0 &&
      vnet_is_packet_traced_inline (b, filter_classify_table_index,
				    0 /* full classify */) != 1)
    return 0; /* not matching the filter, skip */

  return 1; /* success */
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
