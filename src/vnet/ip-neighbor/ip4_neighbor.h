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
/*
 * ip/ip4_forward.c: IP v4 forwarding
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/arp_packet.h>

always_inline bool
ip4_neighbor_probe (vlib_main_t *vm,
                    vlib_node_runtime_t * node,
                    const ip_adjacency_t *adj0,
                    vlib_buffer_t *p0)
{
  vnet_hw_interface_t *hw_if0;
  ethernet_arp_header_t *h0;
  vlib_buffer_t *b0;
  u32 bi0;

  /* Send ARP request. */
  h0 = vlib_packet_template_get_packet (vm,
                                        &im->ip4_arp_request_packet_template,
                                        &bi0);
  /* Seems we're out of buffers */
  if (PREDICT_FALSE (!h0))
    {
      p0->error = node->errors[IP4_ARP_ERROR_NO_BUFFERS];
      return false;
    }

  b0 = vlib_get_buffer (vm, bi0);

  /* copy the persistent fields from the original */
  clib_memcpy_fast (b0->opaque2, p0->opaque2, sizeof (p0->opaque2));

  /* Add rewrite/encap string for ARP packet. */
  vnet_rewrite_one_header (adj0[0], h0, sizeof (ethernet_header_t));

  hw_if0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);

  /* Src ethernet address in ARP header. */
  mac_address_from_bytes (&h0->ip4_over_ethernet[0].mac,
                          hw_if0->hw_address);
  if (is_glean)
    {
      /* The interface's source address is stashed in the Glean Adj */
      h0->ip4_over_ethernet[0].ip4 =
        adj0->sub_type.glean.receive_addr.ip4;
    }
  else
    {
      /* Src IP address in ARP header. */
      if (ip4_src_address_for_packet (lm, sw_if_index0,
                                      &h0->ip4_over_ethernet[0].ip4))
        {
          /* No source address available */
          p0->error = node->errors[IP4_ARP_ERROR_NO_SOURCE_ADDRESS];
          vlib_buffer_free (vm, &bi0, 1);
          return false;
        }
    }
  h0->ip4_over_ethernet[1].ip4 = resolve0;

  p0->error = node->errors[IP4_ARP_ERROR_REQUEST_SENT];

  vlib_buffer_copy_trace_flag (vm, p0, bi0);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index0;

  vlib_buffer_advance (b0, -adj0->rewrite_header.data_bytes);

  vlib_set_next_frame_buffer (vm, node,
                              adj0->rewrite_header.next_index, bi0);

  return true;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
