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
#ifndef included_vnet_ppp_packet_h
#define included_vnet_ppp_packet_h

/*
 * PPP packet format
 *
 * Copyright (c) 2009 Eliot Dresselhaus
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

/*
See http://www.iana.org/assignments/ppp-numbers.

The Point-to-Point Protocol (PPP) Data Link Layer [146,147,175]
contains a 16 bit Protocol field to identify the the encapsulated
protocol.  The Protocol field is consistent with the ISO 3309 (HDLC)
extension mechanism for Address fields.  All Protocols MUST be
assigned such that the least significant bit of the most significant
octet equals "0", and the least significant bit of the least
significant octet equals "1".
*/

#define foreach_ppp_protocol			\
_ (0x0001, padding)				\
_ (0x0003, rohc_small_cid)			\
_ (0x0005, rohc_large_cid)			\
_ (0x0021, ip4)					\
_ (0x0023, osi)					\
_ (0x0025, xerox_ns_idp)			\
_ (0x0027, decnet)				\
_ (0x0029, appletalk)				\
_ (0x002b, ipx)					\
_ (0x002d, vj_compressed_tcp)			\
_ (0x002f, vj_uncompressed_tcp)			\
_ (0x0031, bpdu)				\
_ (0x0033, streams)				\
_ (0x0035, vines)				\
_ (0x0039, appletalk_eddp)			\
_ (0x003b, appletalk_smart_buffered)		\
_ (0x003d, multilink)				\
_ (0x003f, netbios_framing)			\
_ (0x0041, cisco)				\
_ (0x0043, timeplex)				\
_ (0x0045, fujitsu_lblb)			\
_ (0x0047, dca_remote_lan)			\
_ (0x0049, sdtp)				\
_ (0x004b, sna_over_802_2)			\
_ (0x004d, sna)					\
_ (0x004f, ip6_header_compression)		\
_ (0x0051, knx)					\
_ (0x0053, encryption)				\
_ (0x0055, link_encryption)			\
_ (0x0057, ip6)					\
_ (0x0059, ppp_mux)				\
_ (0x005b, vendor_specific_a)			\
_ (0x0061, rtp_iphc_full_header)		\
_ (0x0063, rtp_iphc_compressed_tcp)		\
_ (0x0065, rtp_iphc_compressed_non_tcp)		\
_ (0x0067, rtp_iphc_compressed_udp_8)		\
_ (0x0069, rtp_iphc_compressed_rtp_8)		\
_ (0x006f, stampede)				\
_ (0x0073, mp_plus)				\
_ (0x007d, control)				\
_ (0x00c1, ntcits_ipi)				\
_ (0x00cf, ppp_nlpid)				\
_ (0x00fb, multilink_compression)		\
_ (0x00fd, compressed_datagram)			\
_ (0x0201, 802_1d_hello)			\
_ (0x0203, ibm_source_routing)			\
_ (0x0205, dec_lanbridge)			\
_ (0x0207, cdp)					\
_ (0x0209, netcs)				\
_ (0x020b, stp)					\
_ (0x020d, edp)					\
_ (0x0211, oscp_a)				\
_ (0x0213, oscp_b)				\
_ (0x0231, luxcom)				\
_ (0x0233, sigma)				\
_ (0x0235, apple_client_server)			\
_ (0x0281, mpls_unicast)			\
_ (0x0283, mpls_multicast)			\
_ (0x0285, ieee_p1284_4)			\
_ (0x0287, tetra)				\
_ (0x0289, multichannel_flow_treatment)		\
_ (0x2063, rtp_iphc_compressed_tcp_no_delta)	\
_ (0x2065, rtp_iphc_context_state)		\
_ (0x2067, rtp_iphc_compressed_udp_16)		\
_ (0x2069, rtp_iphc_compressed_rtp_16)		\
_ (0x4001, cray)				\
_ (0x4003, cdpd)				\
_ (0x4005, expand)				\
_ (0x4007, odsicp)				\
_ (0x4009, docsis_dll)				\
_ (0x400B, cetacean)				\
_ (0x4021, lzs)					\
_ (0x4023, reftek)				\
_ (0x4025, fibre_channel)			\
_ (0x4027, emit)				\
_ (0x405b, vendor_specific_b)			\
_ (0xc021, lcp)					\
_ (0xc023, pap)					\
_ (0xc025, link_quality_report)			\
_ (0xc027, shiva_password)			\
_ (0xc029, cbcp)				\
_ (0xc02b, bacp)				\
_ (0xc02d, bap)					\
_ (0xc05b, vendor_specific_password)		\
_ (0xc081, container_control)			\
_ (0xc223, chap)				\
_ (0xc225, rsa)					\
_ (0xc227, extensible_authentication)		\
_ (0xc229, mitsubishi_security_info)		\
_ (0xc26f, stampede_authorization)		\
_ (0xc281, proprietary_authentication_a)	\
_ (0xc283, proprietary_authentication_b)	\
_ (0xc481, proprietary_node_id_authentication)

typedef enum
{
#define _(n,f) PPP_PROTOCOL_##f = n,
  foreach_ppp_protocol
#undef _
} ppp_protocol_t;

/* PPP Link Control Protocol (LCP) and Internet Protocol Control Protocol (IPCP) Codes

The Point-to-Point Protocol (PPP) Link Control Protocol (LCP),
the Compression Control Protocol (CCP), Internet Protocol Control
Protocol (IPCP), and other control protocols, contain an 8 bit
Code field which identifies the type of packet. */

#define foreach_ppp_lcp_code			\
_ (0, vendor_specific)				\
_ (1, configure_request)			\
_ (2, configure_ack)				\
_ (3, configure_nak)				\
_ (4, configure_reject)				\
_ (5, terminate_request)			\
_ (6, terminate_ack)				\
_ (7, code_reject)				\
_ (8, protocol_reject)				\
_ (9, echo_request)				\
_ (10, echo_reply)				\
_ (11, discard_request)				\
_ (12, identification)				\
_ (13, time_remaining)				\
_ (14, reset_request)				\
_ (15, reset_reply)

typedef struct
{
  /* Set to 0xff 0x03 */
  u8 address, control;

  /* Layer 3 protocol for this packet. */
  u16 protocol;
} ppp_header_t;

#endif /* included_vnet_ppp_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
