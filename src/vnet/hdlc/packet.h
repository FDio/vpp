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
#ifndef included_vnet_hdlc_packet_h
#define included_vnet_hdlc_packet_h

/*
 * HDLC packet format
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

#define foreach_hdlc_protocol			\
  _ (0x0800, ip4)				\
  _ (0x2000, cdp)				\
  _ (0x8035, slarp)				\
  _ (0x8847, mpls_unicast)			\
  _ (0x8848, mpls_multicast)			\
  _ (0x86dd, ip6)				\
  _ (0xfefe, osi)

typedef enum {
#define _(n,f) HDLC_PROTOCOL_##f = n,
  foreach_hdlc_protocol
#undef _
} hdlc_protocol_t;

typedef struct {
  /* Set to 0x0f for unicast; 0x8f for broadcast. */
  u8 address;

  /* Always zero. */
  u8 control;

  /* Layer 3 protocol for this packet. */
  u16 protocol;

  /* Layer 3 payload. */
  u8 payload[0];
} hdlc_header_t;

#endif /* included_vnet_hdlc_packet_h */
