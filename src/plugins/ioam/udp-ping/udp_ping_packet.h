/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef PLUGINS_IOAM_PLUGIN_IOAM_UDP_PING_UDP_PING_PACKET_H_
#define PLUGINS_IOAM_PLUGIN_IOAM_UDP_PING_UDP_PING_PACKET_H_

#include <vppinfra/clib.h>
#include <vnet/ip/ip6_hop_by_hop_packet.h>
#include <vnet/udp/udp_packet.h>

#define UDP_PING_PROBE 1
#define UDP_PING_REPLY 2

#define UDP_PING_PROBE_MARKER1          0xDEAD
#define UDP_PING_PROBE_MARKER2          0xBEEF

/*
 * Refer to:
 * https://tools.ietf.org/html/draft-lapukhov-dataplane-probe-01
 *  0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Probe Marker (1)                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Probe Marker (2)                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Version     | Message Type  |             Flags             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Telemetry Request Vector                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Hop Limit   |   Hop Count   |         Must Be Zero          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Maximum Length        |        Current Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Sender's Handle        |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * (1)   The "Probe Marker" fields are arbitrary 32-bit values generally
         used by the network elements to identify the packet as a probe
         packet.  These fields should be interpreted as unsigned integer
         values, stored in network byte order.  For example, a network
         element may be configured to recognize a UDP packet destined to
         port 31337 and having 0xDEAD 0xBEEF as the values in "Probe
         Marker" field as an active probe, and treat it respectively.

   (2)   "Version Number" is currently set to 1.

   (3)   The "Message Type" field value could be either "1" - "Probe" or
         "2" - "Probe Reply"

   (4)   The "Flags" field is 8 bits, and defines the following flags:

   (5)
         (1)  "Overflow" (O-bit) (least significant bit).  This bit is
              set by the network element if the number of records on the
              packet is at the maximum limit as specified by the packet:
              i.e. the packet is already "full" of telemetry
              information.

   (6)   "Telemetry Request Vector" is a 32-bit long field that requests
         well-known inband telemetry information from the network
         elements on the path.  A bit set in this vector translates to a
         request of a particular type of information.  The following
         types/bits are currently defined, starting with the least
         significant bit first:

         (1)  Bit 0: Device identifier.

         (2)  Bit 1: Timestamp.

         (3)  Bit 2: Queueing delay.

         (4)  Bit 3: Ingress/Egress port identifiers.

         (5)  Bit 31: Opaque state snapshot request.

   (7)   "Hop Limit" is defined only for "Message Type" of "1"
         ("Probe").  For "Probe Reply" the "Hop Limit" field must be set
         to zero.  This field is treated as an integer value
         representing the number of network elements.  See the Section 4
         section on the intended use of the field.

   (8)   The "Hop Count" field specifies the current number of hops of
         capable network elements the packet has transit through.  It
         begins with zero and must be incremented by one for every
         network element that adds a telemetry record.  Combined with a
         push mechanism, this simplifies the work for the subsequent
         network element and the packet receiver.  The subsequent
         network element just needs to parse the template and then
         insert new record(s) immediately after the template.

   (9)   The "Max Length" field specifies the maximum length of the
         telemetry payload in bytes.  Given that the sender knows the
         minimum path MTU, the sender can set the maximum of payload
         bytes allowed before exceeding the MTU.  Thus, a simple
         comparison between "Current Length" and "Max Length" allows to
         decide whether or not data could be added.

   (10)  The "Current Length" field specifies the current length of data
         stored in the probe.  This field is incremented by eacn network
         element by the number of bytes it has added with the telemetry
         data frame.

   (11)  The "Sender's Handle" field is set by the sender to allow the
         receiver to identify a particular originator of probe packets.
         Along with "Sequence Number" it allows for tracking of packet
         order and loss within the network.

 *
 */
typedef struct
{
  u32 probe_marker1;
  u32 probe_marker2;
  u8 version;
  u8 msg_type;
  u16 flags;
  u32 tel_req_vec;
  u8 hop_limit;
  u8 hop_count;
  u16 reserve;
  u16 max_len;
  u16 cur_len;
  u16 sender_handle;
  u16 seq_no;
} udp_ping_data;

typedef struct
{
  udp_header_t udp;
  udp_ping_data ping_data;
} udp_ping_t;

#endif /* PLUGINS_IOAM_PLUGIN_IOAM_UDP_PING_UDP_PING_PACKET_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
