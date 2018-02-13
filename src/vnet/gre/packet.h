#ifndef included_vnet_gre_packet_h
#define included_vnet_gre_packet_h

/*
 * GRE packet format
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

#define foreach_gre_protocol			\
_ (0x0800, ip4)                                 \
_ (0x86DD, ip6)                                 \
_ (0x6558, teb)                                 \
_ (0x0806, arp)					\
_ (0x8847, mpls_unicast)			\
_ (0x88BE, erspan)				\
_ (0x894F, nsh)

typedef enum
{
#define _(n,f) GRE_PROTOCOL_##f = n,
  foreach_gre_protocol
#undef _
} gre_protocol_t;

typedef struct
{
  /* flags and version */
  u16 flags_and_version;
  /* unimplemented at the moment */
#define GRE_FLAGS_CHECKSUM (1 << 15)

  /* deprecated, according to rfc2784 */
#define GRE_FLAGS_ROUTING (1 << 14)
#define GRE_FLAGS_KEY (1 << 13)
#define GRE_FLAGS_SEQUENCE (1 << 12)
#define GRE_FLAGS_STRICT_SOURCE_ROUTE (1 << 11)

  /* version 1 is PPTP which we don't support */
#define GRE_SUPPORTED_VERSION 0
#define GRE_VERSION_MASK 0x7

  /* 0x800 for ip4, etc. */
  u16 protocol;
} gre_header_t;

/* From draft-foschiano-erspan-03.txt

   Different frame variants known as "ERSPAN Types" can be
   distinguished based on the GRE "Protocol Type" field value: Type I
   and II's value is 0x88BE while Type III's is 0x22EB [ETYPES].

         GRE header for ERSPAN Type II encapsulation (8 octets [34:41])
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |0|0|0|1|0|00000|000000000|00000|   Protocol Type for ERSPAN    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |      Sequence Number (increments per packet per session)      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Note that in the above GRE header [RFC1701] out of the C, R, K, S,
   s, Recur, Flags, Version fields only S (bit 03) may be set to 1. The
   other fields are always set to zero.

   ERSPAN Type II's frame format also adds a special 8-octet ERSPAN
   "feature" header on top of the MAC/IPv4/GRE headers to enclose the
   raw mirrored frames.

   The ERSPAN Type II feature header is described below:

                     ERSPAN Type II header (8 octets [42:49])
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Ver  |          VLAN         | COS | En|T|    Session ID     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |      Reserved         |                  Index                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  The various fields of the above header are described in this table:

   Field         Position    Length          Definition
                [octet:bit]  (bits)

   Ver            [42:0]       4      ERSPAN Encapsulation version.
                                      This indicates the version of
                                      the ERSPAN encapsulation
                                      specification. Set to 0x1 for
                                      Type II.

   VLAN           [42:4]      12      Original VLAN of the frame,
                                      mirrored from the source.
                                      If the En field is set to 11,
                                      the value of VLAN is undefined.

   COS            [44:0]       3      Original class of service of the
                                      frame, mirrored from the source.

   En             [44:3]       2      The trunk encapsulation type
                                      associated with the ERSPAN source
                                      port for ingress ERSPAN traffic.

                                      The possible values are:
                                      00-originally without VLAN tag
                                      01-originally ISL encapsulated
                                      10-originally 802.1Q encapsulated
                                      11-VLAN tag preserved in frame.

   T              [44:5]       1      This bit indicates that the frame
                                      copy encapsulated in the ERSPAN
                                      packet has been truncated. This
                                      occurs if the ERSPAN encapsulated
                                      frame exceeds the configured MTU.

   Session ID     [44:6]      10      Identification associated with
   (ERSPAN ID)                        each ERSPAN session. Must be
                                     unique between the source and the
                                      receiver(s). (See section below.)

   Reserved       [46:0]      12      All bits are set to zero

   Index          [47:4]      20      A 20 bit index/port number
                                      associated with the ERSPAN
                                      traffic's port and
                                      direction (ingress/egress). N.B.:
                                      This field is platform dependent.
*/

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u32 seq_num;
  union
  {
    struct
    {
      u16 ver_vlan;
      u16 cos_en_t_session;
      u32 res_index;
    } t2;
    u64 t2_u64;
  };
}) erspan_t2_t;

typedef CLIB_PACKED (struct {
  gre_header_t gre; 
  erspan_t2_t erspan;
}) erspan_t2_header_t;

/* *INDENT-ON* */

#endif /* included_vnet_gre_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
