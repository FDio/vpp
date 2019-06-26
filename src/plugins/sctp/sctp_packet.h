/*
 * Copyright (c) 2017 SUSE LLC.
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
#ifndef included_vnet_sctp_packet_h
#define included_vnet_sctp_packet_h

#include <stdbool.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

/*
 * As per RFC 4960
 * https://tools.ietf.org/html/rfc4960
 */

/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Source Port Number        |     Destination Port Number   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Verification Tag                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Checksum                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  /*
   * This is the SCTP sender's port number. It can be used by the
   * receiver in combination with the source IP address, the SCTP
   * destination port, and possibly the destination IP address to
   * identify the association to which this packet belongs.
   * The port number 0 MUST NOT be used.
   */
  u16 src_port;

  /*
   * This is the SCTP port number to which this packet is destined.
   * The receiving host will use this port number to de-multiplex the
   * SCTP packet to the correct receiving endpoint/application.
   * The port number 0 MUST NOT be used.
   */
  u16 dst_port;

  /*
   * The receiver of this packet uses the Verification Tag to validate
   * the sender of this SCTP packet.  On transmit, the value of this
   * Verification Tag MUST be set to the value of the Initiate Tag
   * received from the peer endpoint during the association
   * initialization, with the following exceptions:
   * - A packet containing an INIT chunk MUST have a zero Verification
   *   Tag.
   * - A packet containing a SHUTDOWN COMPLETE chunk with the T bit
   *   set MUST have the Verification Tag copied from the packet with
   *   the SHUTDOWN ACK chunk.
   * - A packet containing an ABORT chunk may have the verification tag
   *   copied from the packet that caused the ABORT to be sent.
   * An INIT chunk MUST be the only chunk in the SCTP packet carrying it.
   */
  u32 verification_tag;

  /*
   * This field contains the checksum of this SCTP packet.
   * SCTP uses the CRC32c algorithm.
   */
  u32 checksum;

} sctp_header_t;

always_inline void
vnet_set_sctp_src_port (sctp_header_t * h, u16 src_port)
{
  h->src_port = clib_host_to_net_u16 (src_port);
}

always_inline u16
vnet_get_sctp_src_port (sctp_header_t * h)
{
  return (clib_net_to_host_u16 (h->src_port));
}

always_inline void
vnet_set_sctp_dst_port (sctp_header_t * h, u16 dst_port)
{
  h->dst_port = clib_host_to_net_u16 (dst_port);
}

always_inline u16
vnet_get_sctp_dst_port (sctp_header_t * h)
{
  return (clib_net_to_host_u16 (h->dst_port));
}

always_inline void
vnet_set_sctp_verification_tag (sctp_header_t * h, u32 verification_tag)
{
  h->verification_tag = clib_host_to_net_u32 (verification_tag);
}

always_inline u32
vnet_get_sctp_verification_tag (sctp_header_t * h)
{
  return (clib_net_to_host_u32 (h->verification_tag));
}

always_inline void
vnet_set_sctp_checksum (sctp_header_t * h, u32 checksum)
{
  h->checksum = clib_host_to_net_u32 (checksum);
}

always_inline u32
vnet_get_sctp_checksum (sctp_header_t * h)
{
  return (clib_net_to_host_u32 (h->checksum));
}

/*
 * Multiple chunks can be bundled into one SCTP packet up to the MTU
 * size, except for the INIT, INIT ACK, and SHUTDOWN COMPLETE chunks.
 * These chunks MUST NOT be bundled with any other chunk in a packet.
 *
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Common Header                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Chunk #1                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           ...                                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Chunk #n                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef enum
{
  DATA = 0,
  INIT,
  INIT_ACK,
  SACK,
  HEARTBEAT,
  HEARTBEAT_ACK,
  ABORT,
  SHUTDOWN,
  SHUTDOWN_ACK,
  OPERATION_ERROR,
  COOKIE_ECHO,
  COOKIE_ACK,
  ECNE,
  CWR,
  SHUTDOWN_COMPLETE,
  UNKNOWN
} sctp_chunk_type;

/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Chunk Type  | Chunk  Flags  |        Chunk Length           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  /*
   * This field identifies the type of information contained in the
   * Chunk Value field. It takes a value from 0 to 254.
   * The value of 255 is reserved for future use as an extension field.
   *
   * The values of Chunk Types are defined as follows:
   * ID Value    Chunk Type
   * -----       ----------
   *  0          - Payload Data (DATA)
   *  1          - Initiation (INIT)
   *  2          - Initiation Acknowledgement (INIT ACK)
   *  3          - Selective Acknowledgement (SACK)
   *  4          - Heartbeat Request (HEARTBEAT)
   *  5          - Heartbeat Acknowledgement (HEARTBEAT ACK)
   *  6          - Abort (ABORT)
   *  7          - Shutdown (SHUTDOWN)
   *  8          - Shutdown Acknowledgement (SHUTDOWN ACK)
   *  9          - Operation Error (ERROR)
   *  10         - State Cookie (COOKIE ECHO)
   *  11         - Cookie Acknowledgement (COOKIE ACK)
   *  12         - Reserved for Explicit Congestion Notification Echo (ECNE)
   *  13         - Reserved for Congestion Window Reduced (CWR)
   *  14         - Shutdown Complete (SHUTDOWN COMPLETE)
   *  15 to 62   - available
   *  63         - reserved for IETF-defined Chunk Extensions
   *  64 to 126  - available
   *  127        - reserved for IETF-defined Chunk Extensions
   *  128 to 190 - available
   *  191        - reserved for IETF-defined Chunk Extensions
   *  192 to 254 - available
   *  255        - reserved for IETF-defined Chunk Extensions
   *
   *  Chunk Types are encoded such that the highest-order 2 bits specify
   *  the action that must be taken if the processing endpoint does not
   *  recognize the Chunk Type.
   *  00 -  Stop processing this SCTP packet and discard it, do not
   *  process any further chunks within it.
   *  01 -  Stop processing this SCTP packet and discard it, do not
   *  process any further chunks within it, and report the
   *  unrecognized chunk in an 'Unrecognized Chunk Type'.
   *  10 -  Skip this chunk and continue processing.
   *  11 -  Skip this chunk and continue processing, but report in an
   *  ERROR chunk using the 'Unrecognized Chunk Type' cause of error.
   *
   *  Note: The ECNE and CWR chunk types are reserved for future use of
   *  Explicit Congestion Notification (ECN);
   */
  //u8 type;

  /*
   * The usage of these bits depends on the Chunk type as given by the
   * Chunk Type field.  Unless otherwise specified, they are set to 0 on
   * transmit and are ignored on receipt.
   */
  //u8 flags;

  /*
   * This value represents the size of the chunk in bytes, including
   * the Chunk Type, Chunk Flags, Chunk Length, and Chunk Value fields.
   * Therefore, if the Chunk Value field is zero-length, the Length
   * field will be set to 4.
   * The Chunk Length field does not count any chunk padding.
   * Chunks (including Type, Length, and Value fields) are padded out
   * by the sender with all zero bytes to be a multiple of 4 bytes
   * long. This padding MUST NOT be more than 3 bytes in total. The
   * Chunk Length value does not include terminating padding of the
   * chunk. However, it does include padding of any variable-length
   * parameter except the last parameter in the chunk. The receiver
   * MUST ignore the padding.
   *
   * Note: A robust implementation should accept the chunk whether or
   * not the final padding has been included in the Chunk Length.
   */
  //u16 length;

  u32 params;

} sctp_chunks_common_hdr_t;

typedef struct
{
  sctp_header_t hdr;
  sctp_chunks_common_hdr_t common_hdr;

} sctp_full_hdr_t;

#define CHUNK_TYPE_MASK 0xFF000000
#define CHUNK_TYPE_SHIFT 24

#define CHUNK_FLAGS_MASK 0x00FF0000
#define CHUNK_FLAGS_SHIFT 16

#define CHUNK_UBIT_MASK 0x00040000
#define CHUNK_UBIT_SHIFT 18

#define CHUNK_BBIT_MASK 0x00020000
#define CHUNK_BBIT_SHIFT 17

#define CHUNK_EBIT_MASK 0x00010000
#define CHUNK_EBIT_SHIFT 16

#define CHUNK_LENGTH_MASK 0x0000FFFF
#define CHUNK_LENGTH_SHIFT 0

always_inline void
vnet_sctp_common_hdr_params_host_to_net (sctp_chunks_common_hdr_t * h)
{
  h->params = clib_host_to_net_u32 (h->params);
}

always_inline void
vnet_sctp_common_hdr_params_net_to_host (sctp_chunks_common_hdr_t * h)
{
  h->params = clib_net_to_host_u32 (h->params);
}

always_inline void
vnet_sctp_set_ubit (sctp_chunks_common_hdr_t * h)
{
  h->params &= ~(CHUNK_UBIT_MASK);
  h->params |= (1 << CHUNK_UBIT_SHIFT) & CHUNK_UBIT_MASK;
}

always_inline u8
vnet_sctp_get_ubit (sctp_chunks_common_hdr_t * h)
{
  return ((h->params & CHUNK_UBIT_MASK) >> CHUNK_UBIT_SHIFT);
}

always_inline void
vnet_sctp_set_bbit (sctp_chunks_common_hdr_t * h)
{
  h->params &= ~(CHUNK_BBIT_MASK);
  h->params |= (1 << CHUNK_BBIT_SHIFT) & CHUNK_BBIT_MASK;
}

always_inline u8
vnet_sctp_get_bbit (sctp_chunks_common_hdr_t * h)
{
  return ((h->params & CHUNK_BBIT_MASK) >> CHUNK_BBIT_SHIFT);
}

always_inline void
vnet_sctp_set_ebit (sctp_chunks_common_hdr_t * h)
{
  h->params &= ~(CHUNK_EBIT_MASK);
  h->params |= (1 << CHUNK_EBIT_SHIFT) & CHUNK_EBIT_MASK;
}

always_inline u8
vnet_sctp_get_ebit (sctp_chunks_common_hdr_t * h)
{
  return ((h->params & CHUNK_EBIT_MASK) >> CHUNK_EBIT_SHIFT);
}

always_inline void
vnet_sctp_set_chunk_type (sctp_chunks_common_hdr_t * h, sctp_chunk_type t)
{
  h->params &= ~(CHUNK_TYPE_MASK);
  h->params |= (t << CHUNK_TYPE_SHIFT) & CHUNK_TYPE_MASK;
}

always_inline u8
vnet_sctp_get_chunk_type (sctp_chunks_common_hdr_t * h)
{
  return ((h->params & CHUNK_TYPE_MASK) >> CHUNK_TYPE_SHIFT);
}

always_inline void
vnet_sctp_set_chunk_length (sctp_chunks_common_hdr_t * h, u16 length)
{
  h->params &= ~(CHUNK_LENGTH_MASK);
  h->params |= (length << CHUNK_LENGTH_SHIFT) & CHUNK_LENGTH_MASK;
}

always_inline u16
vnet_sctp_get_chunk_length (sctp_chunks_common_hdr_t * h)
{
  return ((h->params & CHUNK_LENGTH_MASK) >> CHUNK_LENGTH_SHIFT);
}

/*
 * Payload chunk
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 0    | Reserved|U|B|E|    Length                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              TSN                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Stream Identifier S      |   Stream Sequence Number n    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  Payload Protocol Identifier                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * \                                                               \
 * /                 User Data (seq n of Stream S)                 /
 * \                                                               \
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_header_t sctp_hdr;
  /*
   * Type (8 bits): 0
   * Flags (8 bits):
   * -- Reserved (5 bits): all 0s
   * -- U bit
   * -- B bit
   * -- E bit
   * Length (16 bits): This field indicates the length of the DATA chunk in
   * bytes from the beginning of the type field to the end of the User Data
   * field excluding any padding.
   * A DATA chunk with one byte of user data will have Length set to 17
   * (indicating 17 bytes). A DATA chunk with a User Data field of length L
   * will have the Length field set to (16 + L) (indicating 16+L bytes) where
   * L MUST be greater than 0.
   */

  /*
   * Fragment Description Table:
   *
   *    B E                  Description
   * ============================================================
   * |  1 0 | First piece of a fragmented user message          |
   * +----------------------------------------------------------+
   * |  0 0 | Middle piece of a fragmented user message         |
   * +----------------------------------------------------------+
   * |  0 1 | Last piece of a fragmented user message           |
   * +----------------------------------------------------------+
   * |  1 1 | Unfragmented message                              |
   * ============================================================
   */
  sctp_chunks_common_hdr_t chunk_hdr;

  /*
   * This value represents the TSN for this DATA chunk.
   * The valid range of TSN is from 0 to 4294967295 (2**32 - 1).
   * TSN wraps back to 0 after reaching 4294967295.
   */
  u32 tsn;

  /*
   * Identifies the stream to which the following user data belongs.
   */
  u16 stream_id;

  /*
   * This value represents the Stream Sequence Number of the following user data
   * within the stream S. Valid range is 0 to 65535.
   * When a user message is fragmented by SCTP for transport, the same Stream
   * Sequence Number MUST be carried in each of the fragments of the message.
   */
  u16 stream_seq;

  /*
   * This value represents an application (or upper layer) specified protocol
   * identifier. This value is passed to SCTP by its upper layer and sent to its
   * peer. This identifier is not used by SCTP but can be used by certain network
   * entities, as well as by the peer application, to identify the type of
   * information being carried in this DATA chunk. This field must be sent even
   * in fragmented DATA chunks (to make sure it is available for agents in the
   * middle of the network).  Note that this field is NOT touched by an SCTP
   * implementation; therefore, its byte order is NOT necessarily big endian.
   * The upper layer is responsible for any byte order conversions to this field.
   * The value 0 indicates that no application identifier is specified by the
   * upper layer for this payload data.
   */
  u32 payload_id;

  /*
   * This is the payload user data. The implementation MUST pad the end of the
   * data to a 4-byte boundary with all-zero bytes. Any padding MUST NOT be
   * included in the Length field. A sender MUST never add more than 3 bytes of
   * padding.
   */
  u32 data[];

} sctp_payload_data_chunk_t;

always_inline void
vnet_sctp_set_tsn (sctp_payload_data_chunk_t * p, u32 tsn)
{
  p->tsn = clib_host_to_net_u32 (tsn);
}

always_inline u32
vnet_sctp_get_tsn (sctp_payload_data_chunk_t * p)
{
  return (clib_net_to_host_u32 (p->tsn));
}

always_inline void
vnet_sctp_set_stream_id (sctp_payload_data_chunk_t * p, u16 stream_id)
{
  p->stream_id = clib_host_to_net_u16 (stream_id);
}

always_inline u16
vnet_sctp_get_stream_id (sctp_payload_data_chunk_t * p)
{
  return (clib_net_to_host_u16 (p->stream_id));
}

always_inline void
vnet_sctp_set_stream_seq (sctp_payload_data_chunk_t * p, u16 stream_seq)
{
  p->stream_seq = clib_host_to_net_u16 (stream_seq);
}

always_inline u16
vnet_sctp_get_stream_seq (sctp_payload_data_chunk_t * p)
{
  return (clib_net_to_host_u16 (p->stream_seq));
}

always_inline void
vnet_sctp_set_payload_id (sctp_payload_data_chunk_t * p, u32 payload_id)
{
  p->payload_id = clib_host_to_net_u32 (payload_id);
}

always_inline u32
vnet_sctp_get_payload_id (sctp_payload_data_chunk_t * p)
{
  return (clib_net_to_host_u32 (p->payload_id));
}

always_inline u16
vnet_sctp_calculate_padding (u16 base_length)
{
  if (base_length % 4 == 0)
    return 0;

  return (4 - base_length % 4);
}

#define INBOUND_STREAMS_COUNT 1
#define OUTBOUND_STREAMS_COUNT 1

/*
 * INIT chunk
 *
 * This chunk is used to initiate an SCTP association between two
 * endpoints.
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 1    |  Chunk Flags  |      Chunk Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Initiate Tag                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Advertised Receiver Window Credit (a_rwnd)          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Number of Outbound Streams   |  Number of Inbound Streams    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Initial TSN                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * \                                                               \
 * /              Optional/Variable-Length Parameters              /
 * \                                                               \
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The INIT chunk contains the following parameters. Unless otherwise
 * noted, each parameter MUST only be included once in the INIT chunk.
 *
 * Fixed Parameters                     Status
 * ----------------------------------------------
 *  Initiate Tag                        Mandatory
 *  Advertised Receiver Window Credit   Mandatory
 *  Number of Outbound Streams          Mandatory
 *  Number of Inbound Streams           Mandatory
 *  Initial TSN                         Mandatory
 *
 * Variable Parameters                  Status     Type Value
 * -------------------------------------------------------------
 *  IPv4 Address (Note 1)               Optional    5
 *  IPv6 Address (Note 1)               Optional    6
 *  Cookie Preservative			Optional    9
 *  Reserved for ECN Capable (Note 2)   Optional    32768 (0x8000)
 *  Host Name Address (Note 3)          Optional    11
 *  Supported Address Types (Note 4)    Optional    12
 *
 * Note 1: The INIT chunks can contain multiple addresses that can be
 * IPv4 and/or IPv6 in any combination.
 *
 * Note 2: The ECN Capable field is reserved for future use of Explicit
 * Congestion Notification.
 *
 * Note 3: An INIT chunk MUST NOT contain more than one Host Name Address
 * parameter. Moreover, the sender of the INIT MUST NOT combine any other
 * address types with the Host Name Address in the INIT. The receiver of
 * INIT MUST ignore any other address types if the Host Name Address parameter
 * is present in the received INIT chunk.
 *
 * Note 4: This parameter, when present, specifies all the address types the
 * sending endpoint can support.  The absence of this parameter indicates that
 * the sending endpoint can support any address type.
 *
 * IMPLEMENTATION NOTE: If an INIT chunk is received with known parameters that
 * are not optional parameters of the INIT chunk, then the receiver SHOULD
 * process the INIT chunk and send back an INIT ACK. The receiver of the INIT
 * chunk MAY bundle an ERROR chunk with the COOKIE ACK chunk later.
 * However, restrictive implementations MAY send back an ABORT chunk in response
 * to the INIT chunk. The Chunk Flags field in INIT is reserved, and all bits
 * in it should be set to 0 by the sender and ignored by the receiver.
 * The sequence of parameters within an INIT can be processed in any order.
 */
typedef struct
{
  sctp_header_t sctp_hdr;
  sctp_chunks_common_hdr_t chunk_hdr;

  /*
   * The receiver of the INIT (the responding end) records the value of
   * the Initiate Tag parameter.
   * This value MUST be placed into the Verification Tag field of every
   * SCTP packet that the receiver of the INIT transmits within this association.
   * The Initiate Tag is allowed to have any value except 0.
   *
   * If the value of the Initiate Tag in a received INIT chunk is found
   * to be 0, the receiver MUST treat it as an error and close the
   * association by transmitting an ABORT.
   *
   * The value of the INIT TAG is recommended to be random for security
   * reasons. A good method is described in https://tools.ietf.org/html/rfc4086
   */
  u32 initiate_tag;

  /*
   * This value represents the dedicated buffer space, in number of bytes,
   * the sender of the INIT has reserved in association with this window.
   * During the life of the association, this buffer space SHOULD NOT be
   * lessened (i.e., dedicated buffers taken away from this association);
   * however, an endpoint MAY change the value of a_rwnd it sends in SACK
   * chunks.
   */
  u32 a_rwnd;

  /*
   * Defines the number of outbound streams the sender of this INIT chunk
   * wishes to create in this association.
   * The value of 0 MUST NOT be used.
   *
   * Note: A receiver of an INIT with the OS value set to 0 SHOULD abort
   * the association.
   */
  u16 outbound_streams_count;

  /*
   * Defines the maximum number of streams the sender of this INIT
   * chunk allows the peer end to create in this association.
   * The value 0 MUST NOT be used.
   *
   * Note: There is no negotiation of the actual number of streams but
   * instead the two endpoints will use the min(requested, offered).
   *
   * Note: A receiver of an INIT with the MIS value of 0 SHOULD abort
   * the association.
   */
  u16 inboud_streams_count;

  /*
   * Defines the initial TSN that the sender will use.
   * The valid range is from 0 to 4294967295.
   * This field MAY be set to the value of the Initiate Tag field.
   */
  u32 initial_tsn;

  /* The following field allows to have multiple optional fields which are:
   * - sctp_ipv4_address
   * - sctp_ipv6_address
   * - sctp_cookie_preservative
   * - sctp_hostname_address
   * - sctp_supported_address_types
   */
  u32 optional_fields[];

} sctp_init_chunk_t;

/*
 * INIT ACK chunk
 *
 * The INIT ACK chunk is used to acknowledge the initiation of an SCTP
 * association. The parameter part of INIT ACK is formatted similarly to the
 * INIT chunk.
 *
 * It uses two extra variable parameters:
 * - the State Cookie and
 * - the Unrecognized Parameter:
 */
/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 2    |  Chunk Flags  |      Chunk Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Initiate Tag                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Advertised Receiver Window Credit                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Number of Outbound Streams   |  Number of Inbound Streams    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Initial TSN                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * \                                                               \
 * /              Optional/Variable-Length Parameters              /
 * \                                                               \
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef sctp_init_chunk_t sctp_init_ack_chunk_t;

typedef struct
{
  u16 type;
  u16 length;

} sctp_opt_params_hdr_t;

#define SHA1_OUTPUT_LENGTH 20
/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Parameter Type       |       Parameter Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * \                                                               \
 * /                       Parameter Value                         /
 * \                                                               \
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_opt_params_hdr_t param_hdr;

  unsigned char mac[SHA1_OUTPUT_LENGTH];	/* RFC 2104 */
  u64 creation_time;
  u32 cookie_lifespan;

} sctp_state_cookie_param_t;

/*
 *  This chunk is used only during the initialization of an association.
 *  It is sent by the initiator of an association to its peer to complete
 *  the initialization process.  This chunk MUST precede any DATA chunk
 *  sent within the association, but MAY be bundled with one or more DATA
 *  chunks in the same packet.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Type = 10   |Chunk  Flags   |         Length                |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  /                     Cookie                                    /
 *  \                                                               \
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_header_t sctp_hdr;
  sctp_chunks_common_hdr_t chunk_hdr;

  sctp_state_cookie_param_t cookie;

} sctp_cookie_echo_chunk_t;


/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 11   |Chunk  Flags   |     Length = 4                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_header_t sctp_hdr;
  sctp_chunks_common_hdr_t chunk_hdr;

} sctp_cookie_ack_chunk_t;

/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 14   |Chunk  Flags   |     Length = 4                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_header_t sctp_hdr;
  sctp_chunks_common_hdr_t chunk_hdr;

} sctp_shutdown_complete_chunk_t;

/* OPTIONAL or VARIABLE-LENGTH parameters for INIT */
#define SCTP_IPV4_ADDRESS_TYPE	5
#define SCTP_IPV4_ADDRESS_TYPE_LENGTH 8
#define SCTP_IPV6_ADDRESS_TYPE	6
#define SCTP_IPV6_ADDRESS_TYPE_LENGTH 20
#define SCTP_STATE_COOKIE_TYPE		7
#define SCTP_UNRECOGNIZED_TYPE	8
#define SCTP_COOKIE_PRESERVATIVE_TYPE	9
#define SCTP_COOKIE_PRESERVATIVE_TYPE_LENGTH	8
#define SCTP_HOSTNAME_ADDRESS_TYPE 	11
#define SCTP_SUPPORTED_ADDRESS_TYPES	12

/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        Type = 5               |      Length = 8               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        IPv4 Address                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_opt_params_hdr_t param_hdr;

  /*
   * Contains an IPv4 address of the sending endpoint.
   * It is binary encoded.
   */
  ip4_address_t address;

} sctp_ipv4_addr_param_t;

always_inline void
vnet_sctp_set_ipv4_address (sctp_ipv4_addr_param_t * a, ip4_address_t address)
{
  a->param_hdr.type = clib_host_to_net_u16 (SCTP_IPV4_ADDRESS_TYPE);
  a->param_hdr.length = clib_host_to_net_u16 (8);
  a->address.as_u32 = clib_host_to_net_u32 (address.as_u32);
}

always_inline u32
vnet_sctp_get_ipv4_address (sctp_ipv4_addr_param_t * a)
{
  return (clib_net_to_host_u32 (a->address.as_u32));
}

/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Type = 6           |          Length = 20          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                         IPv6 Address                          |
 * |                                                               |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_opt_params_hdr_t param_hdr;

  /*
   * Contains an IPv6 address of the sending endpoint.
   * It is binary encoded.
   */
  ip6_address_t address;

} sctp_ipv6_addr_param_t;

always_inline void
vnet_sctp_set_ipv6_address (sctp_ipv6_addr_param_t * a, ip6_address_t address)
{
  a->param_hdr.type = clib_host_to_net_u16 (SCTP_IPV6_ADDRESS_TYPE);
  a->param_hdr.length = clib_host_to_net_u16 (20);
  a->address.as_u64[0] = clib_host_to_net_u64 (address.as_u64[0]);
  a->address.as_u64[1] = clib_host_to_net_u64 (address.as_u64[1]);
}

always_inline ip6_address_t
vnet_sctp_get_ipv6_address (sctp_ipv6_addr_param_t * a)
{
  ip6_address_t ip6_address;

  ip6_address.as_u64[0] = clib_net_to_host_u64 (a->address.as_u64[0]);
  ip6_address.as_u64[1] = clib_net_to_host_u64 (a->address.as_u64[1]);

  return ip6_address;
}

/*
 * The sender of the INIT shall use this parameter to suggest to the
 * receiver of the INIT for a longer life-span of the State Cookie.
 */
/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Type = 9             |          Length = 8           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Suggested Cookie Life-Span Increment (msec.)          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_opt_params_hdr_t param_hdr;

  /*
   * This parameter indicates to the receiver how much increment in
   * milliseconds the sender wishes the receiver to add to its default
   * cookie life-span.
   *
   * This optional parameter should be added to the INIT chunk by the
   * sender when it reattempts establishing an association with a peer
   * to which its previous attempt of establishing the association
   * failed due to a stale cookie operation error. The receiver MAY
   * choose to ignore the suggested cookie life-span increase for its
   * own security reasons.
   */
  u32 life_span_inc;

} sctp_cookie_preservative_param_t;

always_inline void
vnet_sctp_set_cookie_preservative (sctp_cookie_preservative_param_t * c,
				   u32 life_span_inc)
{
  c->param_hdr.type = clib_host_to_net_u16 (SCTP_COOKIE_PRESERVATIVE_TYPE);
  c->param_hdr.length = clib_host_to_net_u16 (8);
  c->life_span_inc = clib_host_to_net_u32 (life_span_inc);
}

always_inline u32
vnet_sctp_get_cookie_preservative (sctp_cookie_preservative_param_t * c)
{
  return (clib_net_to_host_u32 (c->life_span_inc));
}

#define FQDN_MAX_LENGTH 256

/*
 * The sender of INIT uses this parameter to pass its Host Name (in
 * place of its IP addresses) to its peer.
 * The peer is responsible for resolving the name.
 * Using this parameter might make it more likely for the association to work
 * across a NAT box.
 */
/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Type = 11            |          Length               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                          Host Name                            /
 * \                                                               \
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_opt_params_hdr_t param_hdr;


  /*
   * This field contains a host name in "host name syntax" per RFC 1123
   * Section 2.1
   *
   * Note: At least one null terminator is included in the Host Name
   * string and must be included in the length.
   */
  char hostname[FQDN_MAX_LENGTH];

} sctp_hostname_param_t;

always_inline void
vnet_sctp_set_hostname_address (sctp_hostname_param_t * h, char *hostname)
{
  h->param_hdr.length = FQDN_MAX_LENGTH;
  h->param_hdr.type = clib_host_to_net_u16 (SCTP_HOSTNAME_ADDRESS_TYPE);
  clib_memset (h->hostname, '0', FQDN_MAX_LENGTH);
  memcpy (h->hostname, hostname, FQDN_MAX_LENGTH);
}

#define MAX_SUPPORTED_ADDRESS_TYPES	3

/*
 * The sender of INIT uses this parameter to list all the address types
 * it can support.
 */
/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Type = 12            |          Length               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        Address Type #1        |        Address Type #2        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                            ......                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+
 */
typedef struct
{
  sctp_opt_params_hdr_t param_hdr;

  u16 address_type[MAX_SUPPORTED_ADDRESS_TYPES];

} sctp_supported_addr_types_param_t;

always_inline void
vnet_sctp_set_supported_address_types (sctp_supported_addr_types_param_t * s)
{
  s->param_hdr.type = clib_host_to_net_u16 (SCTP_SUPPORTED_ADDRESS_TYPES);
  s->param_hdr.length = 4 /* base = type + length */  +
    MAX_SUPPORTED_ADDRESS_TYPES * 4;	/* each address type is 4 bytes */

  s->address_type[0] = clib_host_to_net_u16 (SCTP_IPV4_ADDRESS_TYPE);
  s->address_type[1] = clib_host_to_net_u16 (SCTP_IPV6_ADDRESS_TYPE);
  s->address_type[2] = clib_host_to_net_u16 (SCTP_HOSTNAME_ADDRESS_TYPE);
}

/*
 * Error cause codes to be used for the sctp_error_cause.cause_code field
 */
#define INVALID_STREAM_IDENTIFIER	1
#define MISSING_MANDATORY_PARAMETER	2
#define STALE_COOKIE_ERROR		3
#define OUT_OF_RESOURCE			4
#define UNRESOLVABLE_ADDRESS		5
#define UNRECOGNIZED_CHUNK_TYPE		6
#define INVALID_MANDATORY_PARAMETER	7
#define UNRECOGNIZED_PARAMETER		8
#define NO_USER_DATA			9
#define COOKIE_RECEIVED_WHILE_SHUTTING_DOWN	10
#define RESTART_OF_ASSOCIATION_WITH_NEW_ADDR	11
#define USER_INITIATED_ABORT		12
#define PROTOCOL_VIOLATION		13

always_inline void
vnet_sctp_set_state_cookie (sctp_state_cookie_param_t * s)
{
  s->param_hdr.type = clib_host_to_net_u16 (SCTP_STATE_COOKIE_TYPE);

  /* TODO: length & value to be populated */
}

typedef struct
{
  sctp_opt_params_hdr_t param_hdr;

  u32 value[];

} sctp_unrecognized_param_t;

always_inline void
vnet_sctp_set_unrecognized_param (sctp_unrecognized_param_t * u)
{
  u->param_hdr.type = clib_host_to_net_u16 (UNRECOGNIZED_PARAMETER);

  /* TODO: length & value to be populated */
}

/*
 * Selective ACK (SACK) chunk
 *
 * This chunk is sent to the peer endpoint to acknowledge received DATA
 * chunks and to inform the peer endpoint of gaps in the received
 * subsequences of DATA chunks as represented by their TSNs.
 */
/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 3    |Chunk  Flags   |      Chunk Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Cumulative TSN Ack                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Advertised Receiver Window Credit (a_rwnd)           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Number of Gap Ack Blocks = N  |  Number of Duplicate TSNs = X |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Gap Ack Block #1 Start       |   Gap Ack Block #1 End        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                                                               /
 * \                              ...                              \
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Gap Ack Block #N Start      |  Gap Ack Block #N End         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Duplicate TSN 1                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                                                               /
 * \                              ...                              \
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Duplicate TSN X                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_header_t sctp_hdr;
  sctp_chunks_common_hdr_t chunk_hdr;
  /*
   * This parameter contains the TSN of the last DATA chunk received in
   * sequence before a gap.  In the case where no DATA chunk has been
   * received, this value is set to the peer's Initial TSN minus one.
   */
  u32 cumulative_tsn_ack;

  /*
   * This field indicates the updated receive buffer space in bytes of
   * the sender of this SACK.
   */
  u32 a_rwnd;

  /*
   * Indicates the number of Gap Ack Blocks included in this SACK.
   */
  u16 gap_ack_blocks_count;

  /*
   * This field contains the number of duplicate TSNs the endpoint has
   * received.  Each duplicate TSN is listed following the Gap Ack Block
   * list.
   */
  u16 duplicate_tsn_count;

  /*
   * Indicates the Start offset TSN for this Gap Ack Block. To calculate
   * the actual TSN number the Cumulative TSN Ack is added to this offset
   * number. This calculated TSN identifies the first TSN in this Gap Ack
   * Block that has been received.
   */
  u16 *gap_ack_block_start;

  /*
   * Indicates the End offset TSN for this Gap Ack Block. To calculate
   * the actual TSN number, the Cumulative TSN Ack is added to this offset
   * number. This calculated TSN identifies the TSN of the last DATA chunk
   * received in this Gap Ack Block.
   */
  u16 *gap_ack_block_end;

  /*
   * Indicates the number of times a TSN was received in duplicate since
   * the last SACK was sent. Every time a receiver gets a duplicate TSN
   * (before sending the SACK), it adds it to the list of duplicates.
   * The duplicate count is reinitialized to zero after sending each SACK.
   */
  u32 duplicate_tsn;

} sctp_selective_ack_chunk_t;

always_inline void
vnet_sctp_set_cumulative_tsn_ack (sctp_selective_ack_chunk_t * s,
				  u32 cumulative_tsn_ack)
{
  vnet_sctp_set_chunk_type (&s->chunk_hdr, SACK);
  s->cumulative_tsn_ack = clib_host_to_net_u32 (cumulative_tsn_ack);
}

always_inline u32
vnet_sctp_get_cumulative_tsn_ack (sctp_selective_ack_chunk_t * s)
{
  return clib_net_to_host_u32 (s->cumulative_tsn_ack);
}

always_inline void
vnet_sctp_set_arwnd (sctp_selective_ack_chunk_t * s, u32 a_rwnd)
{
  vnet_sctp_set_chunk_type (&s->chunk_hdr, SACK);
  s->a_rwnd = clib_host_to_net_u32 (a_rwnd);
}

always_inline u32
vnet_sctp_get_arwnd (sctp_selective_ack_chunk_t * s)
{
  return clib_net_to_host_u32 (s->a_rwnd);
}

always_inline void
vnet_sctp_set_gap_ack_blocks_count (sctp_selective_ack_chunk_t * s,
				    u16 gap_ack_blocks_count)
{
  vnet_sctp_set_chunk_type (&s->chunk_hdr, SACK);
  s->gap_ack_blocks_count = clib_host_to_net_u16 (gap_ack_blocks_count);

  if (s->gap_ack_block_start == NULL)
    s->gap_ack_block_start =
      clib_mem_alloc (sizeof (u16) * gap_ack_blocks_count);
  if (s->gap_ack_block_end == NULL)
    s->gap_ack_block_end =
      clib_mem_alloc (sizeof (u16) * gap_ack_blocks_count);
}

always_inline u16
vnet_sctp_get_gap_ack_blocks_count (sctp_selective_ack_chunk_t * s)
{
  return clib_net_to_host_u32 (s->gap_ack_blocks_count);
}

always_inline void
vnet_sctp_set_duplicate_tsn_count (sctp_selective_ack_chunk_t * s,
				   u16 duplicate_tsn_count)
{
  vnet_sctp_set_chunk_type (&s->chunk_hdr, SACK);
  s->duplicate_tsn_count = clib_host_to_net_u16 (duplicate_tsn_count);
}

always_inline u16
vnet_sctp_get_duplicate_tsn_count (sctp_selective_ack_chunk_t * s)
{
  return clib_net_to_host_u16 (s->duplicate_tsn_count);
}

/*
 * Heartbeat Info
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Heartbeat Info Type=1      |         HB Info Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                  Sender-Specific Heartbeat Info               /
 * \                                                               \
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_opt_params_hdr_t param_hdr;

  /*
   * The Sender-Specific Heartbeat Info field should normally include
   * information about the sender's current time when this HEARTBEAT
   * chunk is sent and the destination transport address to which this
   * HEARTBEAT is sent.
   * This information is simply reflected back by the receiver in the
   * HEARTBEAT ACK message.
   *
   * Note also that the HEARTBEAT message is both for reachability
   * checking and for path verification.
   * When a HEARTBEAT chunk is being used for path verification purposes,
   * it MUST hold a 64-bit random nonce.
   */
  u64 hb_info;

} sctp_hb_info_param_t;

always_inline void
vnet_sctp_set_heartbeat_info (sctp_hb_info_param_t * h, u64 hb_info,
			      u16 hb_info_length)
{
  h->hb_info = clib_host_to_net_u16 (1);
  h->param_hdr.length = clib_host_to_net_u16 (hb_info_length);
  h->hb_info = clib_host_to_net_u64 (hb_info);
}

/*
 * Heartbeat Request
 *
 * An endpoint should send this chunk to its peer endpoint to probe the
 * reachability of a particular destination transport address defined in
 * the present association.
 * The parameter field contains the Heartbeat Information, which is a
 * variable-length opaque data structure understood only by the sender.
 */
/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 4    | Chunk  Flags  |      Heartbeat Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * \                                                               \
 * /            Heartbeat Information TLV (Variable-Length)        /
 * \                                                               \
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_header_t sctp_hdr;
  sctp_chunks_common_hdr_t chunk_hdr;
  sctp_hb_info_param_t hb_info;

} sctp_hb_req_chunk_t;

always_inline void
vnet_sctp_set_hb_request_info (sctp_hb_req_chunk_t * h,
			       sctp_hb_info_param_t * hb_info)
{
  vnet_sctp_set_chunk_type (&h->chunk_hdr, HEARTBEAT);
  memcpy (&h->hb_info, hb_info, sizeof (h->hb_info));
}

/*
 * Heartbeat Acknowledgement
 *
 * An endpoint should send this chunk to its peer endpoint as a response
 * to a HEARTBEAT chunk.
 * A HEARTBEAT ACK is always sent to the source IP address of the IP datagram
 * containing the HEARTBEAT chunk to which this ack is responding.
 */
/*
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 5    | Chunk  Flags  |    Heartbeat Ack Length       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * \                                                               \
 * /            Heartbeat Information TLV (Variable-Length)        /
 * \                                                               \
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef sctp_hb_req_chunk_t sctp_hb_ack_chunk_t;

always_inline void
vnet_sctp_set_hb_ack_info (sctp_hb_ack_chunk_t * h,
			   sctp_hb_info_param_t * hb_info)
{
  vnet_sctp_set_chunk_type (&h->chunk_hdr, HEARTBEAT_ACK);
  memcpy (&h->hb_info, hb_info, sizeof (h->hb_info));
}

/*
 * Error cause
 */
/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Cause Code          |       Cause Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                    Cause-Specific Information                 /
 * \                                                               \
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct
{

  sctp_opt_params_hdr_t param_hdr;
  u64 cause_info;

} sctp_err_cause_param_t;


/*
 * An end-point sends this chunk to its peer end-point to notify it of
 * certain error conditions.  It contains one or more error causes.
 * An Operation Error is not considered fatal in and of itself, but may be
 * used with an ABORT chunk to report a fatal condition.  It has the
 * following parameters:
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 9    | Chunk  Flags  |           Length              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * \                                                               \
 * /                    one or more Error Causes                   /
 * \                                                               \
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_header_t sctp_hdr;
  sctp_chunks_common_hdr_t chunk_hdr;
  sctp_err_cause_param_t err_causes[];

} sctp_operation_error_t;

/*
 * Abort Association (ABORT)
 *
 * The ABORT chunk is sent to the peer of an association to close the
 * association.  The ABORT chunk may contain Cause Parameters to inform
 * the receiver about the reason of the abort.  DATA chunks MUST NOT be
 * bundled with ABORT.  Control chunks (except for INIT, INIT ACK, and
 * SHUTDOWN COMPLETE) MAY be bundled with an ABORT, but they MUST be
 * placed before the ABORT in the SCTP packet or they will be ignored by
 * the receiver.
 *
 * If an endpoint receives an ABORT with a format error or no TCB is
 * found, it MUST silently discard it.  Moreover, under any
 * circumstances, an endpoint that receives an ABORT MUST NOT respond to
 * that ABORT by sending an ABORT of its own.
 */
/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 6    |Reserved     |T|           Length              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * \                                                               \
 * /                   zero or more Error Causes                   /
 * \                                                               \
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_header_t sctp_hdr;
  sctp_chunks_common_hdr_t chunk_hdr;
  sctp_err_cause_param_t err_causes[];

} sctp_abort_chunk_t;

always_inline void
vnet_sctp_set_tbit (sctp_abort_chunk_t * a)
{
  vnet_sctp_set_chunk_type (&a->chunk_hdr, ABORT);
  // a->chunk_hdr.flags = clib_host_to_net_u16 (1);
}

always_inline void
vnet_sctp_unset_tbit (sctp_abort_chunk_t * a)
{
  vnet_sctp_set_chunk_type (&a->chunk_hdr, ABORT);
  // a->chunk_hdr.flags = clib_host_to_net_u16 (0);
}

/*
 * Shutdown Association (SHUTDOWN)
 *
 * An endpoint in an association MUST use this chunk to initiate a
 * graceful close of the association with its peer.
 */
/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 7    | Chunk  Flags  |      Length = 8               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Cumulative TSN Ack                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_header_t sctp_hdr;
  sctp_chunks_common_hdr_t chunk_hdr;
  /*
   * This parameter contains the TSN of the last chunk received in
   * sequence before any gaps.
   *
   * Note: Since the SHUTDOWN message does not contain Gap Ack Blocks,
   * it cannot be used to acknowledge TSNs received out of order. In a
   * SACK, lack of Gap Ack Blocks that were previously included
   * indicates that the data receiver reneged on the associated DATA
   * chunks. Since SHUTDOWN does not contain Gap Ack Blocks, the
   * receiver of the SHUTDOWN shouldn't interpret the lack of a Gap Ack
   * Block as a renege.
   */
  u32 cumulative_tsn_ack;

} sctp_shutdown_association_chunk_t;

always_inline void
vnet_sctp_set_tsn_last_received_chunk (sctp_shutdown_association_chunk_t * s,
				       u32 tsn_last_chunk)
{
  vnet_sctp_set_chunk_type (&s->chunk_hdr, SHUTDOWN);
  s->cumulative_tsn_ack = clib_host_to_net_u32 (tsn_last_chunk);
}

/*
 * Shutdown Acknowledgement (SHUTDOWN ACK)
 *
 * This chunk MUST be used to acknowledge the receipt of the SHUTDOWN
 * chunk at the completion of the shutdown process.
 */
/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Type = 8    |Chunk  Flags   |      Length = 4               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  sctp_header_t sctp_hdr;
  sctp_chunks_common_hdr_t chunk_hdr;
} sctp_shutdown_ack_chunk_t;

always_inline void
vnet_sctp_fill_shutdown_ack (sctp_shutdown_ack_chunk_t * s)
{
  vnet_sctp_set_chunk_type (&s->chunk_hdr, SHUTDOWN_ACK);
  vnet_sctp_set_chunk_length (&s->chunk_hdr, 4);
}

#endif /* included_vnet_sctp_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
