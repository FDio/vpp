/*
 * trace_util.h -- Trace Profile Utility header
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 * NOTE: This file utilizes IEFT IOAM DATA DRAFTE v10
*/
/**
 * Usage:
 *
 * On any node that participates in iOAM Trace.
 *
 * Step 1: Initialize this library by calling trace_init()
 * Step 2: Setup a trace  profile that contains all the parameters needed to compute cumulative:
 *         Call these functions:
 *         trace_profile_find
 *         trace_profile_create
 * Step 2a: On initial node enable the profile to be used:
 *          trace_profile_set_active / trace_profile_get_active will return the profile
 * Step 4: TBD
 *         trace_validate
 *
 */
#ifndef include_vnet_trace_util_h
#define include_vnet_trace_util_h

#define debug_ioam debug_ioam_fn

// Useful
#define htonll64(x)    (((u64)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll64(x)    (((u64)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

/*
 * Data-Field - Set of bits with a defined format and meaning, 4 categories
 * Preallocated, Incremental, Proof of Transit, and Edge to Edge
 */
/*
 * Pre alloc - pre allocated space in packet for telemetry data
 * Incremental - Node allocates and pushes telemetry data following option header
 * PoT - Proof of transit
 * E2E - Edge-to-Edge
 * A nodes can use any of these simultaneously, incremental must precede prealloc
 */
#define IOAM_OPTION_PREALLOC    (1<<0)
#define IOAM_OPTION_INCREMENT   (1<<1)
#define IOAM_OPTION_POT         (1<<2)
#define IOAM_OPTION_E2E         (1<<3)
/*
 * Node can only be one !
 * Encapsulation node - A node that adds at least one iOAM option and/or iOAM data
 *                      as packet enters iOAM domain
 * Transit node - Adds iOAM data within an iOAM domain based on the provided iOAM
 *                option type. DOES NOT add new or alter existing option types
 * Decapsulation node - In charge of removing iOAM option type and data before
 *                      leaving iOAM domain
*/
#define IOAM_NODE_ENCAP     (1<<0)
#define IOAM_NODE_TRANSIT   (1<<1)
#define IOAM_NODE_DECAP     (1<<2)

#define IOAM_TSP_SECONDS       ((u8)0)
#define IOAM_TSP_MILLISECONDS  ((u8)1)
#define IOAM_TSP_MICROSECONDS  ((u8)2)
#define IOAM_TSP_NANOSECONDS   ((u8)3)
#define IOAM_TSP_OPTION_SIZE   ((u8)4)

/*
 * Hop-by-hop extension
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |  Next Header  |  Hdr Ext Len  |      Options and Padding      |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +       Options and Padding, but will be header below           +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * iOAM Prealloc and Incremental Option Header
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |          Namespace ID         |  NodeLen | Flags| RemainingLen|
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                 iOAM Trace Type                |   Reserved   +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                       Node Data List [0]                      +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                              ...                              +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                       Node Data List [n]                      +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * namespace_id (16-bit) - unique id which is used by the Encap, Tranist, and Decap nodes
 *             in order to identify what iOAM options/data to alter/add/remove etc.
 *             Allows for a namespace specif interpretation of iOAM data fields.
 *             A subset of all the iOAM option types and data fields are associated
 *             with this ID. There exists two sub-ranges: Default is 0x0000
 *              - Operator-assigned range from 0x0001 to 0x7FFF
 *              - IANA-asigned range from 0x8000 to 0xFFFF
 *             Nodes can work on several Namespace IDs
 *
 * node_len (5-bit) - specified the length of data added by each no in multiples of 4-octets,
 *                    excluding the length of the "Opaque State Snapshot" field.
 *                    Set by Encap.
 *
 *      If iOAM trace type bit 22 is clear,
 *          node_len specifies the actual length added by each node,
 *      else, actual length added by each node is:
 *          node_len + length of "Opaque State Snapshot" field in 4-octet units
 *
 * flags (4-bit) - in IANA, section 8.3 in Draft IETF IPPM iOAM data v10
 *                 Bit 0 "Overflow" (MSB). set if Number of iOAM nodes to aggregate their telemetry
 *                 data is greater than the PMTU.
 *
 * remaining_len (7-bit) - specifies the data space in multiples of 4-octets remaining for
 *      recording the node data, before the node data list is considered to have overflowed.
 *      Can be set to MTU (PMTU) in order to compare with node_len how much space there is left.
 *      In prealloc, this can be used as index for data array, = remaining_len - node_len
 *
 * trace_type (24-bit) - view bit definitions below,
    iOAM-trace-type if above bits are set accordingly
    the format of node header data is something like the following.
    Short/Wide formats - use is not exclusive, so both can be used

          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Hop_Lim     |              node_id (short)                  |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |     ingress_if_id (short)       |     egress_if_id (short)    |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                       timestamp_sec                           +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                       timestamp_sub_sec                       +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +0|                       transit delay                         +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                        app_data (short)                       |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                          queue_depth                          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                       checksum_complement                     |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Hop_Lim     |              node_id (wide)                  |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                      node_id_cont (wide)                      |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                      ingress_if_id (wide)                     +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                      egress_if_id (wide)                      +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                      app_data_cont (wide)                     |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                        buffer_occupancy                       |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         // opaue data length in 4 octets, max 255 * 4 = 1020 (bytes)
         |     length    |               schema_id                       |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                           opaque_data                         |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                               ...                             |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                           opaque_data                         |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

         Explaination of Trace Type data
 *
 * Reserved (8-bit) - Encap must set the value to 0s and ignored by transit nodes
 *
 * Node data list (variable length field) - data elements determined by trace type
 *      Order of data followed Trace Type bit order (below). If node is not able to
 *      populate the data field, it is filled with all 0xFs.
 */
 // Trace type instruction bitmap
#define    IOAM_INSTR_BITMAP_MASK     0x00400FFF
// from pg 15
#define    IOAM_BIT_TTL_NODEID_SHORT       (1<<0)
#define    IOAM_BIT_ING_EGR_INT_SHORT      (1<<1)
#define    IOAM_BIT_TIMESTAMP_SEC          (1<<2)
#define    IOAM_BIT_TIMESTAMP_SUB_SEC      (1<<3)
#define    IOAM_BIT_TRANSIT_DELAY          (1<<4)
#define    IOAM_BIT_APPDATA_SHORT_DATA     (1<<5)
#define    IOAM_BIT_QUEUE_DEPTH            (1<<6)
#define    IOAM_BIT_CHECKSUM_COMPLEMENT    (1<<7)
#define    IOAM_BIT_TTL_NODEID_WIDE        (1<<8)
#define    IOAM_BIT_ING_EGR_INT_WIDE       (1<<9)
#define    IOAM_BIT_APPDATA_WIDE_DATA      (1<<10)
#define    IOAM_BIT_BUFFER_OCCUPANCY       (1<<11)
/*12-21 are undefined, view pg 16, set to 0 */
// variable length opaue state snapshot
#define    IOAM_BIT_VAR_LEN_OP_ST_SNSH     (1<<22)
// 23 is reserved, set to 0
// Trace Flags
#define IOAM_BIT_FLAG_OVERFLOW             (1<<7)
#define IOAM_BIT_FLAG_LOOPBACK             (1<<8)
#define IOAM_BIT_FLAG_LOOPBACK_REPLY       (1<<9)
// For old iOAM Plugin
#define BIT_LOOPBACK                        IOAM_BIT_FLAG_LOOPBACK

// Trace overflow flag, but also used to indicate if we need to add transit delay
#define IOAM_BIT_TRANSIT_DELAY_OVERFLOW    (1<<31)
// Empty values
#define IOAM_EMPTY_FIELD_U8      (0xFF)
#define IOAM_EMPTY_FIELD_U16     (0xFFFF)
#define IOAM_EMPTY_FIELD_U24     (0x00FFFFFF)
#define IOAM_EMPTY_FIELD_U32     (0xFFFFFFFF)
#define IOAM_EMPTY_FIELD_U56     (0x00FFFFFFFFFFFFFF)
#define IOAM_EMPTY_FIELD_U64     (0xFFFFFFFFFFFFFFFF)

#define IOAM_NAMESPACE_ID_MASK  ((u32)0xFFFF0000)
#define IOAM_NODE_LEN_MASK      ((u16)0xF800)
#define IOAM_FLAGS_MASK         ((u16)0x0780)
#define IOAM_REMAIN_LEN_MASK    ((u16)0x0000007F)
#define IOAM_SET_NODE_LEN(len)  ((u16)((len) << 11) & IOAM_NODE_LEN_MASK)
#define IOAM_GET_NODE_LEN(n)    ((u16)((n) & IOAM_NODE_LEN_MASK) >> 11)
#define IOAM_TRACE_TYPE_MASK    ((u32)0xFFFFFF00)
#define IOAM_SET_TRACETYPE(tt)  ((u32)(clib_host_to_net_u32((tt & IOAM_INSTR_BITMAP_MASK) << 8)))
#define IOAM_GET_TRACETYPE(tt)  ((u32)((clib_net_to_host_u32(tt) >> 8) & IOAM_INSTR_BITMAP_MASK))
typedef CLIB_PACKED (struct ioam_trace_hdr_
		     {
		     u16 namespace_id;
		     u16 node_len_flags_remaining_len;
		     u32 trace_type;	// only 24-bits, last 8 is for reserved(=0)
		     u32 data_list[0];
		     }) ioam_trace_hdr_t;

#define IOAM_MAX_OPAQUE_DATA_WORD_SIZE        ((u8)255)
#define IOAM_MAX_OPAQUE_DATA_BYTE_SIZE        ((u16)(IOAM_MAX_OPAQUE_DATA_WORD_SIZE<<2))
#define IOAM_OPAQUE_LEN_MASK                  ((u32)0xFF000000)
#define IOAM_OPAQUE_SCHEMEID_MASK             ((u32)0x00FFFFFF)
#define IOAM_GET_OPAQUE_LEN(b)                ((u8)(((IOAM_OPAQUE_LEN_MASK & (b)) >> 24)))
#define IOAM_SET_OPAQUE_HEADER(len,schemaid)  ((u32)((((len) << 24) & IOAM_OPAQUE_LEN_MASK) | (schemaid & IOAM_OPAQUE_SCHEMEID_MASK)))
// Max data each node can add, minus opaque (60 bytes)
#define IOAM_MAX_DATA_NO_OPAQUE               ((u8)60)
// Max data per node with opaque = 1084-bytes max, +4 due to opaque header
#define IOAM_MAX_DATA_W_OPAQUE                ((u16)(IOAM_MAX_DATA_NO_OPAQUE + 4 + IOAM_MAX_OPAQUE_DATA_BYTE_SIZE))
typedef CLIB_PACKED (struct opaque_scheme_
		     {
		     u32 len_schemeid;
		     u32 * data;
		     }) opaque_scheme_t;

// Queue depth type for device driver
#define QUEUE_DEPTH_AF_PACKET   (1<<0)
#define QUEUE_DEPTH_DPDK        (1<<1)
// These below are not implemented
/*
#define QUEUE_DEPTH_PIPE        (1<<2)
#define QUEUE_DEPTH_TUNTAP      (1<<3)
#define QUEUE_DEPTH_VIRTIO      (1<<4)
#define QUEUE_DEPTH_NETLINK     (1<<5)
*/
/*
 * User sets these values to setup the trace profile
*/
typedef struct trace_profile_
{
  u8 valid:1;
  u16 namespace_id;
  u8 num_elts;
  u32 node_id_short;
  u64 node_id_wide;
  u32 app_data_short;
  u64 app_data_wide;
  u8 option_type;
  u32 trace_type;
  u8 node_type;
  u8 ts_format;
  u8 queue_depth_type;
  opaque_scheme_t opaque;
} trace_profile;

typedef struct
{
  /* Name of the default profile list in use */
  trace_profile profile;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} trace_main_t;

/*
 * Initialize Trace profile
 */
int trace_util_init (void);

/* setup and clean up profile */
int trace_profile_create (trace_profile * profile,
			  trace_profile * user_defined);

void clear_trace_profiles (void);

// Defined as 24-bit
static inline u32
fetch_trace_data_size (trace_profile * profile)
{
  u32 trace_data_size = 0;
  u32 trace_type = profile->trace_type;

  if (trace_type & IOAM_BIT_TTL_NODEID_SHORT)
    {
      trace_data_size += 4;
    }
  if (trace_type & IOAM_BIT_ING_EGR_INT_SHORT)
    {
      trace_data_size += 4;
    }
  if (trace_type & IOAM_BIT_TIMESTAMP_SEC)
    {
      trace_data_size += 4;
    }
  if (trace_type & IOAM_BIT_TIMESTAMP_SUB_SEC)
    {
      trace_data_size += 4;
    }
  if (trace_type & IOAM_BIT_TRANSIT_DELAY)
    {
      trace_data_size += 4;
    }
  if (trace_type & IOAM_BIT_APPDATA_SHORT_DATA)
    {
      trace_data_size += 4;
    }
  if (trace_type & IOAM_BIT_QUEUE_DEPTH)
    {
      trace_data_size += 4;
    }
  if (trace_type & IOAM_BIT_CHECKSUM_COMPLEMENT)
    {
      trace_data_size += 4;
    }
  if (trace_type & IOAM_BIT_TTL_NODEID_WIDE)
    {
      trace_data_size += 8;
    }
  if (trace_type & IOAM_BIT_ING_EGR_INT_WIDE)
    {
      trace_data_size += 8;
    }
  if (trace_type & IOAM_BIT_APPDATA_WIDE_DATA)
    {
      trace_data_size += 8;
    }
  if (trace_type & IOAM_BIT_BUFFER_OCCUPANCY)
    {
      trace_data_size += 4;
    }
  if (trace_type & IOAM_BIT_VAR_LEN_OP_ST_SNSH)
    {
      trace_data_size += 4;	// for opaque header, data is variable length but max 255*4 bytes
      trace_data_size +=
	IOAM_GET_OPAQUE_LEN (profile->opaque.len_schemeid) << 2;
    }
  return trace_data_size;
}

always_inline void
ioam_tracetype_set_bit (ioam_trace_hdr_t * trace_hdr, u32 trace_bit)
{
  trace_hdr->trace_type |= clib_host_to_net_u32 (trace_bit);
}

always_inline void
ioam_tracetype_reset_bit (ioam_trace_hdr_t * trace_hdr, u32 trace_bit)
{
  trace_hdr->trace_type &= clib_host_to_net_u32 (~trace_bit);
}

always_inline void
ioam_traceflag_set_bit (ioam_trace_hdr_t * trace_hdr, u16 flag_bit)
{
  trace_hdr->node_len_flags_remaining_len |= clib_host_to_net_u16 (flag_bit);
}

always_inline void
ioam_traceflag_reset_bit (ioam_trace_hdr_t * trace_hdr, u16 flag_bit)
{
  trace_hdr->node_len_flags_remaining_len &= clib_host_to_net_u16 (~flag_bit);
}

static inline void
ioam_print_profile (trace_profile * profile)
{
  if (profile)
    {
      vlib_cli_output (vlib_get_main (), "iOAM Profile:\n");
      vlib_cli_output (vlib_get_main (),
		       " - namespace-id %d\n - num-elts %d\n - node-id-short %d\n - app-data-short 0x%x\n - node-id-wide %Ld\n - app-data-wide 0x%Lx\n - option-type %d\n - trace-type 0x%x\n - node-type %d\n - ts-format-sub %d\n - opaque-len %d\n - opaque-id %d\n",
		       profile->namespace_id, profile->num_elts,
		       profile->node_id_short, profile->app_data_short,
		       profile->node_id_wide, profile->app_data_wide,
		       profile->option_type, profile->trace_type,
		       profile->node_type, profile->ts_format,
		       IOAM_GET_OPAQUE_LEN (profile->
					    opaque.len_schemeid) << 2,
		       IOAM_OPAQUE_SCHEMEID_MASK & profile->
		       opaque.len_schemeid);
    }
  else
    {
      vlib_cli_output (vlib_get_main (), "No iOAM Profile to print.\n");
    }
}

int ioam_trace_get_sizeof_handler (u32 * result);
int ip6_trace_profile_setup (void);
int ip6_trace_profile_cleanup (void);


#endif /* include_vnet_trace_util_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
