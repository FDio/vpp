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

#ifndef included_vnet_geneve_packet_h
#define included_vnet_geneve_packet_h

/*
 *
 * As per draft https://tools.ietf.org/html/draft-ietf-nvo3-geneve-05
 *
 * Section 3.5
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Option Class         |      Type     |R|R|R| Length  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Variable Option Data                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define GENEVE_MAX_OPT_LENGTH 128

/*
 *
 * As per draft https://tools.ietf.org/html/draft-ietf-nvo3-geneve-05
 *
 * Section 7
 *
 * +----------------+--------------------------------------+
 * | Option Class   | Description                          |
 * +----------------+--------------------------------------+
 * | 0x0000..0x00FF | Unassigned - IETF Review             |
 * | 0x0100         | Linux                                |
 * | 0x0101         | Open vSwitch                         |
 * | 0x0102         | Open Virtual Networking (OVN)        |
 * | 0x0103         | In-band Network Telemetry (INT)      |
 * | 0x0104         | VMware                               |
 * | 0x0105..0xFFEF | Unassigned - First Come First Served |
 * | 0xFFF0..FFFF   | Experimental                         |
 * +----------------+--------------------------------------+
*/
#define LINUX_OPT_CLASS  0x0100
#define OVS_OPT_CLASS    0x0101
#define OVN_OPT_CLASS    0x0102
#define INT_OPT_CLASS    0x0103
#define VMWARE_OPT_CLASS 0x0104

/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Option Class         |      Type     |R|R|R| Length  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Variable Option Data                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
  u16 opt_class;
  u8 type;
  /* The 3 reserved bits are for future use;
   * Need to be 0 on sending and ignored on receipt.
   */
  u8 res;
  /* Length is expressed in 4-bytes multiples excluding the options header. */
  u8 length;
  u32 opt_data[];
} geneve_options_t;

/*
 *
 * As per draft https://tools.ietf.org/html/draft-ietf-nvo3-geneve-05
 *
 * Section 3/3.4
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        Virtual Network Identifier (VNI)       |    Reserved   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Variable Length Options                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
#define GENEVE_BASE_HEADER_LENGTH   8	// GENEVE BASE HEADER in bytes
#define GENEVE_MAX_TOTAL_HDR_LENGTH 260

#define GENEVE_VERSION 0
#define GENEVE_ETH_PROTOCOL 0x6558

typedef struct
{
  /*
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
  u32 first_word;

  /*
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |        Virtual Network Identifier (VNI)       |    Reserved   |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
  u32 vni_rsvd;
  geneve_options_t opts[];
} geneve_header_t;

#define GENEVE_VERSION_SHIFT	30
#define GENEVE_OPTLEN_SHIFT		24
#define GENEVE_O_BIT_SHIFT		23
#define GENEVE_C_BIT_SHIFT		22
#define GENEVE_6_RESERVED_SHIFT 16
#define GENEVE_VNI_SHIFT		8

#define GENEVE_VERSION_MASK		0xC0000000
#define GENEVE_OPTLEN_MASK		0x3F000000
#define GENEVE_O_BIT_MASK		0x00800000
#define GENEVE_C_BIT_MASK		0x00400000
#define GENEVE_6_RESERVED_MASK	0x003F0000
#define GENEVE_PROTOCOL_MASK	0x0000FFFF
#define GENEVE_VNI_MASK			0xFFFFFF00

/*
 * Return the VNI in host-byte order
 */
static inline u32
vnet_get_geneve_vni (geneve_header_t * h)
{
  return (clib_net_to_host_u32 (h->vni_rsvd & GENEVE_VNI_MASK) >>
	  GENEVE_VNI_SHIFT);
}

/*
 * Return the VNI in network-byte order
 *
 * To be used in the DECAP phase to create the lookup key (IP + VNI)
 */
static inline u32
vnet_get_geneve_vni_bigendian (geneve_header_t * h)
{
  u32 vni_host = vnet_get_geneve_vni (h);
  return clib_host_to_net_u32 ((vni_host << GENEVE_VNI_SHIFT) &
			       GENEVE_VNI_MASK);
}

static inline void
vnet_set_geneve_vni (geneve_header_t * h, u32 vni)
{
  h->vni_rsvd &= ~(GENEVE_VNI_MASK);
  h->vni_rsvd |=
    clib_host_to_net_u32 ((vni << GENEVE_VNI_SHIFT) & GENEVE_VNI_MASK);
}

static inline u8
vnet_get_geneve_version (geneve_header_t * h)
{
  return ((h->first_word & GENEVE_VERSION_MASK) >> GENEVE_VERSION_SHIFT);
}

static inline void
vnet_set_geneve_version (geneve_header_t * h, u8 version)
{
  h->first_word &= ~(GENEVE_VERSION_MASK);
  h->first_word |= ((version << GENEVE_VERSION_SHIFT) & GENEVE_VERSION_MASK);
}

static inline u8
vnet_get_geneve_options_len (geneve_header_t * h)
{
  return ((h->first_word & GENEVE_OPTLEN_MASK) >> GENEVE_OPTLEN_SHIFT);
}

static inline void
vnet_set_geneve_options_len (geneve_header_t * h, u8 len)
{
  h->first_word &= ~(GENEVE_OPTLEN_MASK);
  h->first_word |= ((len << GENEVE_OPTLEN_SHIFT) & GENEVE_OPTLEN_MASK);
}

static inline u8
vnet_get_geneve_oamframe_bit (geneve_header_t * h)
{
  return ((h->first_word & GENEVE_O_BIT_MASK) >> GENEVE_O_BIT_SHIFT);
}

static inline void
vnet_set_geneve_oamframe_bit (geneve_header_t * h, u8 oam)
{
  h->first_word &= ~(GENEVE_O_BIT_MASK);
  h->first_word |= ((oam << GENEVE_O_BIT_SHIFT) & GENEVE_O_BIT_MASK);
}

static inline u8
vnet_get_geneve_critical_bit (geneve_header_t * h)
{
  return ((h->first_word & GENEVE_C_BIT_MASK) >> GENEVE_C_BIT_SHIFT);
}

static inline void
vnet_set_geneve_critical_bit (geneve_header_t * h, u8 critical_opts)
{
  h->first_word &= ~(GENEVE_C_BIT_MASK);
  h->first_word |=
    ((critical_opts << GENEVE_C_BIT_SHIFT) & GENEVE_C_BIT_MASK);
}

static inline u16
vnet_get_geneve_protocol (geneve_header_t * h)
{
  return (h->first_word & GENEVE_PROTOCOL_MASK);
}

static inline void
vnet_set_geneve_protocol (geneve_header_t * h, u16 protocol)
{
  h->first_word &= ~(GENEVE_PROTOCOL_MASK);
  h->first_word |= (protocol & GENEVE_PROTOCOL_MASK);
}

static inline void
vnet_geneve_hdr_1word_ntoh (geneve_header_t * h)
{
  h->first_word = clib_net_to_host_u32 (h->first_word);
}

static inline void
vnet_geneve_hdr_1word_hton (geneve_header_t * h)
{
  h->first_word = clib_host_to_net_u32 (h->first_word);
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
