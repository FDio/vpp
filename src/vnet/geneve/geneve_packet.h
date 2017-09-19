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

typedef struct {
  u16 opt_class;
  u8 type;
  u8 res:3;
  u8 length:5;
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
#define GENEVE_MAX_TOTAL_HDR_LENGTH 260

#define GENEVE_VERSION 0 
#define GENEVE_ETH_PROTOCOL 0x6558

typedef struct {
  u8 ver:2;
  u8 opt_len:6;
  u8 oam_frame:1;
  u8 critical_options:1;
  u8 res1:6;
  u16 protocol;
  u32 vni:24;
  u8 res2;
  geneve_options_t opts[];
} geneve_header_t;

static inline u32 vnet_get_geneve_vni (geneve_header_t * h)
{
  return (clib_net_to_host_u32 (h->vni) >> 8);
}

static inline void vnet_set_geneve_vni (geneve_header_t * h, u32 vni)
{
  h->vni = clib_host_to_net_u32 (vni << 8);
}

static inline u8 vnet_get_geneve_version (geneve_header_t * h)
{
  return (clib_net_to_host_u32 (h->ver) >> 30);
}

static inline void vnet_set_geneve_version (geneve_header_t * h, u8 version)
{
  h->ver = clib_host_to_net_u32 (version << 30);
}

static inline u8 vnet_get_geneve_options_len (geneve_header_t * h)
{
  return (clib_net_to_host_u32 (h->opt_len) >> 24);
}

static inline void vnet_set_geneve_options_len (geneve_header_t * h, u8 len)
{
  h->opt_len = clib_host_to_net_u32 (len << 24);
}

static inline u8 vnet_get_geneve_oamframe_bit (geneve_header_t * h)
{
  return (clib_net_to_host_u32 (h->oam_frame) >> 23);
}

static inline void vnet_set_geneve_oamframe_bit (geneve_header_t * h, u8 oam)
{
  h->oam_frame = clib_host_to_net_u32 (oam << 23);
}

static inline u8 vnet_get_geneve_critical_bit (geneve_header_t * h)
{
  return (clib_net_to_host_u32 (h->critical_options) >> 22);
}

static inline void vnet_set_geneve_critical_bit (geneve_header_t * h, u8 critical_opts)
{
  h->critical_options = clib_host_to_net_u32 (critical_opts << 22);
}

static inline u16 vnet_get_geneve_protocol (geneve_header_t * h)
{
  return clib_net_to_host_u32 (h->protocol);
}

static inline void vnet_set_geneve_protocol (geneve_header_t * h, u16 protocol)
{
  h->protocol = clib_host_to_net_u32 (protocol);
}

#endif
