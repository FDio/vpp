/*
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
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
#ifndef __included_cdp_protocol_h__
#define __included_cdp_protocol_h__

#include <vnet/ethernet/ethernet.h>	/* for ethernet_header_t */
#include <vnet/llc/llc.h>
#include <vnet/snap/snap.h>
#include <vnet/srp/packet.h>

typedef CLIB_PACKED (struct
		     {
		     u8 version;
		     u8 ttl;
		     u16 checksum;	/* 1's complement of the 1's complement sum */
		     u8 data[0];
		     }) cdp_hdr_t;

typedef struct
{
  u8 dst_address[6];
  u8 src_address[6];
  u16 len;
} ethernet_802_3_header_t;

typedef CLIB_PACKED (struct
		     {
		     ethernet_802_3_header_t ethernet;
		     llc_header_t llc; snap_header_t snap; cdp_hdr_t cdp;
		     }) ethernet_llc_snap_and_cdp_header_t;

typedef CLIB_PACKED (struct
		     {
		     hdlc_header_t hdlc; cdp_hdr_t cdp;
		     }) hdlc_and_cdp_header_t;

typedef CLIB_PACKED (struct
		     {
		     srp_header_t srp;
		     ethernet_header_t ethernet; cdp_hdr_t cdp;
		     }) srp_and_cdp_header_t;

typedef CLIB_PACKED (struct
		     {
		     u16 t;
		     u16 l;
		     u8 v[0];
		     }) cdp_tlv_t;

/*
 * TLV codes.
 */
#define foreach_cdp_tlv_type                                    \
_(unused)                                                       \
_(device_name)		/* uniquely identifies the device    */ \
_(address)              /* list of addresses this device has */ \
_(port_id)              /* port CDP packet was sent out on   */ \
_(capabilities)         /* funct. capabilities of the device */ \
_(version)              /* version                           */ \
_(platform)             /* hardware platform of this device  */ \
_(ipprefix)             /* An IP network prefix              */ \
_(hello)                /* Pprotocol piggyback hello msg     */ \
_(vtp_domain)           /* VTP management domain             */ \
_(native_vlan)          /* Native VLAN number                */ \
_(duplex)               /* The interface duplex mode         */ \
_(appl_vlan)            /* Appliance VLAN-ID TLV             */ \
_(trigger)              /* For sending trigger TLV msgs.     */ \
_(power)                /* Power consumption of that device  */ \
_(mtu)                  /* MTU defined for sending intf.     */ \
_(trust)                /* Extended trust TLV                */ \
_(cos)                  /* COS for Untrusted Port TLV        */ \
_(sysname)              /* System name (FQDN of device)      */ \
_(sysobject)            /* OID of sysObjectID MIB object     */ \
_(mgmt_addr)            /* SNMP manageable addrs. of device  */ \
_(physical_loc)         /* Physical Location of the device   */ \
_(mgmt_addr2)           /* External Port-ID                  */ \
_(power_requested)                                              \
_(power_available)                                              \
_(port_unidirectional)                                          \
_(unknown_28)                                                   \
_(energywise)                                                   \
_(unknown_30)                                                   \
_(spare_poe)

typedef enum
{
#define _(t) CDP_TLV_##t,
  foreach_cdp_tlv_type
#undef _
} cdp_tlv_code_t;

/*
  The address TLV looks as follows:

          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                    Number of addresses                        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                   IDRP encoded address                        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	  An address is encoded in IDRP format:

	   0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |       PT      |    PT Length  |    Protocol (variable) ...
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |        Address length         |    Address (variable) ...
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	  PT: Protocol type
	      1 = NLPID format
              2 = 802.2 format

	  PT Length:
	      Length of protocol field, 1 for PT = 1, and either 3 or 8 for
	      802.2 format depending if SNAP is used for PT = 2.

	      The encodings for the other protocols have the following format:

          field:    <SSAP><DSAP><CTRL><-------OUI------><protocl_TYPE>
                    |     |     |     |     |     |     |     |      |
          bytes:    0     1     2     3     4     5     6     7      8

          where the first 3 bytes are 0xAAAA03 for SNAP encoded addresses.
          The OUI is 000000 for ethernet and <protocl_TYPE>
          is the assigned Ethernet type code for the particular protocol.
          e.g. for DECnet the encoding is AAAA03 000000 6003.
               for IPv6   the encoding is AAAA03 000000 86DD
*/

/*
 * Capabilities.
 */

#define CDP_ROUTER_DEVICE	0x0001
#define CDP_TB_DEVICE		0x0002
#define CDP_SRB_DEVICE		0x0004
#define CDP_SWITCH_DEVICE	0x0008
#define CDP_HOST_DEVICE		0x0010
#define CDP_IGMP_DEVICE		0x0020
#define CDP_REPEATER_DEVICE	0x0040

/*
  The protocol-hello TLV looks as follows:

           0         1         2         3
           012345678901234567890123456789012345678
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |      Type     |      Length   |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |           OUI                         |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |           Protocol ID         |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |   up to 27 bytes of message           |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/*
 * These macros define the valid values for the Duplex TLV.
 */
#define CDP_DUPLEX_TLV_HALF 0x0
#define CDP_DUPLEX_TLV_FULL 0x1

#endif /* __included_cdp_protocol_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
