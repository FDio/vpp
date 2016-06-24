/*
 *-----------------------------------------------------------------------------
 *
 * Filename: tcp_header_definitions.h
 *
 * Description: Layer 2, 3, 4 definitions and header types
 *
 * Assumptions and Constraints:
 *
 * Copyright (c) 2012-2013 Cisco and/or its affiliates.
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
 *-----------------------------------------------------------------------------
 */

#ifndef __TCP_HEADER_DEFINITIONS_H__
#define __TCP_HEADER_DEFINITIONS_H__

/*
 * A general list of Layer 3 protocols, used by many Layer 2 encaps.
 *
 *                       formerly:
 * TYPE_IP               TYPE_IP10MB
 * TYPE_ARP              TYPE_RFC826_ARP
 * TYPE_RARP             TYPE_REVERSE_ARP
 * TYPE_MPLS             TYPE_TAGSWITCH
 */
#define   TYPE_IP                        0x0800
#define   TYPE_IP_V6                     0x86DD
#define   TYPE_ARP                       0x0806
#define   TYPE_RARP                      0x8035
#define   TYPE_MPLS                      0x8847
#define   TYPE_CDP                       0x2000
#define   TYPE_CGMP                      0x2001
#define   TYPE_LACP                      0x8808 /* 802.3ad */
#define   TYPE_CLNS                      0xFEFE

#define TYPE_PPPOE_SESSION               0x8864 /* PTA plus */
#define TYPE_PPPOE_DISCOVERY             0x8863 /* PTA plus */

/*
 * for atm arp handling
 */
#define IN_ATM_ARP_BIT     0x0008

/*
 * The Layer 2 header structures.
 */


/*
** HDLC
*/

typedef struct hdlc_hdr_type {
    u16 addr;
    u16 type;
    u8  data[0];
} hdlc_hdr_type;

#define    HDLC_ADDR_CMD                 0x0F00
#define    HDLC_HDR_LEN                  4
#define    HDLC_BROADCAST_BIT            31
#define    TYPE_KEEP                     0x8035

#define    HDLC_CLNS  (HDLC_ADDR_CMD<<16|TYPE_CLNS)
#define    HDLC_CDP   (HDLC_ADDR_CMD<<16|TYPE_CDP)
#define    HDLC_MPLS  (HDLC_ADDR_CMD<<16|TYPE_MPLS)
#define    HDLC_IP    (HDLC_ADDR_CMD<<16|TYPE_IP)
#define    HDLC_IP_V6 (HDLC_ADDR_CMD<<16|TYPE_IP_V6)
#define    HDLC_KEEPALIVE_CMD (HDLC_ADDR_CMD<<16|TYPE_KEEP)

/*
** PPP
*/

typedef struct ppp_comp_hdr_type {
    union {
        u8  ppp_u8[4];
        u16 ppp_u16[2];
        u32 ppp_u32;
    } ppp_comp_u;
} ppp_comp_hdr_type;

#define   PPP_STATION                    0xFF03
#define   PPP_STATION_LEN                0x2
#define   PPP_ENDPROTO                   0x01
#define   PPP_NOT_ENDPROTO               0xfffffffe
#define   PPP_CONTROL_PROTOCOL_MASK      0x8000
#define   PPP_CONTROL_PROTOCOL_BIT       15
#define   PPP_CSCO_LEN                   4
#define   PPP_RFC1661_LEN                2
#define   PPP_RFC1661_COMP_LEN           1

#define   TYPE_PPP_IP                    0x0021
#define   TYPE_PPP_IP_V6                 0x0057
#define   TYPE_PPP_MPLS_UNICAST          0x0281
#define   TYPE_PPP_MPLS_CONTROL          0x8281
#define   TYPE_PPP_CLNS                  0x0023
#define   TYPE_PPP_CDP                   0x0207

#define   TYPE_PPP_IPCP                  0x8021
#define   TYPE_PPP_LCP                   0xC021
#define   TYPE_PPP_PAP                   0xC023
#define   TYPE_PPP_LQR                   0xC025
#define   TYPE_PPP_CHAP                  0xC223


#define TYPE_PPP_LCP_ECHO_REQUEST               0x09
/*
** MultiLink PPP
*/

#define   MLPPP_FLAGS_FIELD_LEN          4
#define   MLPPP_BEGIN_MASK               0x80000000
#define   MLPPP_END_MASK                 0x40000000
#define   MLPPP_BEGIN_END_MASK           (MLPPP_BEGIN_MASK|MLPPP_END_MASK)
#define   MLPPP_BEGIN_END_SHIFT          30
#define   MLPPP_SEQUENCE_NUM_MASK        0x00FFFFFF
#define   MLPPP_MC_CLASS_ID_MASK         0x3C000000
#define   MLPPP_MC_CLASS_SHIFT           26

#define   TYPE_PPP_MULTILINK             0x003D

/* these are needed in the micro-code, for optimizations */
#define   TYPE_PPP_FULL_IP_4             0xff030021
#define   TYPE_PPP_FULL_IP_3             0xff0321
#define   TYPE_PPP_FULL_IP_2             0x0021
#define   TYPE_PPP_FULL_IP_1             0x21

#define   MLPPP_BEGIN_END_MASK_BYTE      0xC0
#define   MLPPP_BEGIN_BIT                7
#define   MLPPP_END_BIT                  6
#define   MLPPP_MC_CLASS_ID_MASK_BYTE    0x3C
#define   MLPPP_MC_CLASS_ID_SHIFT_BYTE   2

#define   MLPOA_BEGIN_END_SHIFT          24

/*
** Ethernet ARPA
*/


typedef struct ethernet_arpa_hdr_type {
    u8  daddr[6];
    u8  saddr[6];
    u16 type;
    u8  data[0];
} ethernet_arpa_hdr_type;

typedef struct extension_802p3_type {
    u16 type;
    u8  ctl;
    u8  data[0];
} extension_802p3_type;

typedef struct ethernet_802p3_hdr_type {
    u8  daddr[6];
    u8  saddr[6];
    u16 length;
    extension_802p3_type extension;
} ethernet_802p3_hdr_type;


typedef struct ethernet_vlan_802p3_hdr_type {
    u8  daddr[6];
    u8  saddr[6];
    u16 type1;
    u16 vlan_id;
    u16 length;
    extension_802p3_type extension;
} ethernet_vlan_802p3_hdr_type;

#define   MIN_ETHERNET_PKT_LEN           60
#define   MAX_ETHERNET_PKT_LEN           1500
#define   ETHERNET_ARPA_HDR_LEN          14
#define   ETHERNET_TYPE_FIELD_SIZE       2


/*
** Ethernet 802.1q (VLAN)
*/

typedef struct ethernet_vlan_hdr_type {
    u8  dest_addr[6];
    u8  src_addr[6];
    u16 type1;
    u16 vlan_hdr;
    u16 type2;
    u8  data[0];
} ethernet_vlan_hdr_type;


/*
** Ethernet 802.1.q-in-q (QinQ)
*/

typedef struct ethernet_qinq_hdr_type {
    u8  dest_addr[6];
    u8  src_addr[6];
    u16 type1;
    u16 vlan_hdr1;
    u16 type2;
    u16 vlan_hdr2;
    u16 type3;
    u8  data[0];
} ethernet_qinq_hdr_type;


/*
** Ethernet 802.3ad EtherChannel control
*/

typedef struct ethernet_lacp_hdr_type {
    u8  daddr[6];
    u8  saddr[6];
    u16 type;
    u16 LAcmd;
    u8  data[0];
} ethernet_lacp_hdr_type;


/*
** Ethernet 802.1 Bridge (spanning tree) PDU
*/

typedef struct ethernet_bpdu_hdr_type {
    u8  daddr[6];
    u8  saddr[6];
    u8  dsap;
    u8  ssap;
    u8  control;
    u8  more[0];
} ethernet_bpdu_hdr_type;

#define ETH_BPDU_DSAP       0x42
#define ETH_BPDU_SSAP       0x42
#define ETH_BPDU_CONTROL    0x03
#define ETH_BPDU_MATCH      0x424203


/************************************************************/
/*         PTA PLUS ETHERNET ENCAPSULATIONS                      */
/*
 * PPPoEoARPA 20 bytes
 */
typedef struct ethernet_pppoe_arpa_hdr_type {
    u8  daddr[6];
    u8  saddr[6];
    u16 type;
    /* pppoe hdr at begining of enet payload */
    u16 vtc;           /* version(4b), type(4b) and code(8b) fields */
    u16 sid;
    u16 len;
    u8  ppp_header[0]; /* PPP header start, no ff03 field present */
} ethernet_pppoe_arpa_hdr_type;

typedef struct pppoe_hdr_type {
    /* pppoe hdr at begining of enet payload */
    u16 vtc;           /* version(4b), type(4b) and code(8b) fields */
    u16 sid;
    u16 len;
    u8  ppp_header[0]; /* PPP header start, no ff03 field present */
} pppoe_hdr_type;

/*
** PPPoEoVLAN (802.1p or 802.1q) 24 bytes
*/
typedef struct ethernet_pppoe_vlan_hdr_type {
    u8  dest_addr[6];
    u8  src_addr[6];
    u16 type1;
    u16 vlan_hdr;
    u16 type2;
    /* pppoe hdr at begining of enet payload */
    u16 vtc;           /* version(4b), type(4b) and code(8b) fields */
    u16 sid;
    u16 len;
    u8  ppp_header[0]; /* PPP header start, no ff03 field present */
} ethernet_pppoe_vlan_hdr_type;

/*
** PPPoEoQinQ 28 bytes
*/
typedef struct ethernet_pppoe_qinq_hdr_type {
    u8  dest_addr[6];
    u8  src_addr[6];
    u16 type1;
    u16 vlan_hdr1;
    u16 type2;
    u16 vlan_hdr2;
    u16 type3;
    /* pppoe hdr at begining of enet payload */
    u16 vtc;           /* version(4b), type(4b) and code(8b) fields */
    u16 sid;
    u16 len;
    u8  ppp_header[0]; /* PPP header start, no ff03 field present */
} ethernet_pppoe_qinq_hdr_type;

#define  ETH_PPPOE_ARPA_HDR_LEN   sizeof(ethernet_pppoe_arpa_hdr_type)
#define  ETH_PPPOE_VLAN_HDR_LEN   sizeof(ethernet_pppoe_vlan_hdr_type)
#define  ETH_PPPOE_QINQ_HDR_LEN   sizeof(ethernet_pppoe_qinq_hdr_type)
#define  PPPOE_HDR_LEN  6
/*    End PTA PLUS ETHERNET ENCAPSULATIONS                           */
/****************************************************************/



#define   TYPE_DOT1Q                     0x8100
#define   DOT1Q_HDR_LEN                  18
#define   DOT1Q_VLAN_ID_MASK             0x0FFF
#define   DOT1Q_VLAN_ID_RES_0            0x0000
#define   DOT1Q_VLAN_ID_RES_4095         0x0FFF
#define   DOT1Q_ARPA_INDEX               DOT1Q_VLAN_ID_RES_0

#define   TYPE_QINQ_91                   0x9100
#define   TYPE_QINQ_92                   0x9200
#define   TYPE_QINQ_88A8                 0x88A8
#define   QINQ_HDR_LEN                   22

/*
 * 802.1p support
 */
#define  DOT1P_VLAN_COS_MASK  0xE000
#define  DOT1P_VLAN_COS_SHIFT 13
#define  DOT1P_MAX_COS_VALUE  7

/*
** Frame Relay
*/

/*
 *                          formerly:
 * TYPE_FR_IETF_IPV4        ENCAPS_FR_IETF
 * TYPE_FR_CISCO_IPV4       ENCAPS_FR_CISCO
 * TYPE_FR_ISIS             ENCAPS_FR_ISIS
 *
 * FR_LMI_DLCI_CISCO        LMI_DLCI_CISCO
 * FR_LMI_DLCI_IETF         LMI_DLCI_ITUANSI
 */

typedef struct frame_relay_hdr_type {
    u16 address;
    u16 control_nlpid;
    u8  data[0];
} frame_relay_hdr_type;

typedef struct fr_snap_hdr_type {
    u16 address;
    u8  control;
    u8  pad;
    u8  nlpid;
    u8  oui[3];
    u16 protocol_id;
} fr_snap_hdr_type;

#define   FR_ADDR_LEN                    2
#define   FR_CTL_NLPID_LEN               2
#define   FR_HDR_LEN                     (FR_ADDR_LEN+FR_CTL_NLPID_LEN)

/*
 * These defines are for the FR-SNAP header.
 * The SNAP header is set up solely so that we can
 * identify ARP packets, which look like this:
 *
 *   control  pad  nlpid    oui     protocol_id
 *     03     00    80    00 00 00    0806
 */
#define   FR_ARP_CONTROL                 0x03
#define   FR_ARP_PAD                     0x00
#define   FR_ARP_NLPID                   0x80
#define   FR_ARP_OUI_0                   0x00
#define   FR_ARP_OUI_1                   0x00
#define   FR_ARP_OUI_2                   0x00
/*
 * these are used only in the tmc code
 */
#define   FR_NLPID_OUI_LEN               4
#define   FR_ARP_CONTROL_PAD             0x0300
#define   FR_ARP_NLPID_OUI               0x80000000


#define   FR_DLCI_UPPER_MASK             0xFC00
#define   FR_DLCI_UPPER_SHIFT            6
#define   FR_DLCI_LOWER_MASK             0x00F0
#define   FR_DLCI_LOWER_SHIFT            4

/*
 * Defines for converting a DLCI for insertion into a synthesized FR address
 * field for FRoMPLS disposition.

 * bit 8  7   6   5   4   3   2   1
 * +-------------------------------+
 * |             Flag              |
 * | 0  1   1   1    1   1   1   0 |
 * +-------------------------------+
 * |   Upper DLCI          |C/R| 0 |
 * +-------------------------------+
 * |  Lower DLCI   | F | B | DE| 1 |
 * +-------------------------------+
 * |                               |
 * :Frame relay information field  :
 * :       (i.e.payload)           :
 * |                               |
 * +-------------------------------+
 * |   FCS (2 or 4 octets)         |
 * |                               |
 * +-------------------------------+
 * |             Flag              |
 * | 0  1   1   1    1   1   1   0 |
 * +-------------------------------+
 *
 *   a-With 10 bits for the DLCI
 */
#define   FR_DLCI_TO_HDR_UPPER_MASK      0x3f0
#define   FR_DLCI_TO_HDR_UPPER_SHIFT     (10-4)
#define   FR_DLCI_TO_HDR_LOWER_MASK      0xf
#define   FR_DLCI_TO_HDR_LOWER_SHIFT     4

#define   TYPE_FR_IETF_IP                0x03CC
#define   TYPE_FR_IETF_IP_V6             0x038E
#define   TYPE_FR_CISCO_IP               0x0800
#define   TYPE_FR_CISCO_IP_V6            0x86DD
#define   TYPE_FR_ISIS                   0x0383
#define   TYPE_FR_SNAP0PAD               0x0380
#define   TYPE_FR_SNAP1PAD               0x0300
#define   TYPE_FR_FRF12                  0x03B1
#define   TYPE_FR_MLP                    0x03CF
#define   TYPE_FR_EEK                    0x8037

#define   FR_LMI_DLCI_CISCO              1023
#define   FR_LMI_DLCI_IETF               0

#define   FR_NOT_NOT_NOT                 0
#define   FR_NOT_NOT_DE                  1
#define   FR_NOT_BECN_NOT                2
#define   FR_NOT_BECN_DE                 3
#define   FR_FECN_NOT_NOT                4
#define   FR_FECN_NOT_DE                 5
#define   FR_FECN_BECN_NOT               6
#define   FR_FECN_BECN_DE                7

#define   FR_FECN_BECN_DE_MASK           0x000E
#define   FR_FECN_BECN_DE_SHIFT          1

/* Address field extension bit for standard 2-byte FR address field */
#define   FR_EA1_MASK                    0x0001
#define   FR_EA1_MASK_BIT                0

/*
 * these are needed in the micro-code, for optimizations
 */

/* the bit position (in the address field) of the LSB of the DLCI */
#define   FR_DLCI_LS_BIT                 4


/*
**
** MultiLink Frame Relay
**
*/

typedef struct mlfr_hdr_type {
    u16 frag_hdr;
    u16 address;
    u16 control_nlpid;
    u8  data[0];
} mlfr_hdr_type;

/*
 * LIP frames have B, E and C set--the other
 *  bits in the frag_hdr field are irrelevant.
 *
 * NOTE: Injected LIP packets have a frag_hdr of 0xE100.
 *
 */
#define   MLFR_LIP_FRAME                 0xE100
#define   MLFR_LIP_MASK                  0xE000
#define   MLFR_FRAG_HDR_LEN              2

#define   MLFR_BEGIN_MASK                0x8000
#define   MLFR_END_MASK                  0x4000
#define   MLFR_BEGIN_END_MASK            (MLFR_BEGIN_MASK|MLFR_END_MASK)
#define   MLFR_BEGIN_END_SHIFT           14

#define   MLFR_SEQ_NUM_HI_MASK           0x1E00
#define   MLFR_SEQ_NUM_HI_SHIFT          1
#define   MLFR_SEQ_NUM_LO_MASK           0x00FF

/*
 * these are needed in the micro-code, for optimizations
 */
#define   MLFR_BEGIN_END_MASK_BYTE       0xC0


/*
 * FRF.12 definitions
 */
typedef struct frf12_hdr_type_ {
    u16 address;
    u16 control_nlpid;
    u16 frag_hdr;
    u8  data[0];
} frf12_hdr_type;

#define   FRF12_FRAG_HDR_LEN             sizeof(frf12_hdr_type)

#define   FRF12_BEGIN_MASK               0x8000
#define   FRF12_END_MASK                 0x4000
#define   FRF12_BEGIN_END_MASK           (FRF12_BEGIN_MASK|FRF12_END_MASK)
#define   FRF12_BEGIN_END_SHIFT          8

#define   FRF12_SEQ_NUM_HI_MASK          0x1E00
#define   FRF12_SEQ_NUM_HI_SHIFT         1
#define   FRF12_SEQ_NUM_LO_MASK          0x00FF
#define   FRF12_BEGIN_END_MASK_BYTE      0xC0



/*
**
** MLP over Frame Relay
**  The ppp hdr can be either a
**   an MLP hdr or a PPP hdr
**
**   MLP can be compressed or not:
**     a) 0xff03003d
**     b) 0x003d
**     c) 0x3d
**    followed by:
**     1 byte with begin/end bits
**     3 bytes of a sequence #
**
**  PPP can be also be compressed or not.
**    Only these will be fwded:
**     a) 0xff030021
**     b) 0xff0321
**     c) 0x0021
**     d) 0x21
**
**
*/
typedef struct mlpofr_hdr_type {
    u16 address;
    u16 control_nlpid;
    u8  ppp_header[0];
} mlpofr_hdr_type;

/*
** ATM -
*/

/*
 * channel_handle is defined as follows:
 *
 * bits 15      = reserved (must be 0)
 * bits 14 - 0  = channel handle
 *
 *
 * flags is a bitfield defined as follows:
 *
 * bits 15 - 13 = proto (PPPoA RFC1661 = 0,
 *                       PPPoE = 1,
 *                       RBE = 2,
 *                       PPPoA Cisco = 3,
 *                       MLPoATM RFC1661 = 4,
 *                       MLPoATM Cisco  = 5,
 *                       Reserved = 6-7)
 * bit       12 = encap (MUX=0,
 *                       SNAP=1)
 * bits 11 -  6 = reserved (must be 0)
 * bits  5 -  3 = pkt_type (AAL5 pkt = 0,
 *                          Raw cell (includes F4 OAM) = 1,
 *                          F5 segment OAM cell = 2
 *                          F5 end-to-end OAM cell = 3
 *                          Reserved = 4-7)
 * bit        2 = EFCI (congestion indication)
 * bit        1 = reserved (must be 0)
 * bit        0 = CLP (cell loss priority)
 */

typedef struct apollo_atm_generic_hdr_type {
    u16 channel_handle;
    u16 flags;
} apollo_atm_generic_hdr_type;

typedef struct apollo_atm_aal5_snap_hdr_type {
    u16 channel_handle;
    u16 flags;
    u8  dsap;
    u8  ssap;
    u8  control;
    u8  oui[3];
    u16 type;
    u8  data[0];
} apollo_atm_aal5_snap_hdr_type;

typedef struct atm_aal5_snap_hdr_type {
    u8  dsap;
    u8  ssap;
    u8  control;
    u8  oui[3];
    u16 pid;
    u16 pad;
    u8  data[0];
} atm_aal5_snap_hdr_type;


typedef struct apollo_atm_aal5_snap_hdr1_type {
    u16 channel_handle;
    u16 flags;
    u8  dsap;
    u8  ssap;
    u8  control;
    u8  oui0;
    u8  oui1;
    u8  oui2;
    u16 type;
    u8  data[0];
} apollo_atm_aal5_snap_hdr1_type;

typedef struct apollo_atm_aal5_clns_hdr_type {
    u16 channel_handle;
    u16 flags;
    u16 type;
    u16 data;
} apollo_atm_aal5_clns_hdr_type;

typedef struct apollo_atm_aal5_ilmi_hdr_type {
    u16 channel_handle;
    u16 flags;
    u8  data[0];
} apollo_atm_aal5_ilmi_hdr_type;

typedef struct apollo_atm_aal5_mux_hdr_type {
    u16 channel_handle;
    u16 flags;
    u8  data[0];
} apollo_atm_aal5_mux_hdr_type;

typedef struct apollo_atm_oam_f4_hdr_type {
    u16 channel_handle;
    u16 flags;
    /*
     * gcf_vpi_vci_pt_clp is a bitfield defined as follows:
     *
     * bits 31 - 28 = GCF
     * bits 27 - 20 = VPI
     * bits 19 -  4 = VCI
     * bits  3 -  1 = PT
     * bit        0 = CLP
     */
    u32 gcf_vpi_vci_pt_clp;
    u8  data[0];
} apollo_atm_oam_f4_hdr_type;

#define APOLLO_ATM_OAM_F4_HDR_PT_MASK     0xE
#define APOLLO_ATM_OAM_F4_HDR_PT_SHIFT    1

typedef struct apollo_atm_oam_f5_hdr_type {
    u16 channel_handle;
    u16 flags;
    u8  data[0];
} apollo_atm_oam_f5_hdr_type;

#define   APOLLO_IRONBUS_EXT_LESS_PROTO    0xFFFF0FFF
#define   APOLLO_CHANNEL_HANDLE_MASK       0xFFFF
#define   APOLLO_PKT_TYPE_MASK             0x0038
#define   APOLLO_PKT_TYPE_SHIFT            3
#define   APOLLO_FLAG_CLP_MASK             0x0001
#define   APOLLO_FLAG_CLP_BIT              0

#define   APOLLO_CHANNEL_HANDLE_RES_0      0x0000
/*
 * The 1 byte HEC field is removed by the line card.
 */
#define   APOLLO_F4_RX_CELL_SIZE           52
#define   APOLLO_F5_RX_CELL_SIZE           52

#define   APOLLO_ATM_PACKET_TYPE_AAL5      0
#define   APOLLO_ATM_PACKET_TYPE_F4        1
#define   APOLLO_ATM_PACKET_TYPE_F5_SEG    2
#define   APOLLO_ATM_PACKET_TYPE_F5_E_TO_E 3
#define   APOLLO_ATM_PACKET_TYPE_4         4
#define   APOLLO_ATM_PACKET_TYPE_5         5
#define   APOLLO_ATM_PACKET_TYPE_6         6
#define   APOLLO_ATM_PACKET_RESERVED       7 

#define   APOLLO_AAL5_MUX_IP_HDR_LEN       4
#define   APOLLO_AAL5_SNAP_HDR_LEN         12

#define   APOLLO_RCV_IRON_BUS_EXT_LEN      4
#define   APOLLO_TX_IRON_BUS_EXT_LEN       8

/*
 * MLPoA type definitions
 */
#define MLPOA_CISCO_HDR                    0xFF03
#define MLPOA_SNAP_HDR_LEN                 4
#define MLPOA_CISCO_HDR_LEN                2

/************************************************************/
/*         PTA PLUS ATM ENCAPSULATIONS                      */

/* RBE header 28 bytes*/
typedef struct apollo_atm_aal5_llcsnap_rbe_hdr_type {
    u16 channel_handle;
    u16 flags;
    u8  dsap;
    u8  ssap;
    u8  control;
    u8  oui[3];
    u16 pid;
    u16 pad;
    /* enet header within */
    u8  daddr[6];
    u8  saddr[6];
    u16 type;
    u8  data[0]; /* start of IP */
} apollo_atm_aal5_llcsnap_rbe_hdr_type;

/* PPPoEoA header 34 bytes*/
typedef struct apollo_atm_aal5_llcsnap_pppoe_hdr_type {
    u16 channel_handle;
    u16 flags;
    u8  dsap;
    u8  ssap;
    u8  control;
    u8  oui[3];
    u16 pid;
    u16 pad;
    /* enet header within */
    u8  daddr[6];
    u8  saddr[6];
    u16 type;
    /* pppoe hdr at begining of enet payload */
    u16 vtc;           /* version(4b), type(4b) and code(8b) fields */
    u16 sid;
    u16 len;
    u8  ppp_header[0]; /* PPP header start, no ff03 field present */
} apollo_atm_aal5_llcsnap_pppoe_hdr_type;


/* PPPoA MUX 4 bytes*/
typedef struct apollo_atm_aal5_mux_pppoa_hdr_type {
    u16 channel_handle;
    u16 flags;
    u8  ppp_header[0];
} apollo_atm_aal5_mux_pppoa_hdr_type;


/* PPPoA SNAP LLC 8 bytes */
typedef struct apollo_atm_aal5_llcsnap_pppoa_hdr_type {
    u16 channel_handle;
    u16 flags;
    u8  dsap;
    u8  ssap;
    u8  control;
    u8  nlpid;
    u8  ppp_header[0];
} apollo_atm_aal5_llcsnap_pppoa_hdr_type;

/* MLPoA MUX (generic) */
typedef struct apollo_atm_aal5_mux_mlpoa_hdr_type {
    u16 channel_handle;
    u16 flags;
    u8  ppp_header[0];
} apollo_atm_aal5_mux_mlpoa_hdr_type;

/* MLPoA SNAP LLC */
typedef struct apollo_atm_aal5_llcsnap_mlpoa_hdr_type {
    u16 channel_handle;
    u16 flags;
    u8  dsap;
    u8  ssap;
    u8  control;
    u8  nlpid;
    u8  ppp_header[0];
} apollo_atm_aal5_llcsnap_mlpoa_hdr_type;


#define PPPOA_SNAPLLC_HDR_LEN   sizeof(apollo_atm_aal5_llcsnap_pppoa_hdr_type)
#define PPPOA_MUX_HDR_LEN       sizeof(apollo_atm_aal5_mux_pppoa_hdr_type)
#define PPPOE_SNAPLLC_HDR_LEN   sizeof(apollo_atm_aal5_llcsnap_pppoe_hdr_type)
#define RBE_SNAPLLC_HDR_LEN     sizeof(apollo_atm_aal5_llcsnap_rbe_hdr_type)

/*    End PTA PLUS ATM ENCAPSULATIONS                           */
/****************************************************************/

#define   LLCSNAP_PID_DOT3_NOFCS           0x0007

/*
** the SNAP header
*/

/*
 * Note that some of these definitions are split
 * up along certain word or half word boundaries
 * to help expediate the TMC code.
 */
#define   LLC_SNAP_HDR_DSAP                0xAA
#define   LLC_SNAP_HDR_SSAP                0xAA
#define   LLC_SNAP_HDR_CONTROL             0x03
#define   LLC_SNAP_HDR_OUI_0               0x00
#define   LLC_SNAP_HDR_OUI_1               0x00
#define   LLC_SNAP_HDR_OUI_2               0x00
#define   LLC_SNAP_HDR_OUI_2_CDP           0x0C

#define   LLC_SNAP_HDR_DSAP_SSAP           0xAAAA
#define   LLC_SNAP_HDR_DSAP_SSAP_CTRL_OUI0 0xAAAA0300
#define   LLC_SNAP_HDR_CONTROL_OUI         0x03000000
#define   LLC_SNAP_HDR_OUI1_OUI2_CDP       0x000C2000



/*
** SRP
*/

/*
 * The v2_gen_hdr is a 2-byte field that contains the following:
 *
 *      [ ttl | ring_id | mode | priority | parity ]
 * bits    8       1        3        3         1
 */
typedef struct srp_hdr_type {
    u16 v2_gen_hdr;
    u8  dest_addr[6];
    u8  src_addr[6];
    u16 protocol;
    u8  data[0];
} srp_hdr_type;

#define   SRP_HDR_LEN                      16

#define   SRP_IB_CHANNEL_CONTROL           0x0000
#define   SRP_IB_CHANNEL_DATA_HI           0x0001
#define   SRP_IB_CHANNEL_DATA_LO           0x0002

#define   SRP_RING_ID_MASK                 0x0080
#define   SRP_RING_ID_BIT                  7

#define   SRP_MODE_BITS_MASK               0x0070
#define   SRP_MODE_BITS_SHIFT              4
#define   SRP_MODE_CONTROL_TOPOLOGY        4
#define   SRP_MODE_CONTROL_IPS             5
#define   SRP_MODE_DATA                    7

#define   SRP_PRIORITY_BITS_MASK           0x000E 
#define   SRP_PRIORITY_BITS_SHIFT          1
#define   SRP_PRIORITY_HIGH                7
#define   SRP_PRIORITY_PAK_PRIORITY        6

/* this is for the tmc code */
#define   SRP_INV_PRIORITY_BITS_MASK       0xFFF1

#define   SRP_PROT_CONTROL_TOPOLOGY        0x2007
#define   SRP_PROT_CONTROL_IPS             0x2007

/* this is for the tmc code */
#define   SRP_TRUE                         1
#define   SRP_FALSE                        0

/*
** MPLS
*/
#define   MPLS_EOS_BIT                     0x00000100
#define   MPLS_EOS_SHIFT                   8
#define   MPLS_LABEL_SIZE                  4
#define   MAX_MPLS_LABEL_STACK             6
#define   MPLS_LABEL_MASK                  0xfffff000
#define   MPLS_LABEL_SHIFT                 12
#define   MPLS_TTL_MASK                    0x000000ff
#define   MPLS_EXP_MASK                    0x00000e00
#define   MPLS_EXP_SHIFT                   9
#define   MPLS_EXP_TTL_MASK                0x00000eff



typedef union _layer2 {
    hdlc_hdr_type                           hdlc;
    ppp_comp_hdr_type                       ppp;
    ethernet_arpa_hdr_type                  eth_arpa;
    ethernet_vlan_hdr_type                  eth_vlan;
    ethernet_qinq_hdr_type                  eth_qinq;
    ethernet_lacp_hdr_type                  eth_lacp;
    ethernet_bpdu_hdr_type                  eth_bpdu;
    ethernet_802p3_hdr_type                 eth_802p3;
    ethernet_vlan_802p3_hdr_type            eth_vlan_802p3;
    ethernet_pppoe_arpa_hdr_type            eth_pppoe_arpa; /* PTA plus */
    ethernet_pppoe_vlan_hdr_type            eth_pppoe_vlan; /* PTA plus */
    ethernet_pppoe_qinq_hdr_type            eth_pppoe_qinq; /* PTA plus */
    frame_relay_hdr_type                    frame_relay;
    fr_snap_hdr_type                        fr_snap;
    mlfr_hdr_type                           mlfr;
    mlpofr_hdr_type                         mlpofr;
    frf12_hdr_type                          frf12;
    apollo_atm_generic_hdr_type             atm_generic;
    apollo_atm_aal5_snap_hdr_type           atm_aal5_snap;
    apollo_atm_aal5_snap_hdr1_type          atm_aal5_snap1;
    apollo_atm_aal5_clns_hdr_type           atm_aal5_clns;
    apollo_atm_aal5_ilmi_hdr_type           atm_aal5_ilmi;
    apollo_atm_aal5_mux_hdr_type            atm_aal5_mux;
    apollo_atm_oam_f4_hdr_type              atm_oam_f4;
    apollo_atm_oam_f5_hdr_type              atm_oam_f5;
    apollo_atm_aal5_llcsnap_rbe_hdr_type    atm_aal5_rbe_snapllc;   /* PTA plus */
    apollo_atm_aal5_llcsnap_pppoe_hdr_type  atm_aal5_pppoe_snapllc; /* PTA plus */
    apollo_atm_aal5_mux_pppoa_hdr_type      atm_aal5_pppoa_mux;     /* PTA plus */
    apollo_atm_aal5_llcsnap_pppoa_hdr_type  atm_aal5_pppoa_snapllc; /* PTA plus */
    apollo_atm_aal5_mux_mlpoa_hdr_type      mlpoa_generic;
    apollo_atm_aal5_llcsnap_mlpoa_hdr_type  mlpoa_snapllc;
    srp_hdr_type                            srp;
} layer2_t;

/*
 * Define the Common OAM cell format - F4 & F5 cells
 *  For F4 cells:
 *      VPI == User VPI
 *      VCI == (3 == Segment), (4 == End-to-End)
 *
 *  For F5 cells:
 *      VPI == User VPI
 *      VCI == User VCI
 *      PT == (100 == Segment, 101 == End-to-End)
 * 
 *      OAM Cell Type & Function Type:
 *
 *      OAM_TYPE = (0001 == Fault management)
 *      OAM_FUNC == (0000 == AIS, 0001 == RDI, 0100 == CC,
 *                           1000 == loopback)
 *
 *      OAM_TYPE = (0010 == Performance management)
 *      OAM_FUNC == (0000 == Forward Monitoring(FM), 
 *                           0001 == Backward monitoring(BR), 
 *                           0010 == Monitoring & reporting (FM+BR))
 *
 *              OAM_TYPE = (1000 == Activation/Deactivation)
 *      OAM_FUNC == (0000 == Performance Monitoring, 
 *                           0001 == Continuity Check)
 *            
 *              OAM_TYPE = (1111 == Sytem Management)
 *      OAM_FUNC == (0001 == Security - non-real-time, 
 *                           0010 == Security - real-time)
 *
 */
#define ATM_OAM_FAULT_MGMT  0x1 /* OAM Fault mgmt. code */
#define ATM_OAM_PRFRM_MGMT      0x2     /* performance mgmt code */
#define ATM_OAM_ACT_DEACT       0x8     /* OAM Activation/Deactivation
                                           code */
#define ATM_OAM_SYSTEM_MGMT     0xF     /* System Management code */

#define ATM_OAM_AIS_FUNC    0x0 /* AIS function type */
#define ATM_OAM_RDI_FUNC    0x1 /* RDI function type */
#define ATM_OAM_CC_FUNC     0x4 /* OAM CC FM function code */
#define ATM_OAM_LOOP_FUNC   0x8 /* Loopback function type */

#define ATM_OAM_F5_SEGMENT  0x4     /* Segment function */
#define ATM_OAM_F5_ENDTOEND 0x5     /* End-to-End function */
#define ATM_OAM_F4_SEGMENT  0x3     /* Segment function */
#define ATM_OAM_F4_ENDTOEND 0x4     /* End-to-End function */
#define ATM_OAM_F4_PTI_ZERO     0x0             /* PTI=0 for F4 OAM */

typedef struct  atm_oam_hdr_t_ {
    unsigned    oam_gfc:4;          /* GFC */
    unsigned    oam_vpi:8;          /* VPI */
    unsigned    oam_vci_ms:4;         /* VCI (Most Significant Bits) */

    unsigned    oam_vci_ls:12;        /* VCI (Least Significant Bits) */
    unsigned    oam_pt:3;           /* Payload Type */
    unsigned    oam_clp:1;          /* Cell Loss Priority */
    u8  data[0];
} atm_oam_hdr_t;

typedef struct  atm_oam_type_func_t_ {
    u8  oam_type:4;
    u8  oam_func:4;
    u8  data[0];
} atm_oam_type_func_t;

/*
** IP Version 4 header
*/

/*
 * version_hdr_len_words [7-4]   IP Header Version
 *                       [3-0]   IP Header Length in 32-bit words
 * tos                   Type of Service
 * total_len_bytes       Total IP datagram length in bytes
 *                       (including IP header)
 * identification        Unique fragmentation identifier
 * frag_flags_offset     [15-13] Fragmentation flags
 *                       [12-0]  Fragmentation Offset
 * ttl                   Time To Live
 * protocol_id           Protocol Identifier
 * checksum              16-bit 1's complement IP Header checksum
 * src_addr              IP Source Address
 * dest_addr             IP Destination Address
 */
typedef struct ipv4_header {
    u8  version_hdr_len_words;
    u8  tos;
    u16 total_len_bytes;
    u16 identification;
    u16 frag_flags_offset;
    u8  ttl;
    u8  protocol;
    u16 checksum;
    u32 src_addr;
    u32 dest_addr;
    u8  data[0];
} ipv4_header;

/*OPTIONS PACKET TYPE 
 * +-+-+-+-+-+-+-+-+
 * |C| CL|    OP   |
 * +-+-+-+-+-+-+-+-+
 */
typedef struct ipv4_options {
    u8 copy     :1 ;
    u8 op_class :2 ;
    u8 option   :5 ;
    u8 pad ;
}ipv4_options;

#define LOOSE_SOURCE_ROUTE  131
#define STRICT_SOURCE_ROUTE 137
#define IPV4_NO_OPTIONS_HDR_LEN (sizeof(ipv4_header))
#define IPV4_VERSION 4
#define IPV4_HEADER_LENGTH_WORDS 5
#define IPV4_VERSION_HDR_LEN_FIELD  ((u8) 0x45)
#define IPV4_HEADER_LENGTH_WORDS 5
#define IPV4_MIN_HEADER_LENGTH_BYTES 20
#define IP_HDR_LEN sizeof(ipv4_header)
#define IPV4_VERSION_VALUE_SHIFT 4

#define IPV4_FRAG_OFFSET_MASK (0x1fff)
#define IPV4_FRAG_MF_MASK     (0x2000)
#define IPV4_FRAG_MF_SHIFT    (13)

/* 0.0.0.0 */
#define IP_BOOTP_SOURCE_ADDRESS 0
/* 255.255.255.255 */
#define IP_LIMITED_BROADCAST_ADDRESS 0xFFFFFFFF

/*
 * IPv4 header - version & length fields
 */
#define IP_VER_LEN          0x45
#define IP_VER              0x4
#define IP_MIN_LEN          0x5
#define IP_VER_MASK         0xf0
#define IP_LEN_MASK         0x0f

/*
 * IPv4 header - TOS field
 */
#define PS_IP_TOS_MASK      0xff
#define IP_PRECEDENCE_SHIFT 5     /* shift value up to precedence bits */
#define IP_DSCP_SHIFT       2     /* shift value up to dscp bits */

#define IP_TOS_PRECEDENCE       0xe0    /* mask of precedence in tos byte */
#define IP_TOS_NO_PRECEDENCE    0x1f
#define IP_TOS_LOW_DELAY        8       /* values must be shifted 1 bit */
#define IP_TOS_HIGH_TPUT        4       /* before using */
#define IP_TOS_HIGH_RELY        2
#define IP_TOS_LOW_COST         1
#define IP_TOS_NORMAL           0
#define IP_TOS_MASK             0x1e    /* mask of tos in tos byte */
#define IP_TOS_MBZ_MASK         0x01    /* mask for MZB bit in tos byte */
#define IP_TOS_DSCP             0xfc    /* mask for dscp in tos byte */
#define IP_TOS_NO_DSCP          0x03

#define IP_TOS_METRIC_TYPES     8
#define IP_TOS_SHIFT            1

#define IP_TOS_PRECEDENCE_MASK  (IP_TOS_PRECEDENCE | IP_TOS_MASK)

/*
 * IP TOS Precedence values (High order 3 bits)
 */
#define TOS_PREC_NET_CONTROL    0xe0
#define TOS_PREC_INET_CONTROL   0xc0
#define TOS_PREC_CRIT_ECP       0xa0
#define TOS_PREC_FLASH_OVER     0x80
#define TOS_PREC_FLASH          0x60
#define TOS_PREC_IMMEDIATE      0x40
#define TOS_PREC_PRIORITY       0x20
#define TOS_PREC_ROUTINE        0x00
#define TOS_PREC_ILLEGAL        0xff    /* invalid precedence value */

#define TOS_PREC_NET_CONTROL_NUM   7
#define TOS_PREC_INET_CONTROL_NUM  6
#define TOS_PREC_CRIT_ECP_NUM      5
#define TOS_PREC_FLASH_OVER_NUM    4
#define TOS_PREC_FLASH_NUM         3
#define TOS_PREC_IMMEDIATE_NUM     2
#define TOS_PREC_PRIORITY_NUM      1
#define TOS_PREC_ROUTINE_NUM       0



/*
 * IPv4 header - flags and fragment offset fields
 */
#define IP_FRAG_OFFSET_MASK 0x1fff


#define IP_FRAG_MORE_MASK   0x2000
#define IP_FRAG_DF_MASK     0x4000
#define IP_FRAG_UNDEF_MASK  0x8000
#define IP_FRAG_NO_DF_SET   0x0000

/* bit definitions for fragment flags */
#define IP_FRAG_MORE_BIT       13
#define IP_FRAG_DF_BIT         14
#define IP_FRAG_UNDEF_BIT      15

/*
 * IPv4 header - TTL field
 */
#define TTL_DEFAULT     255
#define TTL_1           1
#define TTL_2           2
#define TTL_255         255


/*
 * IPv4 header - protocol field
 *
 * ICMP_PROT      1    ICMP
 * IGMP_PROT      2    group management
 * GGP_PROT       3    GGP
 * IPINIP_PROT    4    IPv4 in IPv4 encapsulation
 * TCP_PROT       6    TCP
 * EGP_PROT       8    EGP
 * IGRP_PROT      9    IGRP
 * UDP_PROT       17   UDP
 * HMP_PROT       20   HMP
 * RDP_PROT       27   RDP
 * IPV6_INIP_PROT 41   IPV6 in IPv4 encapsulation
 * RSVP_PROT      46   RSVP
 * GRE_PROT       47   GRE
 * ESP_PROT       50   ESP
 * AHP_PROT       51   AHP
 * SDNS0_PROT     53   SNDS
 * NHRP_PROT      54   NHRP
 * SDNS1_PROT     55   SDNS1
 * HELLO_PROT     63   HELLO
 * ND_PROT        77   ND
 * EONIP_PROT     80   CLNS over IP
 * VINES_PROT     83   Banyan Vines
 * NEWIGRP_PROT   88   IGRP
 * OSPF_PROT      89   OSPF
 * FST_RSRB_PROT  90   RSRB
 * FST_DLSW_PROT  91   DLSW
 * NOSIP_PROT     94   KA9Q/NOS compatible IP over IP
 * PIM_PROT       103  PIMv2
 * PCP_PROT       108  PCP
 * PGM_PROT       113  PGM
 * MAX_PROT       113  maximum protocol number in the above list,
 *                      used in creating case registry
 */
#define ICMP_PROT       1
#define IGMP_PROT       2
#define GGP_PROT        3
#define IPINIP_PROT     4
#define TCP_PROT        6
#define EGP_PROT        8
#define IGRP_PROT       9
#define UDP_PROT        17
#define HMP_PROT        20
#define RDP_PROT        27
#define IPV6_INIP_PROT  41
#define RSVP_PROT       46
#define GRE_PROT        47
#define ESP_PROT        50
#define AHP_PROT        51
#define SDNS0_PROT      53
#define NHRP_PROT       54
#define SDNS1_PROT      55
#define HELLO_PROT      63
#define ND_PROT         77
#define EONIP_PROT      80
#define VINES_PROT      83
#define NEWIGRP_PROT    88
#define OSPF_PROT       89
#define FST_RSRB_PROT   90
#define FST_DLSW_PROT   91
#define NOSIP_PROT      94
#define PIM_PROT        103
#define PCP_PROT        108
#define PGM_PROT        113
#define MAX_PROT        113

/*Well Known Application ports */
#define FTP_PORT        21  /* For control connection */
/*
 * TCP header
 */
typedef struct tcp_hdr_type {
    u16 src_port;
    u16 dest_port;
    u32 seq_num;
    u32 ack_num;
    u8  hdr_len;
    u8  flags;
    u16 window_size;
    u16 tcp_checksum;
    u16 urgent_pointer;
    u8  option_data[0];
} tcp_hdr_type;

#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PUSH   0x08
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_URG    0x20
#define TCP_FLAG_ECE    0x40
#define TCP_FLAG_CWR    0x80

/*
 * TCP Option
 */
typedef struct tcp_option_s {
    u8  kind;
    u8  length;
    u8  data[0];
} tcp_option_t;

#define TCP_END_OPTIONS_LIST       0
#define TCP_OPTION_NOP             1
#define TCP_OPTION_MSS             2
#define TCP_OPTION_WINDOW_SCALE    3
#define TCP_OPTION_SACK_PERMITTED  4
#define TCP_OPTION_SACK_DATA       5
#define TCP_OPTION_ECHO            6
#define TCP_OPTION_ECHO_REPLY      7
#define TCP_OPTION_TSOPT           8
/*
  9   2   Partial Order Connection Permitted. RFC 1693
  10  3   Partial Order Service Profile.  RFC 1693
  11  6   CC, Connection Count.   RFC 1644
  12  6   CC.NEW  RFC 1644
  13  6   CC.ECHO RFC 1644
  14  3   TCP Alternate Checksum Request. RFC 1146
  15  Variable.   TCP Alternate Checksum Data.    RFC 1146
  16      Skeeter.     
  17      Bubba.   
  18  3   Trailer Checksum Option.     
*/
#define TCP_OPTION_MD5_SIGNATURE   19
/*
  20      SCPS Capabilities.   
  21      Selective Negative Acknowledgements.     
  22      Record Boundaries.   
  23      Corruption experienced.  
  24      SNAP.    
  25           
  26      TCP Compression Filter.  
*/
#define TCP_OPTION_QUICK_START     27

#define TCP_OPTION_NUM_MAX         27

#ifdef TARGET_CISCO
#define tcp_printf(format_str, params...) //printf(format_str, ## params)
#else
#define tcp_printf(format_str, params...) printf(format_str, ## params)
#endif

typedef struct udp_hdr_type {
  u16 src_port;
  u16 dest_port;
  u16 udp_length;
  u16 udp_checksum;
} udp_hdr_type_t;

#define TYPE_IPV6 0x86dd
#define TYPE_IPV4 0x0800

/*
 * version_trafficclass_flowlabel [31:28] IP Header Version, 
                                  [27:20] traffic_class, 
                                  [19:0]  flow_label[20]
 * payload_length                 Length of packet in bytes excluding header size(s) 
 * next_header                    Identifies the type of header following the IPv6 header  
 * hop_limit                      Decremented by 1 by each forwarding node, packet discarded when zero
 * src_addr                       IPv6 Source Address
 * dst_addr                       IPv6 Destination Address
 */
typedef struct ipv6_header {
  u32 version_trafficclass_flowlabel;
  u16 payload_length;
  u8  next_header;
  u8  hop_limit;
  u32 src_addr[4];
  u32 dst_addr[4];
  u8  data[0];  
} ipv6_header_t;

#define IPV6_HDR_LEN 40 
#define IPV6_HDR_LEN_WORDS 10
#define IPV6_FLABLE_MASK 0x000FFFFF
#define IPV6_MIN_PATH_MTU (1280)

#define IPV6_GET_IP_VER(ih) ((clib_net_to_host_u32((ih) \
                      ->version_trafficclass_flowlabel) >> 28) & 0xf)
#define IPV6_GET_TOS(ih) ((clib_net_to_host_u32((ih) \
                      ->version_trafficclass_flowlabel) >> 20) & 0xff)
#define IPV6_GET_FLOW_LABEL(ih) ((clib_net_to_host_u32((ih) \
                      ->version_trafficclass_flowlabel)) & 0xfffff)

#define IPV6_VERSION_VALUE                    (6)
#define IPV6_VERSION_VALUE_SHIFT              (28)
#define IPV6_TRAFFIC_CLASS_VALUE_SHIFT        (20)
#define IPV6_TRAFFIC_CLASS_VALUE_MASK         (0xff)

#define IPV6_PROTO_HOPOPTS      0
#define IPV6_PROTO_TCP          6       
#define IPV6_PROTO_UDP          17
#define IPV6_PROTO_IPV6         41       
#define IPV6_PROTO_ROUTING      43  
#define IPV6_PROTO_FRAGMENT     44 
#define IPV6_PROTO_DESTOPTS     60 
#define IPV6_PROTO_ESP          50   
#define IPV6_PROTO_AH           51
#define IPV6_PROTO_ICMPV6       58
#define IPV6_PROTO_NONE         59 

/* standard v6 extension header are 2 tytes
 * one byte next header
 * one byte header length
 */

typedef struct ipv6_frag_header {
    u8 next_header;
    u8 reserved;
    u16 frag_offset_res_m;
    u32 identification;
} ipv6_frag_header_t;

#define IPV6_FRAG_HDR_LEN (sizeof(ipv6_frag_header_t))

#define IPV6_FRAG_OFFSET_MASK     (0xFFF8)
#define IPV6_FRAG_OFFSET_SHIFT    (3)
#define IPV6_FRAG_MORE_FRAG_MASK  (0x0001)

#define IPV6_TOS_SHIFT       20
#define IPV6_TOS_SHIFT_HLF_WD 4
#define IPV6_NEXT_HDR_SHIFT  8

typedef struct ipv6_routing_header {
    u8 next_header;
    u8 hdr_ext_len;
    u8 routing_type;
    u8 segments_left;
    u8 data[0];
} ipv6_routing_header_t;
#define IPV6_ROUTING_HDR_LEN (sizeof(ipv6_routing_header_t))

typedef struct ipv6_hop_header {
    u8 next_header;
    u8 hdr_ext_len;
    u8 options[0];
} ipv6_hop_header_t;
#define IPV6_HOP_LEN (sizeof(ipv6_hop_header_t))

typedef struct ipv6_dest_opt_header {
    u8 next_header;
    u8 hdr_ext_len;
    u8 options[0];
} ipv6_dest_opt_header_t;
#define IPV6_DESTOPT_LEN (sizeof(ipv6_dest_opt_header_t))


/* Definition of ICMP header */
typedef struct icmp_v4_s {
    u8 type;
    u8 code;
    u16 checksum;
    u16 identifier;
    u16 sequence;
} icmp_v4_t;

#define ICMPV4_HDR_SIZE  (sizeof(icmp_v4_t))
#define ICMPV4_ECHOREPLY 0                /* Type: echo reply */
#define ICMPV4_ECHO      8                /* Type: echo request */

#define ICMPV4_UNREACHABLE 3              /* Type: destination unreachable */
#define ICMPV4_UNRNET 0                   /* Code: Net unreachable  */
#define ICMPV4_UNRHOST 1                  /* Code: host unreachable */
#define ICMPV4_UNRPROT 2                  /* Code: protocol unreachable */
#define ICMPV4_UNRPORT 3                  /* Code: port unreachable */
#define ICMPV4_UNRFRAG 4                  /* Code: frag req DF set  */
#define ICMPV4_UNRADMIN 13                /* Code: administratively prohib. */
#define ICMPV4_SOURCEROUTE_FAILED 5       /* Code: administratively prohib. */

#define ICMPV4_SRC_ROUTE_FAIL 5           /* Code: Source Route Failed */
#define ICMPV4_NO_ROUTE_DESTN_8 8         /* Code: No Route to Destn */
#define ICMPV4_NO_ROUTE_DESTN_11 11       /* Code: No Route to Destn */
#define ICMPV4_NO_ROUTE_DESTN_12 12       /* Code: No Route to Destn */

#define ICMPV4_ADMIN_PROH_9 9             /* Code: Administratively Prohibited */
#define ICMPV4_ADMIN_PROH_10 10             /* Code: Administratively Prohibited */
#define ICMPV4_PREC_CUTOFF 15             /* Code: Precedence Cutoff  */


#define ICMPV4_TIMEEXCEEDED 11            /* Type: time exceeded */
#define ICMPV4_TIMTTL 0                   /* Code: ttl in transit code */

#define ICMPV4_PARAMETER_PROBLEM    12    /* Type: Parameter Problem */
#define ICMPV4_PARAM_ERROR  0             /* Code: Pointer to Error  */
#define ICMPV4_MISSING_OPTION_CODE  1     /* Code: Mission option */
#define ICMPV4_PARAM_BAD_LEN  2           /* Code:  Bad Length */

#define ICMPV4_CONVERSION_ERROR     31
#define ICMPV4_SOURCE_QUENCH        4
#define ICMPV4_REDIRECT             5
#define ICMPV4_TIMESTAMP            13
#define ICMPV4_TIMESTAMP_REPLY      14
#define ICMPV4_INFO_REQUEST         15
#define ICMPV4_INFO_REPLY           16
#define ICMPV4_ADDR_MASK_REQUEST    17
#define ICMPV4_ADDR_MASK_REPLY      18

typedef struct icmp_v6_s {

    u8 type;
    u8 code;
    u16 checksum;

    u32 data[0];
} icmp_v6_t;

typedef struct pseudo_v6_header {
    u32 src_addr[4];
    u32 dst_addr[4];
    u16 payload_length;
    u16 next_header;
} pseudo_v6_header_t;


#define ICMPV6_ECHO                 128
#define ICMPV6_ECHO_REPLY           129
#define ICMPV6_PKT_TOO_BIG          2
#define ICMPV6_TIMEEXCEEDED         3
#define ICMPV6_TIMTTL               0
#define ICMPV6_PARAMETER_PROBLEM    4
#define ICMPV6_UNREACHABLE          1
#define ICMPV6_NEIGHBOR_SOLICITAION 135
#define ICMPV6_NEIGHBOR_ADVT        136
/* ICMP V6 generated packet size */
#define ICMPV6_ERR_SIZE          48 
#define ICMPV6_HDR_SIZE          (sizeof(icmp_v6_t) +sizeof(u32))

/* Code for Type 1 */
#define ICMPV6_UNRDESTN      0  /* Code: No route to Desnt */
#define ICMPV6_ADM_PROH      1  /* Code: Adminitrative Prohibited */
#define ICMPV6_SRC_ADD_SCOPE 2  /* Code: Source Address beyond scope */
#define ICMPV6_UNRHOST       3  /* Code: Host Unreachable */
#define ICMPV6_UNRPORT       4  /* Code: Port UnReachable */

#define ICMPV6_UNRPROT       1  /* type 4 - Code: No route to Desnt */

#define ICMPV6_PTB_CODE      0  /* Code: For PTB */
#define ICMPV6_PARAM_CODE    0  /* Code: For Parameter Problem */
#define ICMPV6_UNREC_HDR     1  /* Code: For Parameter Problem */
#define ICMPV6_SRC_ADD_FAIL  5  /* Code: For Source address failed */
#define ICMP_ECHO_REPLY_CODE 0
#define DEFAULT_TTL_HOPLIMIT_VAL 64

typedef struct pptp_hdr_type {

  u16 flags_ver;
  u16 proto_type;  /* PPP = 0x880B */
  u16 payload_len;
  u16 call_id;
  u32 seq_no;
  u32 ack_no;

} pptp_hdr_type_t;

/*
 * NAME
 *
 *   tcp_findoption
 *
 * SYNOPSIS
 *   u8* tcp_findoption (tcp_hdr_t *tcp, uchar option)
 *
 * PARAMETERS
 *   tcp       - pointer to TCP header
 *   option    - TCP option
 *
 * RETURNS
 *   This function returns a pointer to the option found,
 *   otherwise returns null.
 *
 *
 * DESCRIPTION
 *   This function searches the option and returns a pointer to the
 *   matched option field containing option kind/length/data sub-fields.
 *
 */
static inline u8* tcp_findoption (tcp_hdr_type *tcp, u8 option)
{
    u8*data;
    u8 len, optlen;

    data = tcp->option_data;
    len = ((tcp->hdr_len>>4) << 2) - sizeof(tcp_hdr_type);

#define         MAXTCPOPTIONBYTES   40
#define         MINTCPOPTIONLENGTH   2

    while (len) {
        if (PREDICT_TRUE(option == data[0])) {
            return (data);
        } else {
            switch (data[0]) {
            case TCP_END_OPTIONS_LIST:
                return (NULL);
            case TCP_OPTION_NOP:
                len -= 1;
                data += 1;
                break;
            default:
                /* Sanity check the length. */
                optlen = data[1];
                if ((optlen < MINTCPOPTIONLENGTH) ||
                    (optlen > MAXTCPOPTIONBYTES)  ||
                    (optlen > len)) {
                    return (NULL);
                }
                len -= optlen;
                data += optlen;
                break;
            }
        }
    }

    return (NULL);
}


static inline u32 crc_calc (ipv4_header *ipv4)
{
    u16 *ipv4_word_ptr = (u16 *) ipv4;
    u32 crc32;
    /*
     * Add all fields except the checksum field
     */
    crc32 = (u32)clib_net_to_host_u16(*ipv4_word_ptr)     +
            (u32)clib_net_to_host_u16(*(ipv4_word_ptr + 1)) +
            (u32)clib_net_to_host_u16(*(ipv4_word_ptr + 2)) +
            (u32)clib_net_to_host_u16(*(ipv4_word_ptr + 3)) +
            (u32)clib_net_to_host_u16(*(ipv4_word_ptr + 4)) +
            (u32)clib_net_to_host_u16(*(ipv4_word_ptr + 6)) +
            (u32)clib_net_to_host_u16(*(ipv4_word_ptr + 7)) +
            (u32)clib_net_to_host_u16(*(ipv4_word_ptr + 8)) +
            (u32)clib_net_to_host_u16(*(ipv4_word_ptr + 9));

    /* Add in the carry of the original sum */
    crc32 = (crc32 & 0xFFFF) + (crc32 >> 16);
    /* Add in the carry of the final sum */
    crc32 = (crc32 & 0xFFFF) + (crc32 >> 16);

    return crc32;
}

#endif /* __TCP_HEADER_DEFINITIONS_H__ */
