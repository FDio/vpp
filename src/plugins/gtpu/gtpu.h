/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef included_vnet_gtpu_h
#define included_vnet_gtpu_h

#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/vtep.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/udp/udp_local.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#include <vnet/fib/fib_table.h>

/**
 *		Bits
 * Octets	8	7	6	5	4	3	2	1
 * 1		          Version	PT	(*)	E	S	PN
 * 2		Message Type
 * 3		Length (1st Octet)
 * 4		Length (2nd Octet)
 * 5		Tunnel Endpoint Identifier (1st Octet)
 * 6		Tunnel Endpoint Identifier (2nd Octet)
 * 7		Tunnel Endpoint Identifier (3rd Octet)
 * 8		Tunnel Endpoint Identifier (4th Octet)
 * 9		Sequence Number (1st Octet)1) 4)
 * 10		Sequence Number (2nd Octet)1) 4)
 * 11		N-PDU Number2) 4)
 * 12		Next Extension Header Type3) 4)
**/

typedef CLIB_PACKED (struct {
  u8 ver_flags;
  u8 type;
  u16 length;			/* length in octets of the data following the fixed part of the header */
  u32 teid;
  /* The following fields exists if and only if one or more of E, S or PN
   * are 1. */
  u16 sequence;
  u8 pdu_number;
  u8 next_ext_type;
}) gtpu_header_t;

typedef CLIB_PACKED (struct {
  u8 type;
  u8 len;
  u16 pad;
}) gtpu_ext_header_t;

/**
 * DL PDU SESSION INFORMATION (PDU Type 0):
 * (3GPP TS 38.415)
 *		Bits
 * Octets	8	7	6	5	4	3	2	1
 * 1		                     type     qmp     snp	    spare
 * 2	     ppp      rqi					   qos_fi
 *
 * UL PDU SESSION INFORMATION (PDU Type 1):
 *		Bits
 * Octets	8	7	6	5	4	3	2	1
 * 1		                     type     qmp   DL d.   UL d.     snp
 * 2  n3/n9 delay  new IE					   qos_fi
 **/
typedef CLIB_PACKED (struct {
  u8 oct0;
  u8 oct1;
  // Extensions are supported
}) pdu_session_container_t;

STATIC_ASSERT_SIZEOF (pdu_session_container_t, 2);
typedef CLIB_PACKED (struct {
  u8 len;
  pdu_session_container_t pdu;
  u8 next_header;
}) gtpu_ext_with_pdu_session_header_t;

#define GTPU_V1_HDR_LEN 8

#define GTPU_VER_MASK (7<<5)
#define GTPU_PT_BIT   (1<<4)
#define GTPU_RES_BIT	 (1 << 3)
#define GTPU_E_BIT    (1<<2)
#define GTPU_S_BIT    (1<<1)
#define GTPU_PN_BIT   (1<<0)
#define GTPU_E_S_PN_BIT  (7<<0)

#define GTPU_V1_VER   (1<<5)

#define GTPU_PT_GTP    (1<<4)
#define GTPU_TYPE_GTPU  255

#define GTPU_EXT_HDR_PDU_SESSION_CONTAINER 133
#define GTPU_NO_MORE_EXT_HDR		   0
#define GTPU_PDU_DL_SESSION_TYPE	   0
#define GTPU_PDU_UL_SESSION_TYPE	   (1 << 4)

#define GTPU_FORWARD_BAD_HEADER	  (1 << 0)
#define GTPU_FORWARD_UNKNOWN_TEID (1 << 1)
#define GTPU_FORWARD_UNKNOWN_TYPE (1 << 2)

/* the ipv4 addresses used for the forwarding tunnels. 127.0.0.127 - .129. */
#define GTPU_FORWARD_BAD_HEADER_ADDRESS_IPV4   0x7f00007fu
#define GTPU_FORWARD_UNKNOWN_TEID_ADDRESS_IPV4 0x8000007fu
#define GTPU_FORWARD_UNKNOWN_TYPE_ADDRESS_IPV4 0x8100007fu

/* the ipv6 addresses used for the forwarding tunnels.
 * 2001:db8:ffff:ffff:ffff:ffff:ffff:fffd -
 * 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff*/
#define GTPU_FORWARD_BAD_HEADER_ADDRESS_IPV6                                  \
  {                                                                           \
    .as_u64[0] = 0xffffffffb80d0120ull, .as_u64[1] = 0xfdffffffffffffffull    \
  }
#define GTPU_FORWARD_UNKNOWN_TEID_ADDRESS_IPV6                                \
  {                                                                           \
    .as_u64[0] = 0xffffffffb80d0120ull, .as_u64[1] = 0xfeffffffffffffffull    \
  }
#define GTPU_FORWARD_UNKNOWN_TYPE_ADDRESS_IPV6                                \
  {                                                                           \
    .as_u64[0] = 0xffffffffb80d0120ull, .as_u64[1] = 0xffffffffffffffffull    \
  }
/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip4_header_t ip4;            /* 20 bytes */
  udp_header_t udp;            /* 8 bytes */
  gtpu_header_t gtpu;	       /* 12 bytes */
  gtpu_ext_with_pdu_session_header_t gtpu_ext; /* 4 bytes */
}) ip4_gtpu_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip6_header_t ip6;            /* 40 bytes */
  udp_header_t udp;            /* 8 bytes */
  gtpu_header_t gtpu;	       /* 12 bytes */
  gtpu_ext_with_pdu_session_header_t gtpu_ext; /* 4 bytes */
}) ip6_gtpu_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: ip src and gtpu teid on incoming gtpu packet
   * all fields in NET byte order
   */
  union {
    struct {
      u32 src;
      u32 teid;
    };
    u64 as_u64;
  };
}) gtpu4_tunnel_key_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: ip src and gtpu teid on incoming gtpu packet
   * all fields in NET byte order
   */
  ip6_address_t src;
  u32 teid;
}) gtpu6_tunnel_key_t;
/* *INDENT-ON* */

typedef struct
{
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Rewrite string */
  u8 *rewrite;

  /* FIB DPO for IP forwarding of gtpu encap packet */
  dpo_id_t next_dpo;

  /* gtpu local(rx) and remote(tx) TEIDs in HOST byte order */
  u32 teid;
  u32 tteid;

  /* tunnel src and dst addresses */
  ip46_address_t src;
  ip46_address_t dst;

  /* mcast packet output intf index (used only if dst is mcast) */
  u32 mcast_sw_if_index;

  /* decap next index */
  u32 decap_next_index;

  /* The FIB index for src/dst addresses */
  u32 encap_fib_index;

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  /* PDU session container extension enable/disable */
  u8 pdu_extension;
  u8 qfi;

  /* The tunnel is used for forwarding */
  u8 is_forwarding;
  u8 forwarding_type;

  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

  /*
   * The FIB entry for (depending on gtpu tunnel is unicast or mcast)
   * sending unicast gtpu encap packets or receiving mcast gtpu packets
   */
  fib_node_index_t fib_entry_index;
  adj_index_t mcast_adj_index;

  /**
   * The tunnel is a child of the FIB entry for its destination. This is
   * so it receives updates when the forwarding information for that entry
   * changes.
   * The tunnels sibling index on the FIB entry's dependency list.
   */
  u32 sibling_index;

  u32 flow_index;		/* infra flow index */
} gtpu_tunnel_t;

#define foreach_gtpu_input_next        \
_(DROP, "error-drop")                  \
_(L2_INPUT, "l2-input")                \
_(IP4_INPUT,  "ip4-input")             \
_(IP6_INPUT, "ip6-input" )

typedef enum
{
#define _(s,n) GTPU_INPUT_NEXT_##s,
  foreach_gtpu_input_next
#undef _
    GTPU_INPUT_N_NEXT,
} gtpu_input_next_t;

typedef enum
{
#define gtpu_error(n,s) GTPU_ERROR_##n,
#include <gtpu/gtpu_error.def>
#undef gtpu_error
  GTPU_N_ERROR,
} gtpu_input_error_t;

typedef struct
{
  /* vector of encap tunnel instances */
  gtpu_tunnel_t *tunnels;

  /* lookup tunnel by key */
  uword *gtpu4_tunnel_by_key;	/* keyed on ipv4.dst + teid */
  uword *gtpu6_tunnel_by_key;	/* keyed on ipv6.dst + teid */

  /* local VTEP IPs ref count used by gtpu-bypass node to check if
     received gtpu packet DIP matches any local VTEP address */
  vtep_table_t vtep_table;

  /* mcast shared info */
  uword *mcast_shared;		/* keyed on mcast ip46 addr */

  /* Free vlib hw_if_indices */
  u32 *free_gtpu_tunnel_hw_if_indices;

  /* Mapping from sw_if_index to tunnel index */
  u32 *tunnel_index_by_sw_if_index;

  /**
   * Node type for registering to fib changes.
   */
  fib_node_type_t fib_node_type;

  /* API message ID base */
  u16 msg_id_base;

  /* Handle GTP packets of unknown type like echo and error indication,
   * unknown teid or bad version/header.
   * All packets will be forwarded to a new IP address,
   * so that they can be processes outside vpp.
   * If not set then packets are dropped.
   * One of more indexes can be unused (~0). */
  u32 bad_header_forward_tunnel_index_ipv4;
  u32 unknown_teid_forward_tunnel_index_ipv4;
  u32 unknown_type_forward_tunnel_index_ipv4;
  u32 bad_header_forward_tunnel_index_ipv6;
  u32 unknown_teid_forward_tunnel_index_ipv6;
  u32 unknown_type_forward_tunnel_index_ipv6;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  u32 flow_id_start;
  /* cache for last 8 gtpu tunnel */
  vtep4_cache_t vtep4_u512;

} gtpu_main_t;

extern gtpu_main_t gtpu_main;

extern vlib_node_registration_t gtpu4_input_node;
extern vlib_node_registration_t gtpu6_input_node;
extern vlib_node_registration_t gtpu4_encap_node;
extern vlib_node_registration_t gtpu6_encap_node;
extern vlib_node_registration_t gtpu4_flow_input_node;

u8 *format_gtpu_encap_trace (u8 * s, va_list * args);

typedef struct
{
  u8 opn;
#define GTPU_DEL_TUNNEL 0
#define GTPU_ADD_TUNNEL 1
#define GTPU_UPD_TTEID  2
  ip46_address_t src, dst;
  u32 mcast_sw_if_index;
  u32 encap_fib_index;
  u32 decap_next_index;
  u32 teid;			/* local  or rx teid */
  u32 tteid;			/* remote or tx teid */
  u8 pdu_extension;
  u8 qfi;
  u8 is_forwarding;
  u8 forwarding_type;
} vnet_gtpu_add_mod_del_tunnel_args_t;

int vnet_gtpu_add_del_forwarding (vnet_gtpu_add_mod_del_tunnel_args_t *a,
				  u32 *sw_if_indexp);

int vnet_gtpu_add_mod_del_tunnel
  (vnet_gtpu_add_mod_del_tunnel_args_t * a, u32 * sw_if_indexp);

typedef struct
{
  u32 tunnel_index;
  u32 tteid;
  u8 pdu_extension;
  u8 qfi;
} gtpu_encap_trace_t;

void vnet_int_gtpu_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable);
u32 vnet_gtpu_get_tunnel_index (u32 sw_if_index);
int vnet_gtpu_add_del_rx_flow (u32 hw_if_index, u32 t_imdex, int is_add);
int get_combined_counters (u32 sw_if_index, vlib_counter_t *result_rx,
			   vlib_counter_t *result_tx);

#endif /* included_vnet_gtpu_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
