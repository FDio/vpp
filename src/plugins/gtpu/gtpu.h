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
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
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

typedef struct
{
  u8 ver_flags;
  u8 type;
  u16 length;			/* length in octets of the payload */
  u32 teid;
  u16 sequence;
  u8 pdu_number;
  u8 next_ext_type;
} gtpu_header_t;

#define GTPU_VER_MASK (7<<5)
#define GTPU_PT_BIT   (1<<4)
#define GTPU_E_BIT    (1<<2)
#define GTPU_S_BIT    (1<<1)
#define GTPU_PN_BIT   (1<<0)
#define GTPU_E_S_PN_BIT  (7<<0)

#define GTPU_V1_VER   (1<<5)

#define GTPU_PT_GTP    (1<<4)

#define	GTPU_TYPE_ECHO_REQUEST			        1
#define	GTPU_TYPE_ECHO_RESPONSE				    2
#define GTPU_TYPE_VERSION_NOT_SUPPORTED         3
#define	GTPU_TYPE_ERROR_INDICATION				26
#define	GTPU_TYPE_EXTENSION_HEADERS_NOTIFICATION 31
#define GTPU_TYPE_GTPU  255

enum
{
  GTPU_EVENT_PATH_ERROR,
  GTPU_EVENT_NO_SUCH_TUNNEL,
  GTPU_EVENT_VERSION_NOT_SUPPORTED,
  GTPU_EVENT_RECEIVE_ERROR_INDICATION,
};


/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip4_header_t ip4;            /* 20 bytes */
  udp_header_t udp;            /* 8 bytes */
  gtpu_header_t gtpu;	       /* 8 bytes */
}) ip4_gtpu_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip6_header_t ip6;            /* 40 bytes */
  udp_header_t udp;            /* 8 bytes */
  gtpu_header_t gtpu;     /* 8 bytes */
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

  /* gtpu in teid in HOST byte order */
  u32 teid_in;

  /* gtpu out teid in HOST byte order */
  u32 teid_out;

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

/* move from gtpu_api.c */
#define REPLY_MSG_ID_BASE gtm->msg_id_base
#include <vlibapi/api_helper_macros.h>

typedef struct
{
  /* if has no one client , disable polling? */
  u32 enable_poller;

  uword *client_hash;
  vpe_client_registration_t *clients;
} gtpu_client_registration_t;


extern vlib_node_registration_t gtpu_process_node;

enum
{
  GTPU_EVENT_TYPE_FAST_POLLING_START,
  GTPU_EVENT_TYPE_ECHO_RESPONSE_IP4,
  GTPU_EVENT_TYPE_ECHO_RESPONSE_IP6,
  GTPU_EVENT_TYPE_VERSION_NOT_SUPPORTED_IP4,
  GTPU_EVENT_TYPE_VERSION_NOT_SUPPORTED_IP6,
  GTPU_EVENT_TYPE_NO_SUCH_TUNNEL_IP4,
  GTPU_EVENT_TYPE_NO_SUCH_TUNNEL_IP6,
  GTPU_EVENT_TYPE_ERROR_INDICATE_IP4,
  GTPU_EVENT_TYPE_ERROR_INDICATE_IP6
};

typedef struct
{
  u64 echo_request_count;	/* record the count about echo request packets send */
  u64 re_echo_request_count;	/* record the count that go into retransmission status */
} gtpu_path_counter_t;

typedef struct
{
  ip46_address_t src;
  ip46_address_t dst;
  f64 last_send_request_time;	/* the last time of send echo request packet */
  f64 last_receive_response_time;	/* the last time of receive echo response packet */
  u32 tunnel_count;		/* how many tunnel on this path */
  u8 re_echo_request;		/* flag to retransmit echo request packet and retransmit count */
  u8 echo_request;		/* flag to transmit echo request packet */
  u8 path_error;		/* path error flag */
  gtpu_path_counter_t counter;	/* path counter info */
} gtpu_path_t;

typedef struct
{
  uword *gtpu4_path_by_key;	/* keyed on ipv4.dst + 0 */
  uword *gtpu6_path_by_key;	/* keyed on ipv6.dst + 0 */
  gtpu_path_t *paths;
} gtpu_path_manage_t;

typedef struct
{
  /* vector of encap tunnel instances */
  gtpu_tunnel_t *tunnels;

  /* lookup tunnel by key */
  uword *gtpu4_tunnel_by_key;	/* keyed on ipv4.dst + teid_in */
  uword *gtpu6_tunnel_by_key;	/* keyed on ipv6.dst + teid_in */

  /* local VTEP IPs ref count used by gtpu-bypass node to check if
     received gtpu packet DIP matches any local VTEP address */
  uword *vtep4;			/* local ip4 VTEPs keyed on their ip4 addr */
  uword *vtep6;			/* local ip6 VTEPs keyed on their ip6 addr */

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

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* gtpu api client registrations */
  gtpu_client_registration_t registrations;

  /* path management */
  gtpu_path_manage_t path_manage;
} gtpu_main_t;

extern gtpu_main_t gtpu_main;

extern vlib_node_registration_t gtpu4_input_node;
extern vlib_node_registration_t gtpu6_input_node;
extern vlib_node_registration_t gtpu4_encap_node;
extern vlib_node_registration_t gtpu6_encap_node;

u8 *format_gtpu_encap_trace (u8 * s, va_list * args);

typedef struct
{
  u8 is_add;
  u8 is_ip6;
  ip46_address_t src, dst;
  u32 mcast_sw_if_index;
  u32 encap_fib_index;
  u32 decap_next_index;
  u32 teid_in;
  u32 teid_out;
} vnet_gtpu_add_del_tunnel_args_t;

int vnet_gtpu_add_del_tunnel
  (vnet_gtpu_add_del_tunnel_args_t * a, u32 * sw_if_indexp);

void vnet_int_gtpu_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable);
#endif /* included_vnet_gtpu_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
